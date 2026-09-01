/*
 * server.c - a2tp-srv: take over a NIC and transparently bridge it to a
 * remote client over a UDP or TCP tunnel.
 *
 *   NIC (promiscuous) --.                  .--> transport --> client (tap clone)
 *                       |                  |
 *   NIC (inject)       '<-- transport <-- client'
 *
 * - The NIC is put into promiscuous mode via a packet socket; every frame
 *   the NIC receives is mirrored to the client.
 * - Every data frame received from the client is injected onto the NIC
 *   verbatim (raw L2 send), so the two directions form a transparent L2 pipe.
 * - UDP (default): NAT friendly, the client endpoint is re-learned from the
 *   source address of every incoming datagram.
 * - TCP (--tcp): framed stream with kernel congestion control and
 *   retransmission; one connection at a time, re-accepted on disconnect.
 *
 * Threading model: a rx thread pumps transport -> NIC inject (blocking in
 * recv), while main itself is the mirror pump NIC -> transport (blocking in
 * recvfrom on the packet socket; a 1 s receive timeout is the only idle tick,
 * needed to notice a dead connection / shutdown on a quiet NIC).  No locks:
 * each send is one syscall, serialized by the kernel on the socket.  UDP and
 * TCP remain separate code paths -- the per-frame hot path never branches on
 * the transport.
 */
#include "common.h"
#include "auth.h"

#include <getopt.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define FILTER_IP_MAX 32   /* --filter-ip addresses */
#define PUBKEY_MAX     16  /* --pubkey authorized keys */

/* how long a challenge may sit unanswered, and how far a response's
 * challenge timestamp may have drifted when it is checked */
#define AUTH_WAIT_MS  10000
#define AUTH_FRESH_MS 30000

struct cfg {
    const char *iface;
    uint16_t port;
    struct in_addr bind_addr;    /* local address to listen on ({0} = 0.0.0.0) */
    int tcp;                     /* --tcp: framed stream transport */
    int peer_fixed;              /* --peer given: only accept that source */
    struct sockaddr_in peer;     /* fixed or last learned */
    int peer_timeout_ms;         /* stop mirroring when peer silent this long */
    int self_filter;             /* don't mirror the tunnel's own packets */
    int keep_offloads;           /* don't touch tso/gso/gro on the NIC */
    uint32_t filter_ip[FILTER_IP_MAX];  /* --filter-ip: IPv4 dsts to mirror */
    int filter_n;
    const char *pubkey_path;     /* --pubkey file (authorized_keys style) */
    uint8_t pubkeys[PUBKEY_MAX][32];
    int pubkeys_n;
};

/*
 * Mirror filter for multi-IP NICs: with --filter-ip only IPv4 frames whose
 * destination is one of the listed addresses (the IPs the client took over
 * from this NIC -- deleted from the local stack) are mirrored.
 *
 * ARP is always passed through untouched: the server stays stateless, the
 * client's protocol stack answers for its own IPs and resolves its own
 * neighbors.  Ownership is disjoint by construction -- the host still
 * answers ARP for the addresses it kept, the client for the taken-over
 * ones -- so the two never race; the tunnel just relays the bytes.
 *
 * Everything else stays with the local stack (AF_PACKET only taps the NIC,
 * it never intercepts, so "not mirrored" costs nothing and the host
 * terminates that traffic as before).  Without a filter every frame is
 * mirrored, as always.
 */
static int mirror_filter_pass(const struct cfg *c, const uint8_t *f, size_t len)
{
    if (!c->filter_n)
        return 1;
    if (frame_ethertype(f, len) == 0x0806)
        return 1;   /* ARP passes through: client answers for its own IPs */
    uint32_t dst = frame_ipv4_dst(f, len);
    if (!dst)
        return 0;
    for (int i = 0; i < c->filter_n; i++)
        if (dst == c->filter_ip[i])
            return 1;
    return 0;
}

static void parse_filter_ips(struct cfg *cfg, const char *arg)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", arg);
    for (char *p = strtok(buf, ","); p; p = strtok(NULL, ",")) {
        struct in_addr a;
        if (inet_pton(AF_INET, p, &a) != 1)
            die("--filter-ip: expect IPv4 addresses (comma-separated)");
        if (cfg->filter_n >= FILTER_IP_MAX)
            die("--filter-ip: at most %d addresses", FILTER_IP_MAX);
        cfg->filter_ip[cfg->filter_n++] = a.s_addr;
    }
}

static void usage(FILE *out)
{
    fprintf(out,
        "usage: a2tp-srv -i <iface> [options]\n"
        "\n"
        "  -i, --iface <name>       NIC to take over (promiscuous capture + inject)\n"
        "  -p, --port <port>        port to listen on (default %d)\n"
        "  -b, --bind <ip>          local address to listen on (default 0.0.0.0;\n"
        "                           e.g. 127.0.0.1 to serve local clients only)\n"
        "      --tcp                framed TCP stream instead of UDP: kernel\n"
        "                           congestion control and retransmission (pick\n"
        "                           the cc algorithm via sysctl); the client\n"
        "                           must be started with --tcp too\n"
        "      --peer <ip:port>     pin the client (udp only); without it the\n"
        "                           peer is learned/re-learned from every packet\n"
        "                           (NAT roaming)\n"
        "      --peer-timeout <s>   pause mirroring after N s without peer packets,\n"
        "                           0 = never (default 30, udp only)\n"
        "      --no-self-filter     also mirror the tunnel's own packets\n"
        "      --filter-ip <ip[,ip..]>\n"
        "                           multi-IP NIC: mirror only IPv4 frames whose\n"
        "                           destination is one of these (the client's IPs\n"
        "                           on this NIC; repeatable / comma-separated).\n"
        "                           ARP still passes (neighbor discovery); every\n"
        "                           other frame stays with the local stack.\n"
        "                           Default: mirror everything, unfiltered\n"
        "      --keep-offloads      do not disable tso/gso/gro on the NIC\n"
        "      --pubkey <file>      authorized_keys-style file of ssh-ed25519\n"
        "                           public keys; every --tcp connection must\n"
        "                           answer a challenge signed by one of them\n"
        "                           (fresh 96-bit nonce each time: recorded\n"
        "                           responses never verify twice)\n"
        "  -v, --verbose            per-packet logging\n"
        "  -h, --help               this help\n",
        A2TP_UDP_PORT);
}

static int packet_socket_open(const char *iface, int ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        die("socket(AF_PACKET): need root/CAP_NET_RAW");

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
        die("bind AF_PACKET to %s", iface);

    /* promiscuous mode, the way tcpdump does it */
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
        die("setsockopt(PACKET_MR_PROMISC)");

    /* don't loop back frames sent by any local socket (incl. our injections) */
    int one = 1;
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));

    int bufsz = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));

    return fd;
}

/* state shared by the rx thread and the mirror (main); all atomic */
struct sh {
    struct cfg *cfg;
    int pfd;                    /* AF_PACKET socket on the NIC */
    int ifindex;
    int xfd;                    /* transport socket (udp or tcp) */
    /* udp: learned/roaming peer (atomic); tcp: fixed peer of the connection */
    uint64_t peer_k;
    int peer_known;
    int64_t peer_last;
    int dead;                   /* tcp: connection is down */
};

/* raw L2 inject; used by the rx threads of both transports */
static int inject_frame(int pfd, int ifindex, const uint8_t *frame, size_t flen)
{
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifindex;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, frame, ETH_ALEN);
    return sendto(pfd, frame, flen, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0 ? -1 : 0;
}

static void inject_from_msg(struct sh *s, const uint8_t *frame, size_t flen)
{
    if (inject_frame(s->pfd, s->ifindex, frame, flen) < 0)
        logv("inject failed: %s", strerror(errno));
    else {
        logv("inject %zu bytes", flen);
        if (g_verbose)
            hexdump(frame, flen, 24);
    }
}

/* ================= UDP: rx thread + mirror in main ======================= */

static void *rx_udp_thread(void *arg)
{
    struct sh *s = arg;
    block_termination_signals();
    uint8_t buf[HDR_LEN + MAX_FRAME];

    while (!g_stop) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t r = recvfrom(s->xfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &flen);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            logmsg("recvfrom udp: %s", strerror(errno));
            break;
        }
        if (r < 1)
            continue;   /* socket shut down for teardown */

        if (s->cfg->peer_fixed) {
            if (sockaddr_key(&from) !=
                __atomic_load_n(&s->peer_k, __ATOMIC_RELAXED)) {
                logv("drop packet from %s:%d (peer pinned)",
                     inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                continue;
            }
        } else {
            uint64_t k = sockaddr_key(&from);
            int known = __atomic_load_n(&s->peer_known, __ATOMIC_RELAXED);
            if (!known || k != __atomic_load_n(&s->peer_k, __ATOMIC_RELAXED)) {
                __atomic_store_n(&s->peer_k, k, __ATOMIC_RELAXED);
                __atomic_store_n(&s->peer_known, 1, __ATOMIC_RELAXED);
                logmsg("peer: %s:%d (%s)", inet_ntoa(from.sin_addr),
                       ntohs(from.sin_port), known ? "updated" : "learned");
            }
        }
        __atomic_store_n(&s->peer_last, now_ms(), __ATOMIC_RELAXED);

        if (buf[0] == A2TP_TYPE_KEEPALIVE) {
            logv("keepalive from peer");
        } else if (buf[0] == A2TP_TYPE_DATA && r > HDR_LEN + ETH_HLEN) {
            inject_from_msg(s, buf + HDR_LEN, (size_t)r - HDR_LEN);
        } else {
            logv("bad message type 0x%02x", buf[0]);
        }
    }
    return NULL;
}

/* main thread: mirror everything the NIC receives down to the peer */
static int mirror_udp(struct sh *s)
{
    uint8_t buf[HDR_LEN + MAX_FRAME];

    while (!g_stop) {
        struct sockaddr_ll sa;
        socklen_t slen = sizeof(sa);
        ssize_t r = recvfrom(s->pfd, buf + HDR_LEN, MAX_FRAME, 0,
                             (struct sockaddr *)&sa, &slen);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;   /* signal, or the 1 s idle tick */
            logmsg("recvfrom packet: %s", strerror(errno));
            break;
        }
        if (r < 1)
            continue;

        int known = __atomic_load_n(&s->peer_known, __ATOMIC_RELAXED);
        uint64_t k = __atomic_load_n(&s->peer_k, __ATOMIC_RELAXED);

        if (sa.sll_pkttype == PACKET_OUTGOING) {
            /* local traffic, incl. our own injections */
        } else if (s->cfg->self_filter &&
                   frame_is_tunnel_l4(buf + HDR_LEN, (size_t)r, IPPROTO_UDP,
                                      s->cfg->port,
                                      known ? (uint32_t)(k >> 16) : 0,
                                      known ? ntohs((uint16_t)k) : 0)) {
            /* the tunnel's own UDP: mirroring it back would loop */
        } else if (!mirror_filter_pass(s->cfg, buf + HDR_LEN, (size_t)r)) {
            /* not one of the client's IPs: the local stack keeps it */
        } else if (!known ||
                   (s->cfg->peer_timeout_ms &&
                    now_ms() - __atomic_load_n(&s->peer_last, __ATOMIC_RELAXED)
                        > s->cfg->peer_timeout_ms)) {
            /* nobody to mirror to (peer never seen or gone quiet) */
        } else if ((size_t)r + HDR_LEN > 65507) {
            logv("oversize frame %zd bytes dropped", r);   /* datagram limit */
        } else {
            buf[0] = A2TP_TYPE_DATA;
            struct sockaddr_in peer;
            key_to_sockaddr(k, &peer);
            if (sendto(s->xfd, buf, r + HDR_LEN, 0,
                       (const struct sockaddr *)&peer, sizeof(peer)) < 0)
                logv("mirror send failed: %s", strerror(errno));
            else {
                logv("mirror %zd bytes", r);
                if (g_verbose)
                    hexdump(buf + HDR_LEN, r, 24);
            }
        }
    }
    return 0;
}

static int run_udp(struct cfg *cfg, int pfd, int ifindex)
{
    int ufd = udp_bind(cfg->bind_addr.s_addr, cfg->port);
    if (ufd < 0)
        die("bind UDP %s:%d", inet_ntoa(cfg->bind_addr), cfg->port);

    struct sh s = { .cfg = cfg, .pfd = pfd, .ifindex = ifindex, .xfd = ufd };
    if (cfg->peer_fixed) {
        s.peer_k = sockaddr_key(&cfg->peer);
        s.peer_known = 1;
        logmsg("peer pinned to %s:%d", inet_ntoa(cfg->peer.sin_addr),
               ntohs(cfg->peer.sin_port));
    } else {
        logmsg("peer: dynamic (re-learned from every packet, NAT roaming)");
    }
    s.peer_last = now_ms();

    /* idle tick for the mirror: nothing else wakes it on a quiet NIC */
    sock_rcvtimeo(pfd, 1000);

    pthread_t rx;
    if (pthread_create(&rx, NULL, rx_udp_thread, &s))
        die("pthread_create");

    int rc = mirror_udp(&s);

    shutdown(ufd, SHUT_RDWR);   /* wake the rx thread */
    pthread_join(rx, NULL);
    close(ufd);
    logmsg("shutting down");
    return rc;
}

/* ================= TCP: rx thread + mirror in main, one connection ======== */

static void *rx_tcp_thread(void *arg)
{
    struct sh *s = arg;
    block_termination_signals();
    uint8_t buf[2 + HDR_LEN + MAX_FRAME];   /* [len(2)][type][frame] */
    struct stream_rx rx;
    stream_rx_init(&rx, buf);

    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
        int rc = stream_rx_feed(&rx, s->xfd);   /* blocks until a message */
        if (rc < 0)
            break;                              /* EOF / reset / bad frame */
        if (rc == 0)
            continue;
        uint8_t *msg = rx.buf + 2;
        size_t mlen = rx.have - 2;
        if (mlen == 1 && msg[0] == A2TP_TYPE_KEEPALIVE) {
            logv("keepalive from peer");
        } else if (msg[0] == A2TP_TYPE_DATA && mlen > HDR_LEN + ETH_HLEN) {
            inject_from_msg(s, msg + HDR_LEN, mlen - HDR_LEN);
        } else {
            logv("bad message (type 0x%02x, %zu bytes)", msg[0], mlen);
        }
        stream_rx_next(&rx);
    }
    __atomic_store_n(&s->dead, 1, __ATOMIC_RELAXED);
    shutdown(s->xfd, SHUT_RDWR);   /* wake main if it is blocked in a send */
    return NULL;
}

static int mirror_tcp(struct sh *s)
{
    uint8_t buf[2 + HDR_LEN + MAX_FRAME];   /* [len(2)][type][frame] */
    uint32_t peer_ip = (uint32_t)(s->peer_k >> 16);
    uint16_t peer_port = ntohs((uint16_t)s->peer_k);

    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
        struct sockaddr_ll sa;
        socklen_t slen = sizeof(sa);
        ssize_t r = recvfrom(s->pfd, buf + 2 + HDR_LEN, MAX_FRAME, 0,
                             (struct sockaddr *)&sa, &slen);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;   /* signal, or the 1 s idle tick (rechecks dead) */
            logmsg("recvfrom packet: %s", strerror(errno));
            break;
        }
        if (r < 1)
            continue;

        if (sa.sll_pkttype == PACKET_OUTGOING) {
            /* local traffic, incl. our own injections */
        } else if (s->cfg->self_filter &&
                   frame_is_tunnel_l4(buf + 2 + HDR_LEN, (size_t)r, IPPROTO_TCP,
                                      s->cfg->port, peer_ip, peer_port)) {
            /* the tunnel's own TCP: mirroring it back would loop */
        } else if (!mirror_filter_pass(s->cfg, buf + 2 + HDR_LEN, (size_t)r)) {
            /* not one of the client's IPs: the local stack keeps it */
        } else if ((size_t)r + HDR_LEN > 0xffff) {
            logv("oversize frame %zd bytes dropped", r);   /* u16 length limit */
        } else {
            buf[2] = A2TP_TYPE_DATA;
            if (stream_send_msg(s->xfd, buf + 2, HDR_LEN + (size_t)r) < 0) {
                logv("mirror send failed: %s", strerror(errno));
                __atomic_store_n(&s->dead, 1, __ATOMIC_RELAXED);
                break;   /* stalled past the send deadline or connection gone */
            }
            logv("mirror %zd bytes", r);
            if (g_verbose)
                hexdump(buf + 2 + HDR_LEN, r, 24);
        }
    }
    return 0;
}

/*
 * Challenge-response gate for --pubkey (tcp): send a fresh 96-bit
 * challenge -- u64 unix-ms + u32 random -- and demand a signature over it
 * from one of the authorized keys.  A recorded response is worthless: it
 * only verifies against its exact challenge, which the moving ms clock
 * never reissues (same-millisecond replay needs a 2^-32 nonce collision,
 * and is additionally bounded by the freshness window below).
 *
 * Returns the 1-based index of the key that signed, or -1.
 */
static int tcp_auth_challenge(struct cfg *cfg, int cfd)
{
    uint8_t chal[A2TP_CHALLENGE_LEN];
    if (a2tp_challenge_build(chal, (uint64_t)now_ms()) < 0) {
        logmsg("auth: entropy failure");
        return -1;
    }
    uint8_t msg[1 + A2TP_CHALLENGE_LEN] = { A2TP_TYPE_AUTH_CHALLENGE };
    memcpy(msg + 1, chal, sizeof(chal));
    if (stream_send_msg(cfd, msg, sizeof(msg)) < 0)
        return -1;

    /* full-size buffer: the length prefix is read before it is validated,
     * so the reader must be able to take the largest frame a peer sends */
    uint8_t buf[2 + HDR_LEN + MAX_FRAME];
    struct stream_rx rx;
    stream_rx_init(&rx, buf);
    sock_rcvtimeo(cfd, AUTH_WAIT_MS);
    int64_t deadline = now_ms() + AUTH_WAIT_MS;
    int rc;
    while ((rc = stream_rx_feed(&rx, cfd)) == 0)
        if (g_stop || now_ms() >= deadline) { rc = -1; break; }
    sock_rcvtimeo(cfd, 0);          /* the pump blocks for real again */
    if (rc < 0)
        return -1;

    uint8_t *ans = rx.buf + 2;
    size_t alen = rx.have - 2;
    if (alen != 1 + A2TP_SIG_LEN || ans[0] != A2TP_TYPE_AUTH_RESPONSE) {
        logv("auth: bad answer (type 0x%02x, %zu bytes)", ans[0], alen);
        return -1;
    }
    if ((uint64_t)(now_ms() - (int64_t)a2tp_challenge_ts(chal)) >
        (uint64_t)AUTH_FRESH_MS) {
        logv("auth: challenge drifted out of the freshness window");
        return -1;
    }
    for (int i = 0; i < cfg->pubkeys_n; i++)
        if (ssh_verify(cfg->pubkeys[i], chal, sizeof(chal), ans + 1) == 1)
            return i + 1;
    return -1;
}

static int run_tcp(struct cfg *cfg, int pfd, int ifindex)
{
    int lfd = tcp_listen_on(cfg->bind_addr, cfg->port);
    if (lfd < 0)
        die("listen tcp %s:%d", inet_ntoa(cfg->bind_addr), cfg->port);

    sock_rcvtimeo(pfd, 1000);

    while (!g_stop) {
        struct sockaddr_in who;
        socklen_t wlen = sizeof(who);
        int cfd = accept(lfd, (struct sockaddr *)&who, &wlen);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            logv("accept: %s", strerror(errno));
            continue;
        }
        tcp_tune(cfd);
        logmsg("client %s:%d connected (tcp)", inet_ntoa(who.sin_addr),
               ntohs(who.sin_port));

        if (cfg->pubkeys_n > 0) {
            int k = tcp_auth_challenge(cfg, cfd);
            if (k < 0) {
                logmsg("client %s:%d rejected (auth failed)",
                       inet_ntoa(who.sin_addr), ntohs(who.sin_port));
                close(cfd);
                continue;
            }
            logmsg("client %s:%d authenticated (key %d of %d)",
                   inet_ntoa(who.sin_addr), ntohs(who.sin_port),
                   k, cfg->pubkeys_n);
        }

        struct sh s = { .cfg = cfg, .pfd = pfd, .ifindex = ifindex, .xfd = cfd,
                        .peer_k = sockaddr_key(&who), .peer_known = 1 };

        pthread_t rx;
        if (pthread_create(&rx, NULL, rx_tcp_thread, &s))
            die("pthread_create");

        mirror_tcp(&s);

        shutdown(cfd, SHUT_RDWR);
        pthread_join(rx, NULL);
        close(cfd);
        logmsg("client disconnected (tcp)");
    }

    close(lfd);
    logmsg("shutting down");
    return 0;
}

/* ======================================================================== */

int main(int argc, char **argv)
{
    struct cfg cfg = {
        .iface = NULL,
        .port = A2TP_UDP_PORT,
        .peer_timeout_ms = 30000,
        .self_filter = 1,
    };

    static int opt_tcp;   /* long-only flag, copied into cfg after parsing */

    static const struct option lopts[] = {
        {"iface",        required_argument, 0, 'i'},
        {"port",         required_argument, 0, 'p'},
        {"bind",         required_argument, 0, 'b'},
        {"tcp",          no_argument,       &opt_tcp, 1},
        {"peer",         required_argument, 0, 'P'},
        {"peer-timeout", required_argument, 0, 'T'},
        {"no-self-filter", no_argument,     0, 'F'},
        {"filter-ip",      required_argument, 0, 1001},
        {"pubkey",         required_argument, 0, 1002},
        {"keep-offloads",  no_argument,     0, 'K'},
        {"verbose",      no_argument,       0, 'v'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "i:p:b:P:T:FKvh", lopts, NULL)) != -1) {
        switch (opt) {
        case 0:  break;   /* flag options (--tcp) */
        case 'i': cfg.iface = optarg; break;
        case 'p': cfg.port = atoi(optarg); break;
        case 'b':
            if (inet_pton(AF_INET, optarg, &cfg.bind_addr) != 1)
                die("--bind: expect an IPv4 address");
            break;
        case 'P':
            if (parse_ip_port(optarg, 0, &cfg.peer) < 0)
                die("--peer: expect ip:port");
            cfg.peer_fixed = 1;
            break;
        case 'T': cfg.peer_timeout_ms = atoi(optarg) * 1000; break;
        case 'F': cfg.self_filter = 0; break;
        case 1001: parse_filter_ips(&cfg, optarg); break;
        case 1002: cfg.pubkey_path = optarg; break;
        case 'K': cfg.keep_offloads = 1; break;
        case 'v': g_verbose = 1; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return 1;
        }
    }
    if (!cfg.iface) {
        usage(stderr);
        return 1;
    }
    cfg.tcp = opt_tcp;
    if (cfg.port == 0)
        die("invalid port");

    if (cfg.pubkey_path) {
        if (!cfg.tcp)
            die("--pubkey needs --tcp (the challenge handshake is tcp-only)");
        int n = ssh_pubkeys_load(cfg.pubkey_path, cfg.pubkeys, PUBKEY_MAX);
        if (n < 0)
            die("read %s: %s", cfg.pubkey_path, strerror(errno));
        if (n == 0)
            die("%s: no ssh-ed25519 keys found", cfg.pubkey_path);
        cfg.pubkeys_n = n;
        logmsg("auth: %d key(s) from %s, every tcp connection is challenged",
               n, cfg.pubkey_path);
    }

    install_signal_handlers();

    int ifindex = if_nametoindex(cfg.iface);
    if (!ifindex)
        die("interface %s not found", cfg.iface);

    uint8_t mac[6];
    int mtu = 0;
    if (!if_get_mac(cfg.iface, mac))
        if_get_mtu(cfg.iface, &mtu);

    int pfd = packet_socket_open(cfg.iface, ifindex);

    /*
     * The mirror must forward real wire frames.  With tso/gso/gro enabled
     * the kernel hands AF_PACKET 64K super-frames that are not wire frames
     * and exceed the datagram limit, so TCP through the tunnel breaks.
     * The previous state is restored on shutdown (we may own a live NIC).
     */
    int offload_saved[OFFLOAD_N] = { -1, -1, -1 };
    if (!cfg.keep_offloads) {
        if_offload_save(cfg.iface, offload_saved);
        if (if_disable_offloads(cfg.iface) == 0)
            logmsg("disabled tso/gso/gro on %s (restored on exit; "
                   "--keep-offloads to keep them)", cfg.iface);
    }

    /* one dispatch at startup: the pumps are transport-specific */
    logmsg("a2tp-srv on %s (idx %d, mac %02x:%02x:%02x:%02x:%02x:%02x, mtu %d), "
           "%s %s:%d", cfg.iface, ifindex,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mtu,
           cfg.tcp ? "tcp" : "udp", inet_ntoa(cfg.bind_addr), cfg.port);
    if (cfg.filter_n) {
        char ips[32 * 16] = "";
        for (int i = 0; i < cfg.filter_n; i++) {
            struct in_addr a = { .s_addr = cfg.filter_ip[i] };
            char one[16];
            snprintf(one, sizeof(one), "%s%s", i ? "," : "", inet_ntoa(a));
            strncat(ips, one, sizeof(ips) - strlen(ips) - 1);
        }
        logmsg("mirror filter: ipv4 dst in {%s} (arp passes, rest stays local)",
               ips);
    }

    int rc;
    if (cfg.tcp) {
        if (cfg.peer_fixed || cfg.peer_timeout_ms != 30000)
            logmsg("note: --peer/--peer-timeout apply to udp mode only");
        rc = run_tcp(&cfg, pfd, ifindex);
    } else {
        rc = run_udp(&cfg, pfd, ifindex);
    }

    if (offload_saved[0] >= 0 || offload_saved[1] >= 0 || offload_saved[2] >= 0) {
        if_offload_apply(cfg.iface, offload_saved);
        logmsg("restored tso/gso/gro on %s", cfg.iface);
    }
    return rc;
}
