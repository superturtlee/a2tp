/*
 * client.c - a2tp-cli: create a TAP interface cloned from the server's NIC.
 *
 *   transport <-- server (promiscuous NIC) --> every frame into the tap
 *   tap --> every frame the local host emits on the tap goes to the server
 *           and is injected there onto the NIC
 *
 * The result is a local TAP that behaves like the server's remote NIC.
 *
 * - UDP (default): keepalives keep the NAT mapping alive and let the server
 *   learn our endpoint before any real traffic; the server endpoint is
 *   re-learned from every incoming datagram (roaming).
 * - TCP (--tcp): framed stream with kernel congestion control and
 *   retransmission; automatic reconnect when the connection drops.
 *
 * Threading model (both transports): a rx thread pumps transport -> tap, a
 * tx thread pumps tap -> transport, a keepalive thread owns the liveness
 * timer.  Every pump blocks in its syscall -- no polling loop anywhere; the
 * kernel wakes a thread exactly when a frame arrives.  No locks: each send
 * is one syscall (sendto / sendmsg), which the kernel serializes on the
 * socket.  main owns the lifecycle only: it blocks on an event pipe until a
 * pump thread dies or a signal arrives, then tears down and, in tcp mode,
 * reconnects.
 */
#include "common.h"

#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>

struct cfg {
    struct sockaddr_in srv;
    uint16_t local_port;
    int tcp;                    /* --tcp: framed stream transport */
    const char *tap;
    uint8_t mac[6];
    int have_mac;
    int mtu;
    int keepalive_ms;
};

static void usage(FILE *out)
{
    fprintf(out,
        "usage: a2tp-cli -s <server_ip[:port]> [options]\n"
        "\n"
        "  -s, --server <ip[:port]>  tunnel server (default port %d)\n"
        "  -p, --port <port>         local UDP port (default %d, 0 = ephemeral;\n"
        "                            udp mode only, tcp uses an ephemeral port)\n"
        "  -t, --tap <name>          TAP interface name (default a2tp0)\n"
        "      --tcp                 framed TCP stream instead of UDP: kernel\n"
        "                            congestion control and retransmission; the\n"
        "                            server must be started with --tcp too\n"
        "      --up                  accepted for compatibility; the TAP is\n"
        "                            always brought up promiscuous (so mirrored\n"
        "                            frames to foreign MACs reach the stack)\n"
        "      --mac <aa:bb:..>      set the TAP MAC (e.g. clone the server NIC)\n"
        "      --mtu <n>             set the TAP MTU\n"
        "      --keepalive <s>       keepalive interval (default 10, 0 = off)\n"
        "  -v, --verbose             per-packet logging\n"
        "  -h, --help                this help\n",
        A2TP_UDP_PORT, A2TP_UDP_PORT);
}

static int tap_open(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        die("open /dev/net/tun");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        die("TUNSETIFF %s (need root/CAP_NET_ADMIN)", name);
    /* plain <=MTU frames only: no GSO super-frames through the tunnel */
    if (ioctl(fd, TUNSETOFFLOAD, 0) < 0)
        logv("TUNSETOFFLOAD(0) failed: %s", strerror(errno));
    return fd;
}

/* state shared by the pump threads; every mutable field is lock-free */
struct sh {
    struct cfg *cfg;
    int tfd;                    /* tap */
    int xfd;                    /* transport socket (udp or tcp) */
    int is_tcp;
    int ev_r, ev_w;             /* pump-death notifications to main */
    uint64_t peer_k;            /* udp: current server endpoint (atomic) */
    int dead;                   /* link down / teardown started (atomic) */
};

static void mark_dead(struct sh *s)
{
    if (!__atomic_exchange_n(&s->dead, 1, __ATOMIC_RELAXED))
        evpipe_notify(s->ev_w);
}

static void rx_to_tap(struct sh *s, const uint8_t *frame, size_t flen)
{
    if (write(s->tfd, frame, flen) < 0)
        logv("tap write: %s", strerror(errno));
    else {
        logv("net->tap %zu bytes", flen);
        if (g_verbose)
            hexdump(frame, flen, 24);
    }
}

/* ---- rx: transport -> tap (blocks in recv; udp also refreshes the peer) -- */

static void *rx_udp_thread(void *arg)
{
    struct sh *s = arg;
    block_termination_signals();
    uint8_t buf[HDR_LEN + MAX_FRAME];

    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
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
            continue;   /* socket shut down */
        uint64_t k = sockaddr_key(&from);
        if (k != __atomic_load_n(&s->peer_k, __ATOMIC_RELAXED)) {
            __atomic_store_n(&s->peer_k, k, __ATOMIC_RELAXED);
            logmsg("server endpoint updated: %s:%d",
                   inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        }
        if (buf[0] == A2TP_TYPE_DATA && r > HDR_LEN + ETH_HLEN)
            rx_to_tap(s, buf + HDR_LEN, (size_t)r - HDR_LEN);
        else if (buf[0] != A2TP_TYPE_KEEPALIVE)
            logv("bad message type 0x%02x", buf[0]);
    }
    mark_dead(s);
    return NULL;
}

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
        if (msg[0] == A2TP_TYPE_DATA && mlen > HDR_LEN + ETH_HLEN)
            rx_to_tap(s, msg + HDR_LEN, mlen - HDR_LEN);
        else if (!(mlen == 1 && msg[0] == A2TP_TYPE_KEEPALIVE))
            logv("bad message (type 0x%02x, %zu bytes)", msg[0], mlen);
        stream_rx_next(&rx);
    }
    mark_dead(s);
    return NULL;
}

/* ---- tx: tap -> transport (blocks in read; one send syscall per frame) --- */

static void *tx_udp_thread(void *arg)
{
    struct sh *s = arg;
    block_termination_signals();
    uint8_t buf[HDR_LEN + MAX_FRAME];

    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
        ssize_t r = read(s->tfd, buf + HDR_LEN, MAX_FRAME);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            logmsg("tap read: %s", strerror(errno));
            break;
        }
        if (r == 0)
            break;
        buf[0] = A2TP_TYPE_DATA;
        struct sockaddr_in peer;
        key_to_sockaddr(__atomic_load_n(&s->peer_k, __ATOMIC_RELAXED), &peer);
        if (sendto(s->xfd, buf, r + HDR_LEN, 0,
                   (const struct sockaddr *)&peer, sizeof(peer)) < 0)
            logv("send: %s", strerror(errno));
        else {
            logv("tap->net %zd bytes", r);
            if (g_verbose)
                hexdump(buf + HDR_LEN, r, 24);
        }
    }
    mark_dead(s);
    return NULL;
}

static void *tx_tcp_thread(void *arg)
{
    struct sh *s = arg;
    block_termination_signals();
    uint8_t buf[2 + HDR_LEN + MAX_FRAME];   /* [len(2)][type][frame] */

    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
        ssize_t r = read(s->tfd, buf + 2 + HDR_LEN, MAX_FRAME);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            logmsg("tap read: %s", strerror(errno));
            break;
        }
        if (r == 0)
            break;
        buf[2] = A2TP_TYPE_DATA;
        if (stream_send_msg(s->xfd, buf + 2, HDR_LEN + (size_t)r) < 0) {
            logv("send failed: %s", strerror(errno));
            break;   /* connection is gone */
        }
        logv("tap->net %zd bytes", r);
        if (g_verbose)
            hexdump(buf + 2 + HDR_LEN, r, 24);
    }
    mark_dead(s);
    return NULL;
}

/* ---- keepalive: owns the liveness timer (single send, no lock needed) ---- */

static void keepalive_send(struct sh *s)
{
    uint8_t ka = A2TP_TYPE_KEEPALIVE;
    if (s->is_tcp) {
        if (stream_send_msg(s->xfd, &ka, 1) < 0) {
            logv("keepalive send: %s", strerror(errno));
            mark_dead(s);
        }
    } else {
        struct sockaddr_in peer;
        key_to_sockaddr(__atomic_load_n(&s->peer_k, __ATOMIC_RELAXED), &peer);
        if (sendto(s->xfd, &ka, 1, 0,
                   (const struct sockaddr *)&peer, sizeof(peer)) < 0)
            logv("keepalive send: %s", strerror(errno));
    }
}

static void *keepalive_thread(void *arg)
{
    struct sh *s = arg;
    block_termination_signals();
    int64_t next = now_ms();   /* first one right away: server learns our endpoint */

    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
        int64_t now = now_ms();
        if (now >= next) {
            keepalive_send(s);
            next = now + s->cfg->keepalive_ms;
        }
        int64_t ms = next - now_ms();
        if (ms < 0)
            ms = 0;
        if (ms > 1000)
            ms = 1000;   /* cap the sleep so teardown never waits long */
        if (ms > 0) {
            struct timespec ts = { .tv_sec = ms / 1000,
                                   .tv_nsec = (ms % 1000) * 1000000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

/* ---- lifecycle: main blocks here until a pump dies or a signal arrives --- */

static void main_wait(struct sh *s)
{
    while (!g_stop && !__atomic_load_n(&s->dead, __ATOMIC_RELAXED)) {
        char b;
        ssize_t r = read(s->ev_r, &b, 1);
        (void)r;   /* EINTR = signal, one byte = a pump thread died */
    }
}

static void pump_teardown(struct sh *s, pthread_t rx, pthread_t tx, pthread_t ka)
{
    shutdown(s->xfd, SHUT_RDWR);   /* wakes rx if it is still blocked */
    pthread_cancel(tx);            /* a blocked tap read wakes no other way */
    pthread_join(rx, NULL);
    pthread_join(tx, NULL);
    if (ka)
        pthread_join(ka, NULL);    /* leaves within <= 1 s on its own */
}

static int run_udp(struct cfg *cfg, int tfd)
{
    int ufd = udp_bind(htonl(INADDR_ANY), cfg->local_port);
    if (ufd < 0)
        die("bind udp %d", cfg->local_port);

    struct sockaddr_in local = {0};
    socklen_t llen = sizeof(local);
    getsockname(ufd, (struct sockaddr *)&local, &llen);
    char local_s[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &local.sin_addr, local_s, sizeof(local_s));
    logmsg("udp local %s:%d, keepalive %llds", local_s, ntohs(local.sin_port),
           (long long)(cfg->keepalive_ms / 1000));

    int ev[2];
    if (evpipe_create(ev) < 0)
        die("pipe");

    struct sh s = { .cfg = cfg, .tfd = tfd, .xfd = ufd, .ev_r = ev[0], .ev_w = ev[1],
                    .peer_k = sockaddr_key(&cfg->srv) };
    pthread_t rx, tx, ka = 0;
    if (pthread_create(&rx, NULL, rx_udp_thread, &s) ||
        pthread_create(&tx, NULL, tx_udp_thread, &s) ||
        (cfg->keepalive_ms > 0 && pthread_create(&ka, NULL, keepalive_thread, &s)))
        die("pthread_create");

    main_wait(&s);
    pump_teardown(&s, rx, tx, ka);
    close(ufd);
    logmsg("shutting down");
    return 0;
}

static int run_tcp(struct cfg *cfg, int tfd)
{
    char srv_s[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &cfg->srv.sin_addr, srv_s, sizeof(srv_s));

    int ev[2];
    if (evpipe_create(ev) < 0)
        die("pipe");

    while (!g_stop) {
        logmsg("connecting to %s:%d (tcp)", srv_s, ntohs(cfg->srv.sin_port));
        int cfd = tcp_connect_to(&cfg->srv, 5000);
        if (cfd < 0) {
            logmsg("connect failed: %s, retrying", strerror(errno));
            for (int i = 0; i < 3 && !g_stop; i++)
                sleep(1);
            continue;
        }

        struct sh s = { .cfg = cfg, .tfd = tfd, .xfd = cfd, .is_tcp = 1,
                        .ev_r = ev[0], .ev_w = ev[1] };
        pthread_t rx, tx, ka = 0;
        if (pthread_create(&rx, NULL, rx_tcp_thread, &s) ||
            pthread_create(&tx, NULL, tx_tcp_thread, &s) ||
            (cfg->keepalive_ms > 0 && pthread_create(&ka, NULL, keepalive_thread, &s)))
            die("pthread_create");

        main_wait(&s);
        int stopped = g_stop;
        pump_teardown(&s, rx, tx, ka);
        close(cfd);
        if (stopped)
            break;
        logmsg("tcp connection lost, reconnecting");
        for (int i = 0; i < 3 && !g_stop; i++)
            sleep(1);
    }

    logmsg("shutting down");
    return 0;
}

/* ======================================================================== */

int main(int argc, char **argv)
{
    struct cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_port = A2TP_UDP_PORT;
    cfg.tap = "a2tp0";
    cfg.keepalive_ms = 10000;

    static int opt_tcp;   /* long-only flag, copied into cfg after parsing */

    static const struct option lopts[] = {
        {"server",    required_argument, 0, 's'},
        {"port",      required_argument, 0, 'p'},
        {"tap",       required_argument, 0, 't'},
        {"tcp",       no_argument,       &opt_tcp, 1},
        {"up",        no_argument,       0, 'U'},
        {"mac",       required_argument, 0, 'm'},
        {"mtu",       required_argument, 0, 'M'},
        {"keepalive", required_argument, 0, 'k'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0},
    };
    int have_srv = 0, opt;
    while ((opt = getopt_long(argc, argv, "s:p:t:Um:M:k:vh", lopts, NULL)) != -1) {
        switch (opt) {
        case 0:  break;   /* flag options (--tcp) */
        case 's':
            if (parse_ip_port(optarg, A2TP_UDP_PORT, &cfg.srv) < 0)
                die("-s: expect ip[:port]");
            have_srv = 1;
            break;
        case 'p': cfg.local_port = atoi(optarg); break;
        case 't': cfg.tap = optarg; break;
        case 'U': break; /* tap is always brought up; kept for compatibility */
        case 'm':
            if (parse_mac(optarg, cfg.mac) < 0)
                die("--mac: expect aa:bb:cc:dd:ee:ff");
            cfg.have_mac = 1;
            break;
        case 'M': cfg.mtu = atoi(optarg); break;
        case 'k': cfg.keepalive_ms = atoi(optarg) * 1000; break;
        case 'v': g_verbose = 1; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return 1;
        }
    }
    if (!have_srv) {
        usage(stderr);
        return 1;
    }
    cfg.tcp = opt_tcp;
    if (strlen(cfg.tap) >= IFNAMSIZ)
        die("tap name too long");

    install_signal_handlers();

    int tfd = tap_open(cfg.tap);

    if (cfg.have_mac && if_set_mac(cfg.tap, cfg.mac) < 0)
        die("set mac on %s", cfg.tap);
    if (cfg.mtu > 0 && if_set_mtu(cfg.tap, cfg.mtu) < 0)
        die("set mtu on %s", cfg.tap);
    /* promisc so mirrored unicast frames to foreign MACs enter the stack */
    if (if_up(cfg.tap, 1) < 0)
        die("bring up %s", cfg.tap);

    uint8_t mac[6] = {0};
    int mtu = 0;
    if_get_mac(cfg.tap, mac);
    if_get_mtu(cfg.tap, &mtu);

    char srv_s[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &cfg.srv.sin_addr, srv_s, sizeof(srv_s));

    logmsg("a2tp-cli tap %s (mac %02x:%02x:%02x:%02x:%02x:%02x, mtu %d), %s, "
           "server %s:%d", cfg.tap,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mtu,
           cfg.tcp ? "tcp" : "udp", srv_s, ntohs(cfg.srv.sin_port));

    /* one dispatch at startup: the pump threads are transport-specific */
    if (cfg.tcp)
        return run_tcp(&cfg, tfd);
    return run_udp(&cfg, tfd);
}
