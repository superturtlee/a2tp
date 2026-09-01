/*
 * common.c - shared helpers for a2tp-srv / a2tp-cli
 */
#include "common.h"

#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

int g_verbose;
volatile sig_atomic_t g_stop;

void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, " (%s)\n", strerror(errno));
    va_end(ap);
    exit(1);
}

void logmsg(const char *fmt, ...)
{
    va_list ap;
    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    fprintf(stderr, "[%s] ", ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void logv(const char *fmt, ...)
{
    va_list ap;
    if (!g_verbose)
        return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void hexdump(const uint8_t *p, size_t n, size_t max)
{
    size_t i, limit = n < max ? n : max;
    fprintf(stderr, "        %zu bytes:", n);
    for (i = 0; i < limit; i++)
        fprintf(stderr, " %02x", p[i]);
    if (n > limit)
        fprintf(stderr, " ...");
    fputc('\n', stderr);
}

int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int parse_ip_port(const char *s, uint16_t def_port, struct sockaddr_in *out)
{
    char buf[256];
    char *colon;
    long port = def_port;

    if (!s || !*s)
        return -1;
    snprintf(buf, sizeof(buf), "%s", s);
    colon = strrchr(buf, ':');
    if (colon) {
        char *end = NULL;
        *colon = '\0';
        port = strtol(colon + 1, &end, 10);
        if (!end || *end || port < 0 || port > 65535)
            return -1;
        if (!*buf)
            return -1;
    }
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, buf, &out->sin_addr) != 1)
        return -1;
    return 0;
}

int parse_mac(const char *s, uint8_t out[6])
{
    unsigned int m[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x",
                     &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (m[i] > 0xff)
            return -1;
        out[i] = (uint8_t)m[i];
    }
    return 0;
}

int udp_bind(uint32_t bind_ip, uint16_t local_port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* allow outer-IP fragmentation so full-size L2 frames can pass through */
    int dont = IP_PMTUDISC_DONT;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &dont, sizeof(dont));
    int bufsz = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = bind_ip;
    a.sin_port = htons(local_port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

/*
 * No userspace checksum code: the TAP is opened without IFF_VNET_HDR and with
 * TUNSETOFFLOAD(0), so the kernel computes every checksum in software before
 * a frame is handed to us, and frames mirrored from a real NIC were completed
 * by hardware (or by the sender's kernel) before they hit the wire.  Any lab
 * path that violates this (e.g. veth tx-checksumming) must be fixed at the
 * source with `ethtool -K <if> tx off` -- see test/bench.sh.
 */

/*
 * Walk Ethernet [+VLAN tags] and hand back the offset of the L3 header plus
 * the unwrapped ethertype; (size_t)-1 when the frame is too short.
 */
static size_t l3_hdr(const uint8_t *f, size_t len, uint16_t *et_out)
{
    if (len < ETH_HLEN)
        return (size_t)-1;
    uint16_t et = (f[12] << 8) | f[13];
    size_t off = ETH_HLEN;
    while ((et == 0x8100 || et == 0x88a8) && len >= off + 4) {
        et = (f[off + 2] << 8) | f[off + 3];
        off += 4;
    }
    *et_out = et;
    return off;
}

/* VLAN-unwrapped ethertype (0x0800 = IPv4, 0x0806 = ARP, ...), 0 if too short */
uint16_t frame_ethertype(const uint8_t *f, size_t len)
{
    uint16_t et = 0;
    l3_hdr(f, len, &et);
    return et;
}

/*
 * IPv4 destination of an Eth[+VLAN]+IPv4 frame.  0 when the frame is not
 * IPv4 -- 0.0.0.0 is not a usable unicast destination, so 0 unambiguously
 * means "none" for matching purposes.
 */
uint32_t frame_ipv4_dst(const uint8_t *f, size_t len)
{
    uint16_t et = 0;
    size_t off = l3_hdr(f, len, &et);
    if (off == (size_t)-1 || et != 0x0800)
        return 0;
    if (len < off + sizeof(struct iphdr))
        return 0;
    const struct iphdr *iph = (const struct iphdr *)(f + off);
    if ((size_t)iph->ihl * 4 < 20)
        return 0;
    return iph->daddr;
}

/*
 * Walk Ethernet [+VLAN tags] -> IPv4 -> UDP and match the tunnel's own
 * 5-tuple. Only IPv4 is inspected (the tunnel itself is IPv4).
 */
int frame_is_tunnel_l4(const uint8_t *f, size_t len,
                       uint16_t local_port, uint32_t peer_ip, uint16_t peer_port)
{
    uint16_t et = 0;
    size_t off = l3_hdr(f, len, &et);
    if (off == (size_t)-1 || et != 0x0800)
        return 0;

    const uint8_t *ip = f + off;
    size_t iplen = len - off;
    if (iplen < sizeof(struct iphdr))
        return 0;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    if (ihl < 20 || iplen < ihl + sizeof(struct udphdr))
        return 0;
    if (ip[9] != IPPROTO_UDP)
        return 0;

    const struct iphdr *iph = (const struct iphdr *)ip;
    const struct udphdr *uh = (const struct udphdr *)(ip + ihl);
    uint16_t sp = ntohs(uh->source), dp = ntohs(uh->dest);

    int port_match;
    if (peer_port)
        port_match = (sp == peer_port && dp == local_port) ||
                     (sp == local_port && dp == peer_port);
    else
        port_match = (sp == local_port || dp == local_port);
    if (!port_match)
        return 0;
    if (peer_ip)
        return iph->saddr == peer_ip || iph->daddr == peer_ip;
    return 1;
}

/* ---------- interface helpers ---------- */

int ctl_socket(void)
{
    return socket(AF_INET, SOCK_DGRAM, 0);
}

static int if_ioctl(int cmd, struct ifreq *ifr)
{
    int fd = ctl_socket();
    if (fd < 0)
        return -1;
    int rc = ioctl(fd, cmd, ifr);
    int err = errno;
    close(fd);
    errno = err;
    return rc;
}

int if_up(const char *ifname, int promisc)
{
    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (if_ioctl(SIOCGIFFLAGS, &ifr) < 0)
        return -1;
    ifr.ifr_flags |= IFF_UP;
    if (promisc)
        ifr.ifr_flags |= IFF_PROMISC;
    return if_ioctl(SIOCSIFFLAGS, &ifr);
}

int if_set_mac(const char *ifname, const uint8_t mac[6])
{
    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
    return if_ioctl(SIOCSIFHWADDR, &ifr);
}

int if_set_mtu(const char *ifname, int mtu)
{
    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_mtu = mtu;
    return if_ioctl(SIOCSIFMTU, &ifr);
}

int if_get_mtu(const char *ifname, int *mtu)
{
    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (if_ioctl(SIOCGIFMTU, &ifr) < 0)
        return -1;
    *mtu = ifr.ifr_mtu;
    return 0;
}

int if_get_mac(const char *ifname, uint8_t mac[6])
{
    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (if_ioctl(SIOCGIFHWADDR, &ifr) < 0)
        return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

/*
 * tso/gso/gro control.  A mirror must forward what is really on the wire;
 * offloaded 64K super-frames are not wire frames and would also exceed the
 * UDP datagram limit, so the server turns them off while it owns the NIC and
 * restores the previous state on shutdown.
 */
static const struct { int get; int set; const char *name; } offload_flags[] = {
    { ETHTOOL_GTSO, ETHTOOL_STSO, "tso" },
    { ETHTOOL_GGSO, ETHTOOL_SGSO, "gso" },
    { ETHTOOL_GGRO, ETHTOOL_SGRO, "gro" },
};

/* read current tso/gso/gro into ov (entry -1 = unknown/unsupported) */
int if_offload_save(const char *ifname, int ov[OFFLOAD_N])
{
    for (size_t i = 0; i < OFFLOAD_N; i++) {
        struct ethtool_value ev;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        memset(&ev, 0, sizeof(ev));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
        ev.cmd = offload_flags[i].get;
        ifr.ifr_data = (char *)&ev;
        ov[i] = if_ioctl(SIOCETHTOOL, &ifr) < 0 ? -1 : (ev.data != 0);
    }
    return 0;
}

/* apply ov entries that are 0/1; returns the number of failed flags */
int if_offload_apply(const char *ifname, const int ov[OFFLOAD_N])
{
    int failed = 0;

    for (size_t i = 0; i < OFFLOAD_N; i++) {
        if (ov[i] != 0 && ov[i] != 1)
            continue;
        struct ethtool_value ev;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        memset(&ev, 0, sizeof(ev));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
        ev.cmd = offload_flags[i].set;
        ev.data = (uint32_t)ov[i];
        ifr.ifr_data = (char *)&ev;
        if (if_ioctl(SIOCETHTOOL, &ifr) < 0) {
            logv("%s: %s %s failed (%s)", ifname, offload_flags[i].name,
                 ov[i] ? "on" : "off", strerror(errno));
            failed++;
        }
    }
    return failed;
}

int if_disable_offloads(const char *ifname)
{
    int ov[OFFLOAD_N] = { 0, 0, 0 };
    return if_offload_apply(ifname, ov);
}

/* ---------- signals ---------- */

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

void install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: blocked syscalls return EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/* ---------- threading helpers ---------- */

uint64_t sockaddr_key(const struct sockaddr_in *a)
{
    /* ip (4B, network order) << 16 | port (2B, network order) */
    return ((uint64_t)a->sin_addr.s_addr << 16) | a->sin_port;
}

void key_to_sockaddr(uint64_t key, struct sockaddr_in *a)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = (uint32_t)(key >> 16);
    a->sin_port = (uint16_t)(key & 0xffff);
}

int evpipe_create(int fds[2])
{
    if (pipe2(fds, O_CLOEXEC) < 0)
        return -1;
    /* writers never block (a full pipe just means main is already waking) */
    int fl = fcntl(fds[1], F_GETFL, 0);
    if (fl >= 0)
        fcntl(fds[1], F_SETFL, fl | O_NONBLOCK);
    return 0;
}

void evpipe_notify(int fd)
{
    char c = 1;
    ssize_t r = write(fd, &c, 1);
    (void)r;
}

void sock_rcvtimeo(int fd, int ms)
{
    struct timeval tv = { .tv_sec = ms / 1000,
                          .tv_usec = (suseconds_t)(ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void block_termination_signals(void)
{
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGINT);
    sigaddset(&s, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
}
