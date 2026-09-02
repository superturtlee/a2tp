/*
 * a2tpctl.c - control-plane tool for the a2tp kernel module
 *
 *   server side: generic netlink family "a2tp"
 *       a2tpctl srv add -i eth0 [--peer 1.2.3.4:1702] [--filter-ip ..] ..
 *       a2tpctl srv del -i eth0
 *       a2tpctl srv status
 *   client side: rtnetlink link kind "a2tp" (until iproute2 grows a
 *   link_a2tp.c, this tool speaks RTM_NEWLINK directly)
 *       a2tpctl cli add a2tp0 remote 1.2.3.4:1702 [local-port 0] ..
 *       a2tpctl cli del a2tp0
 *
 * NIC offload handling (tso/gso/gro off while the server owns the NIC) is
 * done here, not in the kernel: the same ethtool ioctls the userspace
 * a2tp-srv used, persisted across invocations so `srv del` can restore.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include "kapi.h"
#include "proto.h"	/* wire format constants: A2TP_UDP_PORT */


/* ---------------- small helpers ---------------- */

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, " (%s)\n", strerror(errno));
	va_end(ap);
	exit(1);
}

static void logmsg(const char *fmt, ...)
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

static int g_verbose;

static void logv(const char *fmt, ...)
{
	va_list ap;

	if (!g_verbose)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* ---------------- dual-family addresses ---------------- */

struct xaddr {
	int		family;		/* AF_INET / AF_INET6 / AF_UNSPEC */
	union {
		uint32_t	v4;	/* network order */
		uint8_t		v6[16];
	};
};

/* parse "1.2.3.4:1702", "1.2.3.4", "[fd00::1]:1702" or "fd00::1";
 * v6-with-port requires the brackets (same rule as ssh / iproute2).
 * def_port is used when none is given; *port_be gets the network-order
 * port */
static int parse_addr_port(const char *s, uint16_t def_port,
			   struct xaddr *a, uint16_t *port_be)
{
	char buf[256], *host, *serv = NULL;
	long port = def_port;
	int colons = 0;
	const char *c;

	if (!s || !*s)
		return -1;
	snprintf(buf, sizeof(buf), "%s", s);
	if (buf[0] == '[') {
		char *rb = strchr(buf, ']');

		if (!rb)
			return -1;
		*rb = '\0';
		host = buf + 1;
		if (rb[1] == ':')
			serv = rb + 2;
		else if (rb[1])
			return -1;
	} else {
		for (c = buf; *c; c++)
			colons += (*c == ':');
		if (colons == 1) {
			/* single colon: v4 "ip:port" (bare v6 has >= 2) */
			host = buf;
			serv = strchr(buf, ':');
			*serv++ = '\0';
		} else {
			host = buf;
		}
	}
	if (serv && *serv) {
		char *end = NULL;

		port = strtol(serv, &end, 10);
		if (!end || *end || port < 0 || port > 65535)
			return -1;
	}

	memset(a, 0, sizeof(*a));
	if (inet_pton(AF_INET, host, &a->v4) == 1)
		a->family = AF_INET;
	else if (inet_pton(AF_INET6, host, a->v6) == 1)
		a->family = AF_INET6;
	else
		return -1;
	*port_be = htons((uint16_t)port);
	return 0;
}

/* bare address, no port allowed (e.g. -b, cli local) */
static int parse_addr(const char *s, struct xaddr *a)
{
	uint16_t port_be;

	if (parse_addr_port(s, 0, a, &port_be) < 0 || port_be)
		return -1;
	return 0;
}

static const char *addr_str(const struct xaddr *a, char *buf, size_t n)
{
	if (a->family == AF_INET) {
		struct in_addr in;

		in.s_addr = a->v4;
		inet_ntop(AF_INET, &in, buf, n);
	} else if (a->family == AF_INET6) {
		inet_ntop(AF_INET6, a->v6, buf, n);
	} else {
		snprintf(buf, n, "(?)");
	}
	return buf;
}

/* "1.2.3.4:1702" / "[fd00::1]:1702" */
static const char *addr_port_str(const struct xaddr *a, uint16_t port_be,
				 char *buf, size_t n)
{
	char ab[64];

	addr_str(a, ab, sizeof(ab));
	if (a->family == AF_INET6)
		snprintf(buf, n, "[%s]:%hu", ab, ntohs(port_be));
	else
		snprintf(buf, n, "%s:%hu", ab, ntohs(port_be));
	return buf;
}

/* address-style mask for a prefix length (the only place prefix math
 * exists; everything downstream sees a plain mask) */
static void plen_to_mask(int family, int plen, struct xaddr *mask)
{
	int i;

	memset(mask, 0, sizeof(*mask));
	mask->family = family;
	if (family == AF_INET) {
		mask->v4 = plen ? htonl((uint32_t)~0U << (32 - plen)) : 0;
		return;
	}
	for (i = 0; i < plen; i++)
		mask->v6[i / 8] |= (uint8_t)(0x80 >> (i % 8));
}

/* parse one --filter-ip / --filter-ip6 entry, "a" or "a/m":
 *   m all-digits within family range -> prefix length (10.0.0.0/24)
 *   otherwise                        -> address-style mask
 *                                    (10.0.0.0/255.255.255.0,
 *                                     fd00::/ffff:ffff::)
 * a bare address is an exact match.  The entry is normalized here
 * (addr &= mask) and sent as raw {addr, mask}; no network/host semantics
 * travel further than this function. */
static int parse_filter(const char *s, int family,
			struct xaddr *addr, struct xaddr *mask)
{
	char buf[256], *sl;
	int maxbits = family == AF_INET6 ? 128 : 32;
	int i;

	snprintf(buf, sizeof(buf), "%s", s);
	sl = strchr(buf, '/');
	if (sl)
		*sl++ = '\0';

	memset(addr, 0, sizeof(*addr));
	memset(mask, 0, sizeof(*mask));
	addr->family = mask->family = family;
	if (inet_pton(family, buf, family == AF_INET6 ? (void *)addr->v6
						      : &addr->v4) != 1)
		return -1;

	if (!sl) {
		plen_to_mask(family, maxbits, mask);	/* exact match */
	} else {
		char *end = NULL;
		long v = strtol(sl, &end, 10);

		if (end && !*end && v >= 0 && v <= maxbits)
			plen_to_mask(family, (int)v, mask);
		else if (inet_pton(family, sl,
				   family == AF_INET6 ? (void *)mask->v6
						      : &mask->v4) != 1)
			return -1;
	}

	if (family == AF_INET) {
		addr->v4 &= mask->v4;
	} else {
		for (i = 0; i < 16; i++)
			addr->v6[i] &= mask->v6[i];
	}
	return 0;
}

/* parse "aa:bb:cc:dd:ee:ff" */
static int parse_mac(const char *s, uint8_t out[6])
{
	unsigned int m[6];
	int i;

	if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x",
			 &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
		return -1;
	for (i = 0; i < 6; i++) {
		if (m[i] > 0xff)
			return -1;
		out[i] = (uint8_t)m[i];
	}
	return 0;
}

/* ---------------- NIC offload handling (ethtool ioctls) ----------------
 * A mirror must forward what is really on the wire; offloaded 64K
 * super-frames are not wire frames and would also exceed the UDP datagram
 * limit, so the server side turns tso/gso/gro off while it owns the NIC
 * and restores the previous state on `srv del`. */

#define OFFLOAD_N 3	/* tso, gso, gro */

static int ctl_socket(void)
{
	return socket(AF_INET, SOCK_DGRAM, 0);
}

static int if_ioctl(int cmd, struct ifreq *ifr)
{
	int fd = ctl_socket();
	int rc, err;

	if (fd < 0)
		return -1;
	rc = ioctl(fd, cmd, ifr);
	err = errno;
	close(fd);
	errno = err;
	return rc;
}

static const struct { int get; int set; const char *name; } offload_flags[] = {
	{ ETHTOOL_GTSO, ETHTOOL_STSO, "tso" },
	{ ETHTOOL_GGSO, ETHTOOL_SGSO, "gso" },
	{ ETHTOOL_GGRO, ETHTOOL_SGRO, "gro" },
};

/* read current tso/gso/gro into ov (entry -1 = unknown/unsupported) */
static int if_offload_save(const char *ifname, int ov[OFFLOAD_N])
{
	size_t i;

	for (i = 0; i < OFFLOAD_N; i++) {
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
static int if_offload_apply(const char *ifname, const int ov[OFFLOAD_N])
{
	int failed = 0;
	size_t i;

	for (i = 0; i < OFFLOAD_N; i++) {
		struct ethtool_value ev;
		struct ifreq ifr;

		if (ov[i] != 0 && ov[i] != 1)
			continue;
		memset(&ifr, 0, sizeof(ifr));
		memset(&ev, 0, sizeof(ev));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
		ev.cmd = offload_flags[i].set;
		ev.data = (uint32_t)ov[i];
		ifr.ifr_data = (char *)&ev;
		if (if_ioctl(SIOCETHTOOL, &ifr) < 0) {
			logv("%s: %s %s failed (%s)", ifname,
			     offload_flags[i].name, ov[i] ? "on" : "off",
			     strerror(errno));
			failed++;
		}
	}
	return failed;
}

static int if_disable_offloads(const char *ifname)
{
	int ov[OFFLOAD_N] = { 0, 0, 0 };

	return if_offload_apply(ifname, ov);
}

const char *const a2tp_kstat_name[A2TP_KSTAT_NR] = {
	"mirror", "inject", "tx_err", "rx_data", "rx_ka", "rx_bad",
	"pass_filter", "pass_self", "pass_no_peer", "pass_gso", "pass_mtu",
	"peer_pinned_drop", "keepalive",
};

/* ---------------- raw netlink plumbing ---------------- */

struct nlbuf {
	char	b[8192];
	size_t	len;
};

struct nlsk {
	int	fd;
	uint32_t seq;
};

static void nl_put(struct nlbuf *nb, const void *d, size_t n)
{
	if (nb->len + n > sizeof(nb->b))
		die("netlink message too long");
	memcpy(nb->b + nb->len, d, n);
	nb->len += n;
}

static void nl_pad(struct nlbuf *nb)
{
	while (nb->len % NLA_ALIGNTO)
		nb->b[nb->len++] = '\0';
}

static void nl_put_attr(struct nlbuf *nb, uint16_t type,
			const void *d, size_t n)
{
	struct nlattr na = { .nla_len = NLA_HDRLEN + n, .nla_type = type };

	nl_put(nb, &na, sizeof(na));
	nl_put(nb, d, n);
	nl_pad(nb);
}

#define nl_put_str(nb, t, s)	nl_put_attr(nb, t, s, strlen(s) + 1)
#define nl_put_u16(nb, t, v)	nl_put_attr(nb, t, &(uint16_t){(uint16_t)(v)}, 2)
#define nl_put_u32(nb, t, v)	nl_put_attr(nb, t, &(uint32_t){(uint32_t)(v)}, 4)
#define nl_put_flag(nb, t)	nl_put_attr(nb, t, NULL, 0)

/* start a nested attr; returns the offset to pass to nl_nest_end() */
static size_t nl_nest_start(struct nlbuf *nb, uint16_t type)
{
	size_t off = nb->len;
	struct nlattr na = { .nla_len = NLA_HDRLEN,
			     .nla_type = type | NLA_F_NESTED };

	nl_put(nb, &na, sizeof(na));
	return off;
}

static void nl_nest_end(struct nlbuf *nb, size_t off)
{
	struct nlattr *na = (struct nlattr *)(nb->b + off);

	na->nla_len = nb->len - off;
}

static void nl_open(struct nlsk *sk, int proto)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };

	sk->fd = socket(AF_NETLINK, SOCK_RAW, proto);
	if (sk->fd < 0)
		die("netlink socket: %s", strerror(errno));
	if (bind(sk->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("netlink bind: %s", strerror(errno));
	sk->seq = (uint32_t)time(NULL);
}

/* finalize @nb and send it.  Every request carries NLM_F_ACK so a terminal
 * NLMSG_ERROR always comes back.  Returns 0 on ack, negative errno on
 * error; when a non-error reply message (genlmsg_reply / dumpit records)
 * arrives first, it is copied into @reply and also returns 0.
 */
static int nl_talk(struct nlsk *sk, struct nlbuf *nb, struct nlbuf *reply)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)nb->b;
	char rbuf[8192];

	nh->nlmsg_len = nb->len;
	nh->nlmsg_seq = ++sk->seq;
	if (send(sk->fd, nb->b, nb->len, 0) < 0)
		die("netlink send: %s", strerror(errno));

	for (;;) {
		ssize_t n = recv(sk->fd, rbuf, sizeof(rbuf), 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("netlink recv: %s", strerror(errno));
		}

		struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
		int len = (int)n;

		for (; NLMSG_OK(rh, len); rh = NLMSG_NEXT(rh, len)) {
			if (rh->nlmsg_seq != sk->seq)
				continue;
			if (rh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(rh);

				return e->error;	/* 0 = plain ACK */
			}
			if (reply && rh->nlmsg_len <= sizeof(reply->b)) {
				memcpy(reply->b, rh, rh->nlmsg_len);
				reply->len = rh->nlmsg_len;
				reply = NULL;	/* only the first one */
			}
			/* else: late multicast etc, keep waiting */
		}
	}
}

/* start a genl message for @cmd */
static void genl_start(struct nlbuf *nb, uint16_t fam, uint8_t cmd,
		       uint16_t extra_flags)
{
	struct nlmsghdr n = {
		.nlmsg_type	= fam,
		.nlmsg_flags	= NLM_F_REQUEST | NLM_F_ACK | extra_flags,
	};
	struct genlmsghdr g = { .cmd = cmd, .version = A2TP_GENL_VERSION };

	nl_put(nb, &n, sizeof(n));
	nl_put(nb, &g, sizeof(g));
}

/* resolve a genl family id by name (CTRL_CMD_GETFAMILY) */
static uint16_t genl_resolve(struct nlsk *sk, const char *name)
{
	struct nlbuf nb = { .len = 0 }, rep = { .len = 0 };
	struct walk {
		struct nlattr *na;
		int rem;
	} w;
	int rc;

	genl_start(&nb, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0);
	nl_put_str(&nb, CTRL_ATTR_FAMILY_NAME, name);
	rc = nl_talk(sk, &nb, &rep);
	if (rc < 0)
		die("genl family \"%s\" not available: %s (is the a2tp module loaded?)",
		    name, strerror(-rc));
	if (!rep.len)
		die("genl family \"%s\": empty reply", name);

	w.na = (struct nlattr *)((char *)NLMSG_DATA(rep.b) + GENL_HDRLEN);
	w.rem = NLMSG_PAYLOAD((struct nlmsghdr *)rep.b, GENL_HDRLEN);
	for (; w.rem >= (int)NLA_HDRLEN && w.na->nla_len >= NLA_HDRLEN &&
	     w.na->nla_len <= w.rem;
	     w.rem -= NLA_ALIGN(w.na->nla_len),
	     w.na = (struct nlattr *)((char *)w.na + NLA_ALIGN(w.na->nla_len)))
		if ((w.na->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID &&
		    w.na->nla_len >= NLA_HDRLEN + 2)
			return *(uint16_t *)((char *)w.na + NLA_HDRLEN);
	die("genl family \"%s\": no id in reply", name);
}

/* ---------------- attribute walking ---------------- */

struct walk {
	struct nlattr	*na;
	int		rem;
};

static void attr_first(struct walk *w, struct nlmsghdr *nh, size_t hdr)
{
	w->na = (struct nlattr *)((char *)NLMSG_DATA(nh) + hdr);
	w->rem = NLMSG_PAYLOAD(nh, hdr);
}

static int attr_ok(struct walk *w)
{
	return w->rem >= (int)NLA_HDRLEN && w->na->nla_len >= NLA_HDRLEN &&
	       w->na->nla_len <= w->rem;
}

static void attr_advance(struct walk *w)
{
	w->rem -= NLA_ALIGN(w->na->nla_len);
	w->na = (struct nlattr *)((char *)w->na + NLA_ALIGN(w->na->nla_len));
}

static void nest_walk(struct walk *w, struct nlattr *na)
{
	w->na = (struct nlattr *)((char *)na + NLA_HDRLEN);
	w->rem = na->nla_len - NLA_HDRLEN;
}

static uint32_t attr_u32(struct nlattr *na)
{
	uint32_t v;

	memcpy(&v, (char *)na + NLA_HDRLEN, sizeof(v));
	return v;
}

static uint16_t attr_u16(struct nlattr *na)
{
	uint16_t v;

	memcpy(&v, (char *)na + NLA_HDRLEN, sizeof(v));
	return v;
}

static uint64_t attr_u64(struct nlattr *na)
{
	uint64_t v;

	memcpy(&v, (char *)na + NLA_HDRLEN, sizeof(v));
	return v;
}

/* ---------------- offload-state persistence ---------------- */

/* the userspace a2tp-srv kept this in process memory; a ctl tool lives
 * one command at a time, so park the saved state next to the interface */
static void offl_path(char *out, size_t n, const char *ifname)
{
	snprintf(out, n, "/run/a2tp-offload-%s.bin", ifname);
}

static int offl_save(const char *ifname, const int ov[OFFLOAD_N])
{
	char path[256];
	FILE *f;
	struct {
		char magic[8];
		int v[OFFLOAD_N];
	} rec;

	memcpy(rec.magic, "a2tpof01", 8);
	memcpy(rec.v, ov, sizeof(rec.v));
	offl_path(path, sizeof(path), ifname);
	f = fopen(path, "wb");
	if (!f)
		return -1;
	fwrite(&rec, sizeof(rec), 1, f);
	fclose(f);
	return 0;
}

static int offl_load_apply(const char *ifname)
{
	char path[256];
	FILE *f;
	struct {
		char magic[8];
		int v[OFFLOAD_N];
	} rec;

	offl_path(path, sizeof(path), ifname);
	f = fopen(path, "rb");
	if (!f)
		return -1;
	if (fread(&rec, sizeof(rec), 1, f) != 1 ||
	    memcmp(rec.magic, "a2tpof01", 8)) {
		fclose(f);
		unlink(path);
		return -1;
	}
	fclose(f);
	unlink(path);
	return if_offload_apply(ifname, rec.v);
}

/* ---------------- server (genl) commands ---------------- */

/* one parsed {addr, mask} entry onto the wire */
static void put_filter_entry(struct nlbuf *nb, const struct xaddr *addr,
			     const struct xaddr *mask)
{
	size_t nest = nl_nest_start(nb, 1 /* position-only type */);
	int v6 = addr->family == AF_INET6;
	size_t len = v6 ? 16 : 4;

	nl_put_attr(nb, A2TP_FILTER_ADDR, v6 ? (const void *)addr->v6 : &addr->v4,
		    len);
	nl_put_attr(nb, A2TP_FILTER_MASK, v6 ? (const void *)mask->v6 : &mask->v4,
		    len);
	nl_nest_end(nb, nest);
}

/* parse a comma-separated --filter-ip[-6] argument into fa/fm */
static void parse_filter_list(const char *s, int family,
			      struct xaddr fa[], struct xaddr fm[],
			      int *n, int *n_other)
{
	char *dup = strdup(s), *tok, *save = NULL;

	for (tok = strtok_r(dup, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		if (*n + *n_other >= A2TP_FILTER_MAX)
			die("too many filter entries (max %d)", A2TP_FILTER_MAX);
		if (parse_filter(tok, family, &fa[*n], &fm[*n]) < 0)
			die("bad filter entry \"%s\" (family %s)", tok,
			    family == AF_INET6 ? "ipv6" : "ipv4");
		(*n)++;
	}
	free(dup);
}

static int cmd_srv_add(int argc, char **argv)
{
	const char *ifname = NULL, *bind_s = NULL, *peer_s = NULL;
	const char *filter4_s = NULL, *filter6_s = NULL;
	int i;
	uint16_t port = A2TP_UDP_PORT;
	uint32_t peer_timeout_s = 30;
	bool no_self_filter = false, keep_offloads = false;
	struct xaddr peer_a = {}, bind_a = {};
	uint16_t peer_port = 0;
	struct xaddr f4a[A2TP_FILTER_MAX], f4m[A2TP_FILTER_MAX];
	struct xaddr f6a[A2TP_FILTER_MAX], f6m[A2TP_FILTER_MAX];
	int nf4 = 0, nf6 = 0;
	struct nlsk sk;
	struct nlbuf nb = { .len = 0 };
	size_t nest;
	int ov[OFFLOAD_N];
	bool saved_off = false;
	int rc;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-i") && i + 1 < argc)
			ifname = argv[++i];
		else if (!strcmp(argv[i], "-p") && i + 1 < argc)
			port = (uint16_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--peer") && i + 1 < argc)
			peer_s = argv[++i];
		else if (!strcmp(argv[i], "--peer-timeout") && i + 1 < argc)
			peer_timeout_s = (uint32_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "-b") && i + 1 < argc)
			bind_s = argv[++i];
		else if (!strcmp(argv[i], "--filter-ip") && i + 1 < argc)
			filter4_s = argv[++i];
		else if (!strcmp(argv[i], "--filter-ip6") && i + 1 < argc)
			filter6_s = argv[++i];
		else if (!strcmp(argv[i], "--no-self-filter"))
			no_self_filter = true;
		else if (!strcmp(argv[i], "--keep-offloads"))
			keep_offloads = true;
		else
			die("srv add: unknown arg \"%s\"", argv[i]);
	}
	if (!ifname)
		die("srv add: -i <iface> required");

	if (peer_s && parse_addr_port(peer_s, A2TP_UDP_PORT, &peer_a,
				      &peer_port) < 0)
		die("bad --peer \"%s\" (v6 needs brackets: [fd00::1]:1702)",
		    peer_s);
	if (bind_s && parse_addr(bind_s, &bind_a) < 0)
		die("bad -b \"%s\"", bind_s);

	/* offloads off BEFORE the kernel pump starts mirroring, exactly like
	 * the userspace a2tp-srv at startup (GRO super-frames cannot ride a
	 * 64 KB datagram); persist the old state for `srv del` */
	if (!keep_offloads) {
		if (if_offload_save(ifname, ov) == 0) {
			saved_off = true;
			if (offl_save(ifname, ov) < 0)
				logmsg("warning: cannot persist offload state of %s",
				       ifname);
			if_disable_offloads(ifname);
		} else {
			logmsg("warning: cannot read offload state of %s "
			       "(ethtool missing?); leaving as-is", ifname);
		}
	}

	nl_open(&sk, NETLINK_GENERIC);
	genl_start(&nb, genl_resolve(&sk, A2TP_GENL_NAME), A2TP_CMD_SRV_ADD, 0);
	nl_put_str(&nb, A2TP_ATTR_IFNAME, ifname);
	nl_put_u16(&nb, A2TP_ATTR_PORT, port);
	if (bind_s) {
		if (bind_a.family == AF_INET6)
			nl_put_attr(&nb, A2TP_ATTR_BIND_IP6, bind_a.v6, 16);
		else
			nl_put_u32(&nb, A2TP_ATTR_BIND_IP, bind_a.v4);
	}
	if (peer_s) {
		nl_put_flag(&nb, A2TP_ATTR_PEER_FIXED);
		if (peer_a.family == AF_INET6)
			nl_put_attr(&nb, A2TP_ATTR_PEER_IP6, peer_a.v6, 16);
		else
			nl_put_u32(&nb, A2TP_ATTR_PEER_IP, peer_a.v4);
		nl_put_attr(&nb, A2TP_ATTR_PEER_PORT, &peer_port, 2);
	}
	nl_put_u32(&nb, A2TP_ATTR_PEER_TIMEOUT, peer_timeout_s * 1000);
	if (no_self_filter)
		nl_put_flag(&nb, A2TP_ATTR_NO_SELF_FILTER);
	if (filter4_s)
		parse_filter_list(filter4_s, AF_INET, f4a, f4m, &nf4, &nf6);
	if (filter6_s)
		parse_filter_list(filter6_s, AF_INET6, f6a, f6m, &nf6, &nf4);
	if (nf4) {
		nest = nl_nest_start(&nb, A2TP_ATTR_FILTER_IP);
		for (i = 0; i < nf4; i++)
			put_filter_entry(&nb, &f4a[i], &f4m[i]);
		nl_nest_end(&nb, nest);
	}
	if (nf6) {
		nest = nl_nest_start(&nb, A2TP_ATTR_FILTER_IP6);
		for (i = 0; i < nf6; i++)
			put_filter_entry(&nb, &f6a[i], &f6m[i]);
		nl_nest_end(&nb, nest);
	}

	rc = nl_talk(&sk, &nb, NULL);
	if (rc < 0) {
		logmsg("srv add failed: %s", strerror(-rc));
		if (saved_off)
			offl_load_apply(ifname);
		return 1;
	}
	{
		char bs[80] = "";

		if (bind_s) {
			addr_str(&bind_a, bs, sizeof(bs));
			if (bind_a.family == AF_INET6) {
				char b6[80];

				snprintf(b6, sizeof(b6), "[%s]", bs);
				snprintf(bs, sizeof(bs), "%s", b6);
			}
		}
		logmsg("srv %s up: port %u%s%s%s", ifname, port,
		       bind_s ? " carrier " : "", bs,
		       keep_offloads ? " (offloads untouched)" : "");
	}
	return 0;
}

static int cmd_srv_del(int argc, char **argv)
{
	const char *ifname = NULL;
	int i, rc;
	struct nlsk sk;
	struct nlbuf nb = { .len = 0 };

	for (i = 0; i < argc; i++)
		if (!strcmp(argv[i], "-i") && i + 1 < argc)
			ifname = argv[++i];
	if (!ifname)
		die("srv del: -i <iface> required");

	nl_open(&sk, NETLINK_GENERIC);
	genl_start(&nb, genl_resolve(&sk, A2TP_GENL_NAME), A2TP_CMD_SRV_DEL, 0);
	nl_put_str(&nb, A2TP_ATTR_IFNAME, ifname);
	rc = nl_talk(&sk, &nb, NULL);
	if (rc < 0) {
		logmsg("srv del failed: %s", strerror(-rc));
		return 1;
	}

	/* restore the NIC's offload state saved at add time */
	if (offl_load_apply(ifname) < 0)
		logmsg("srv %s down (no saved offload state to restore)", ifname);
	else
		logmsg("srv %s down; offloads restored", ifname);
	return 0;
}

/* pretty-print one SRV_GET instance message */
static void srv_status_one(struct nlmsghdr *nh)
{
	struct xaddr fa[A2TP_FILTER_MAX], fm[A2TP_FILTER_MAX];
	int nf = 0, i, fam;
	struct walk w;
	const char *ifname = "(?)";
	struct xaddr bind = {}, peer = {};
	char b1[80], b2[80], b3[80];
	uint16_t port = 0, peer_port = 0;
	uint32_t peer_timeout = 0;
	bool fixed = false, known = false;
	uint64_t age = 0;
	uint64_t stats[A2TP_KSTAT_NR] = {};
	bool has_stats = false;

	attr_first(&w, nh, GENL_HDRLEN);
	for (; attr_ok(&w); attr_advance(&w)) {
		switch (w.na->nla_type & NLA_TYPE_MASK) {
		case A2TP_ATTR_IFNAME:
			ifname = (char *)w.na + NLA_HDRLEN;
			break;
		case A2TP_ATTR_PORT:
			port = attr_u16(w.na);
			break;
		case A2TP_ATTR_BIND_IP:
			bind.family = AF_INET;
			bind.v4 = attr_u32(w.na);
			break;
		case A2TP_ATTR_BIND_IP6:
			bind.family = AF_INET6;
			memcpy(bind.v6, (char *)w.na + NLA_HDRLEN, 16);
			break;
		case A2TP_ATTR_PEER_IP:
			peer.family = AF_INET;
			peer.v4 = attr_u32(w.na);
			break;
		case A2TP_ATTR_PEER_IP6:
			peer.family = AF_INET6;
			memcpy(peer.v6, (char *)w.na + NLA_HDRLEN, 16);
			break;
		case A2TP_ATTR_PEER_PORT:
			peer_port = attr_u16(w.na);
			break;
		case A2TP_ATTR_PEER_TIMEOUT:
			peer_timeout = attr_u32(w.na);
			break;
		case A2TP_ATTR_PEER_FIXED:
			fixed = true;
			break;
		case A2TP_ATTR_PEER_KNOWN:
			known = true;
			break;
		case A2TP_ATTR_PEER_AGE_MS:
			age = attr_u64(w.na);
			break;
		case A2TP_ATTR_FILTER_IP:
		case A2TP_ATTR_FILTER_IP6: {
			struct walk fw, ew;
			int t, len;

			fam = (w.na->nla_type & NLA_TYPE_MASK) ==
			      A2TP_ATTR_FILTER_IP ? AF_INET : AF_INET6;
			len = fam == AF_INET ? 4 : 16;
			nest_walk(&fw, w.na);
			for (; attr_ok(&fw) && nf < A2TP_FILTER_MAX;
			     attr_advance(&fw)) {
				memset(&fa[nf], 0, sizeof(fa[nf]));
				memset(&fm[nf], 0, sizeof(fm[nf]));
				fa[nf].family = fm[nf].family = fam;
				nest_walk(&ew, fw.na);
				for (; attr_ok(&ew); attr_advance(&ew)) {
					t = ew.na->nla_type & NLA_TYPE_MASK;
					if (t == A2TP_FILTER_ADDR &&
					    ew.na->nla_len >= NLA_HDRLEN + len)
						memcpy(fam == AF_INET ?
						       (void *)&fa[nf].v4 :
						       fa[nf].v6,
						       (char *)ew.na + NLA_HDRLEN,
						       len);
					else if (t == A2TP_FILTER_MASK &&
						 ew.na->nla_len >= NLA_HDRLEN + len)
						memcpy(fam == AF_INET ?
						       (void *)&fm[nf].v4 :
						       fm[nf].v6,
						       (char *)ew.na + NLA_HDRLEN,
						       len);
				}
				nf++;
			}
			break;
		}
		case A2TP_ATTR_STATS: {
			struct walk sw;
			int idx = 0;

			has_stats = true;
			nest_walk(&sw, w.na);
			for (; attr_ok(&sw) && idx < A2TP_KSTAT_NR; attr_advance(&sw))
				stats[idx++] = attr_u64(sw.na);
			break;
		}
		}
	}

	if (bind.family == AF_UNSPEC)
		snprintf(b1, sizeof(b1), "*");
	else if (bind.family == AF_INET6)
		snprintf(b1, sizeof(b1), "[%s]", addr_str(&bind, b3, sizeof(b3)));
	else
		addr_str(&bind, b1, sizeof(b1));

	printf("srv %s: local %s:%u", ifname, b1, port);
	if (fixed)
		printf("  peer fixed %s", addr_port_str(&peer, peer_port,
							b2, sizeof(b2)));
	else if (known)
		printf("  peer learned %s (age %llums)",
		       addr_port_str(&peer, peer_port, b2, sizeof(b2)),
		       (unsigned long long)age);
	else
		printf("  peer unknown");
	if (peer_timeout)
		printf("  timeout %ums", peer_timeout);
	printf("\n");

	/* one line per family, only when that family has entries */
	for (fam = AF_INET; fam <= AF_INET6; fam++) {
		bool head = false;

		for (i = 0; i < nf; i++) {
			if (fa[i].family != fam)
				continue;
			if (!head) {
				printf("    filter-ip%s:", fam == AF_INET6 ? "6" : "");
				head = true;
			}
			printf(" %s/%s", addr_str(&fa[i], b1, sizeof(b1)),
				addr_str(&fm[i], b2, sizeof(b2)));
		}
		if (head)
			printf("\n");
	}

	if (has_stats) {
		printf("    ");
		for (i = 0; i < A2TP_KSTAT_NR; i++)
			printf("%s=%llu ", a2tp_kstat_name[i],
			       (unsigned long long)stats[i]);
		printf("\n");
	}
}

static int cmd_srv_status(int argc, char **argv)
{
	struct nlsk sk;
	struct nlbuf nb = { .len = 0 };
	char rbuf[8192];
	uint16_t fam;

	(void)argv;
	if (argc)
		die("srv status takes no arguments (lists all instances)");

	nl_open(&sk, NETLINK_GENERIC);
	fam = genl_resolve(&sk, A2TP_GENL_NAME);
	genl_start(&nb, fam, A2TP_CMD_SRV_GET, NLM_F_DUMP);
	{
		struct nlmsghdr *nh = (struct nlmsghdr *)nb.b;

		nh->nlmsg_len = nb.len;
		nh->nlmsg_seq = ++sk.seq;
	}
	if (send(sk.fd, nb.b, nb.len, 0) < 0)
		die("netlink send: %s", strerror(errno));

	for (;;) {
		ssize_t n = recv(sk.fd, rbuf, sizeof(rbuf), 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("netlink recv: %s", strerror(errno));
		}
		struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
		int len = (int)n;

		for (; NLMSG_OK(rh, len); rh = NLMSG_NEXT(rh, len)) {
			if (rh->nlmsg_seq != sk.seq)
				continue;
			if (rh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (rh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(rh);

				die("srv status: %s", strerror(-e->error));
			}
			srv_status_one(rh);
		}
	}
}

/* ---------------- client (rtnl) commands ---------------- */

static int cmd_cli_add(int argc, char **argv)
{
	const char *ifname = NULL, *remote_s = NULL, *local_s = NULL;
	const char *mac_s = NULL;
	uint16_t local_port = 0;
	uint32_t keepalive_ms = 10000, mtu = 0;
	uint8_t mac[6];
	struct xaddr remote = {}, local = {};
	uint16_t remote_port = 0;
	struct nlsk sk;
	struct nlbuf nb = { .len = 0 };
	size_t info, data;
	struct {
		struct nlmsghdr	n;
		struct ifinfomsg	ifi;
	} hdr = { 0 };
	int i, rc;
	char rs[80];

	if (argc < 1)
		die("cli add <name> remote <ip[:port]> [key value..]");
	ifname = argv[0];
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "remote") && i + 1 < argc)
			remote_s = argv[++i];
		else if (!strcmp(argv[i], "local") && i + 1 < argc)
			local_s = argv[++i];
		else if (!strcmp(argv[i], "local-port") && i + 1 < argc)
			local_port = (uint16_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "keepalive-ms") && i + 1 < argc)
			keepalive_ms = (uint32_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "mtu") && i + 1 < argc)
			mtu = (uint32_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "mac") && i + 1 < argc)
			mac_s = argv[++i];
		else
			die("cli add: unknown arg \"%s\"", argv[i]);
	}
	if (!remote_s)
		die("cli add: remote <ip[:port]> required");
	if (parse_addr_port(remote_s, A2TP_UDP_PORT, &remote, &remote_port) < 0)
		die("bad remote \"%s\" (v6 needs brackets: [fd00::1]:1702)",
		    remote_s);
	if (local_s) {
		if (parse_addr(local_s, &local) < 0)
			die("bad local \"%s\"", local_s);
		if (local.family != remote.family)
			die("local \"%s\" family must match the remote", local_s);
	}
	if (mac_s && parse_mac(mac_s, mac) < 0)
		die("bad mac \"%s\"", mac_s);

	hdr.n.nlmsg_type = RTM_NEWLINK;
	hdr.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	hdr.ifi.ifi_family = AF_UNSPEC;
	nl_put(&nb, &hdr, sizeof(hdr));
	nl_put_str(&nb, IFLA_IFNAME, ifname);
	if (mac_s)
		nl_put_attr(&nb, IFLA_ADDRESS, mac, 6);
	if (mtu)
		nl_put_u32(&nb, IFLA_MTU, mtu);

	info = nl_nest_start(&nb, IFLA_LINKINFO);
	nl_put_str(&nb, IFLA_INFO_KIND, A2TP_LINK_KIND);
	data = nl_nest_start(&nb, IFLA_INFO_DATA);
	if (remote.family == AF_INET6) {
		nl_put_attr(&nb, IFLA_A2TP_REMOTE_IP6, remote.v6, 16);
		if (local_s)
			nl_put_attr(&nb, IFLA_A2TP_LOCAL_IP6, local.v6, 16);
	} else {
		nl_put_attr(&nb, IFLA_A2TP_REMOTE_IP, &remote.v4, 4);
		if (local_s)
			nl_put_attr(&nb, IFLA_A2TP_LOCAL_IP, &local.v4, 4);
	}
	nl_put_attr(&nb, IFLA_A2TP_REMOTE_PORT, &remote_port, 2);
	nl_put_u16(&nb, IFLA_A2TP_LOCAL_PORT, local_port);
	nl_put_u32(&nb, IFLA_A2TP_KEEPALIVE_MS, keepalive_ms);
	nl_nest_end(&nb, data);
	nl_nest_end(&nb, info);

	nl_open(&sk, NETLINK_ROUTE);
	rc = nl_talk(&sk, &nb, NULL);
	if (rc < 0) {
		logmsg("cli add failed: %s", strerror(-rc));
		return 1;
	}
	logmsg("cli %s created: remote %s, carrier %s, local port %s -- "
	       "configure and bring it up with ip(8)",
	       ifname, addr_port_str(&remote, remote_port, rs, sizeof(rs)),
	       local_s ? addr_str(&local, rs, sizeof(rs)) : "(routing table)",
	       local_port ? "(fixed)" : "ephemeral");
	return 0;
}

static int cmd_cli_del(int argc, char **argv)
{
	struct ifreq ifr = { 0 };
	struct nlsk sk;
	struct nlbuf nb = { .len = 0 };
	struct {
		struct nlmsghdr	n;
		struct ifinfomsg	ifi;
	} hdr = { 0 };
	int s, rc;

	if (argc < 1)
		die("cli del <name>");
	strncpy(ifr.ifr_name, argv[0], IFNAMSIZ - 1);
	s = ctl_socket();
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
		die("no interface \"%s\"", argv[0]);

	hdr.n.nlmsg_type = RTM_DELLINK;
	hdr.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr.ifi.ifi_family = AF_UNSPEC;
	hdr.ifi.ifi_index = ifr.ifr_ifindex;
	nl_put(&nb, &hdr, sizeof(hdr));

	nl_open(&sk, NETLINK_ROUTE);
	rc = nl_talk(&sk, &nb, NULL);
	if (rc < 0) {
		logmsg("cli del failed: %s", strerror(-rc));
		return 1;
	}
	logmsg("cli %s down", argv[0]);
	return 0;
}

/* ---------------- main ---------------- */

static void usage(void)
{
	fprintf(stderr,
"usage: a2tpctl <command> [args]          (needs the a2tp kernel module)\n"
"\n"
"  srv add -i <iface> [-p <port>] [-b <carrier ip>]\n"
"          [--peer <ip:port>] [--peer-timeout <sec>]\n"
"          [--filter-ip <a[/m][,a[/m]..]>] [--filter-ip6 <a[/m]..>]\n"
"          [--no-self-filter] [--keep-offloads]\n"
"        filter m: prefix len (10.0.0.0/24, fd00::/64) or address-style\n"
"        mask (10.0.0.0/255.255.255.0, fd00::/ffff:ffff::); bare = exact;\n"
"        pure mask match, families independent\n"
"  srv del -i <iface>\n"
"  srv status\n"
"  cli add <name> remote <ip[:port]> [local <carrier ip>]\n"
"          [local-port <n>] [keepalive-ms <n>] [mtu <n>]\n"
"          [mac <aa:bb:cc:dd:ee:ff>]\n"
"  cli del <name>\n"
"\n"
"v6 endpoints with a port need brackets: [fd00::1]:1702\n"
"without -b/local the outer source follows the routing table; the tunnel\n"
"survives carrier/route outages and resumes on its own\n");
	exit(2);
}

int main(int argc, char **argv)
{
	if (argc < 3)
		usage();
	if (!strcmp(argv[1], "srv")) {
		if (!strcmp(argv[2], "add"))
			return cmd_srv_add(argc - 3, argv + 3);
		if (!strcmp(argv[2], "del"))
			return cmd_srv_del(argc - 3, argv + 3);
		if (!strcmp(argv[2], "status"))
			return cmd_srv_status(argc - 3, argv + 3);
	} else if (!strcmp(argv[1], "cli")) {
		if (!strcmp(argv[2], "add"))
			return cmd_cli_add(argc - 3, argv + 3);
		if (!strcmp(argv[2], "del"))
			return cmd_cli_del(argc - 3, argv + 3);
	}
	usage();
	return 2;
}
