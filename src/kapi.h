/*
 * kapi.h - kernel-module control-plane ABI, shared by kernel/a2tp*.c and
 * src/a2tpctl.c.  Userspace-safe: no kernel includes.
 *
 *   server side: generic-netlink family "a2tp" (no netdev of its own, so
 *                rtnetlink does not apply -- same choice net/l2tp made)
 *   client side: rtnetlink link kind "a2tp" (attrs ride inside
 *                IFLA_LINKINFO/IFLA_INFO_DATA; one day iproute2 can grow a
 *                link_a2tp.c that speaks these same attrs)
 */
#ifndef A2TP_KAPI_H
#define A2TP_KAPI_H

/* genl */
#define A2TP_GENL_NAME		"a2tp"
#define A2TP_GENL_VERSION	1

enum {
	A2TP_CMD_UNSPEC,
	A2TP_CMD_SRV_ADD,	/* -> one A2TP_CMD_SRV_* reply (the new instance) */
	A2TP_CMD_SRV_DEL,	/* -> reply 0 */
	A2TP_CMD_SRV_GET,	/* dump: one reply per server instance */
	__A2TP_CMD_MAX,
};
#define A2TP_CMD_MAX (__A2TP_CMD_MAX - 1)

enum {
	A2TP_ATTR_UNSPEC,
	A2TP_ATTR_IFNAME,	/* string */
	A2TP_ATTR_PORT,		/* u16, local UDP port (host order) */
	A2TP_ATTR_BIND_IP,	/* u32 (network order), v4 bind (with
				 * BIND_IP6 absent: v4 wildcard) */
	A2TP_ATTR_BIND_IP6,	/* in6_addr (16B network order), v6 bind */
	A2TP_ATTR_PEER_IP,	/* u32 (network order) */
	A2TP_ATTR_PEER_IP6,	/* in6_addr (16B network order) */
	A2TP_ATTR_PEER_PORT,	/* u16 (network order) */
	A2TP_ATTR_PEER_FIXED,	/* flag: --peer given, learn nothing */
	A2TP_ATTR_PEER_TIMEOUT,	/* u32, ms (0 = never expires) */
	A2TP_ATTR_PEER_KNOWN,	/* flag (reply): a peer was learned */
	A2TP_ATTR_PEER_AGE_MS,	/* u64 (reply): ms since last peer packet */
	A2TP_ATTR_NO_SELF_FILTER,/* flag: do not filter the tunnel's own UDP */
	A2TP_ATTR_FILTER_IP,	/* nested array, each entry nested:
				 * { FILTER_ADDR u32, FILTER_MASK u32 } */
	A2TP_ATTR_FILTER_IP6,	/* nested array, each entry nested:
				 * { FILTER_ADDR in6, FILTER_MASK in6 } */
	A2TP_ATTR_STATS,	/* nested: u64 list, enum a2tp_stat order
				 * (kept in sync with kernel/a2tp.h) */
	A2TP_ATTR_ERRMSG,	/* string: kernel-side error detail */
	A2TP_ATTR_PAD,		/* padding for 64-bit attrs, never used */
	__A2TP_ATTR_MAX,
};
#define A2TP_ATTR_MAX (__A2TP_ATTR_MAX - 1)

/* one --filter-ip / --filter-ip6 entry is an (address, netmask) pair; a frame
 * matches when (dst & mask) == (addr & mask).  A bare address means an
 * all-ones mask (exact match).  The mask may be written as an address-style
 * mask (255.255.255.0, ffff:ffff::) or as a prefix length (10.0.0.0/24,
 * fd00::/64).  addr is stored pre-masked (host bits cleared).  Pure mask
 * semantics on the kernel side: no address/network distinction, no
 * contiguity requirement.  Max combined entries per server instance: */
#define A2TP_FILTER_MAX		32

enum {
	A2TP_FILTER_UNSPEC,
	A2TP_FILTER_ADDR,
	A2TP_FILTER_MASK,
	__A2TP_FILTER_MAX,
};

/* per-stat order, shared by the kernel counters and a2tpctl's display;
 * each side defines a2tp_kstat_name[] in this order */
enum a2tp_kstat {
	A2TP_KSTAT_MIRROR,
	A2TP_KSTAT_INJECT,
	A2TP_KSTAT_TX_ERR,
	A2TP_KSTAT_RX_DATA,
	A2TP_KSTAT_RX_KA,
	A2TP_KSTAT_RX_BAD,
	A2TP_KSTAT_PASS_FILTER,
	A2TP_KSTAT_PASS_SELF,
	A2TP_KSTAT_PASS_NO_PEER,
	A2TP_KSTAT_PASS_GSO,
	A2TP_KSTAT_PASS_MTU,
	A2TP_KSTAT_PEER_PINNED,
	A2TP_KSTAT_KEEPALIVE,
	A2TP_KSTAT_NR,
};

extern const char *const a2tp_kstat_name[A2TP_KSTAT_NR];

/* rtnl link kind + IFLA_INFO_DATA attrs */
#define A2TP_LINK_KIND		"a2tp"

enum {
	IFLA_A2TP_UNSPEC,
	IFLA_A2TP_REMOTE_IP,	/* u32 (network order); exactly one of
				 * REMOTE_IP / REMOTE_IP6 is required */
	IFLA_A2TP_REMOTE_IP6,	/* in6_addr (16B network order) */
	IFLA_A2TP_REMOTE_PORT,	/* u16 (network order), default A2TP_UDP_PORT */
	IFLA_A2TP_LOCAL_PORT,	/* u16 (host order), 0 = ephemeral */
	IFLA_A2TP_LOCAL_IP,	/* u32: pin the carrier (source address).
				 * Absent = source follows the routing table
				 * (default-route following).  Family must
				 * match the remote. */
	IFLA_A2TP_LOCAL_IP6,	/* in6_addr: same, v6 */
	IFLA_A2TP_KEEPALIVE_MS,	/* u32, 0 = disabled */
	__IFLA_A2TP_MAX,
};
#define IFLA_A2TP_MAX (__IFLA_A2TP_MAX - 1)

#endif /* A2TP_KAPI_H */
