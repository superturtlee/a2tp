/* SPDX-License-Identifier: GPL-2.0 */
/* a2tp.h - internal shared definitions of the a2tp kernel module
 *
 * a2tp ("another layer2 transport") moves the data plane of the userspace
 * a2tp-srv/a2tp-cli tools into the kernel, following the shape of the
 * in-tree L2TPv3-over-UDP pseudowire (net/l2tp) code:
 *
 *   server side: no netdev of its own.  An rx_handler (the same hook the
 *     bridge uses) is installed on the taken-over NIC; matching frames are
 *     cloned, prefixed with the a2tp type byte and sent to the peer over a
 *     kernel UDP socket.  The frame itself continues up the stack
 *     (RX_HANDLER_PASS): the mirror is a passive tap, like AF_PACKET.
 *     Frames arriving from the peer are decapsulated and injected onto the
 *     NIC with dev_queue_xmit(), like an AF_PACKET raw send.
 *
 *   client side: a rtnl_link netdev (l2tp_eth style).  ndo_start_xmit
 *     prefixes the type byte and sends over the kernel UDP socket; received
 *     datagrams are decapsulated and pushed up the stack via
 *     dev_forward_skb(), which is the tap-write equivalent.
 *
 * Both families are carried: the server opens one v4 and one v6-only socket
 * unless -b pinned a single family, and the client follows the family of its
 * configured server address.
 *
 * Both directions transmit through ip_local_out() with a per-datagram,
 * flow-based route lookup (ip_route_output_flow / ipv6_dst_lookup_flow), so
 * outer packets get the full policy stack: kernel IPsec (ip xfrm
 * policy/state, ESP transport) applies to the outer UDP transparently,
 * policy routing can steer them into a WireGuard interface, and IP
 * fragmentation (DF=0) works like the userspace IP_PMTUDISC_DONT.
 *
 * The tunnel is deliberately decoupled from the lifetime of its underlay:
 * no route is ever cached and no socket is ever connected, so a vanished
 * carrier address, a down NIC or a gone default route simply makes each
 * transmit fail (counted as tx_err) while the instance lives on, waiting;
 * the next datagram after the underlay returns just routes again.  A
 * configured local address (-b on the server, "local" on the client)
 * additionally pins the outer source: while that address is absent from
 * the host, the per-packet lookup fails on the invalid source and nothing
 * is sent -- the same wait-and-resume, but scoped to that carrier.
 */

#ifndef __A2TP_H
#define __A2TP_H

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/in6.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "../src/proto.h"	/* wire format constants, shared with userspace */
#include "../src/kapi.h"	/* control-plane ABI, shared with a2tpctl */

#define A2TP_IF_PREFIX		"a2tp"	/* A2TP_FILTER_MAX lives in kapi.h */

/* dual-family address: a value plus the family that interprets it.
 * AF_UNSPEC means "not present" (no carrier pinned, no peer known). */
struct a2tp_addr {
	sa_family_t		family;
	union {
		__be32		v4;	/* network order */
		struct in6_addr	v6;
	};
};

/* learned/roaming peer endpoint, written from softirq on every received
 * datagram */
struct a2tp_peer {
	struct a2tp_addr		a;
	__be16				port;	/* network order */
};

/* one --filter-ip / --filter-ip6 rule.  Pure mask semantics, on purpose:
 * (dst & mask) == addr, with addr stored pre-masked.  The kernel never
 * interprets the mask (no prefix-length math, no contiguity check,
 * no address-vs-network distinction) -- 255.255.255.255 is an exact-host
 * rule, 0.0.0.0 matches everything and a discontiguous mask simply works
 * bitwise.  Only the family is distinguished: a v4 rule never matches an
 * IPv6 frame and vice versa. */
struct a2tp_filter {
	struct a2tp_addr		addr;
	struct a2tp_addr		mask;
};

/* peer state under a spinlock: v4+v6+port no longer packs into one atomic
 * word the way the userspace sockaddr_key trick did, so the refresh from
 * softirq takes the lock instead (softirq writers/readers use plain
 * spin_lock, process context uses the _bh variant) */
struct a2tp_peer_state {
	spinlock_t		lock;
	struct a2tp_peer	peer;
	bool			valid;
};

/* the underlay endpoint: one encap socket per family plus the pinned local
 * source address ("carrier"), when one was configured.  local.family
 * AF_UNSPEC = let routing pick the source per packet (default route
 * following). */
struct a2tp_ep {
	struct socket		*sock4;		/* v4 encap socket, or NULL */
	struct socket		*sock6;		/* v6-only encap socket, or NULL */
	struct a2tp_addr	local;
};

/* counters indexed by enum a2tp_kstat (kapi.h): the order is wire ABI,
 * shared with a2tpctl's display */
struct a2tp_stats {
	u64			cnt[A2TP_KSTAT_NR];
};

/* server instance: one taken-over NIC (no netdev of its own) */
struct a2tp_srv {
	struct list_head	list;	/* member of the per-netns list */
	struct net		*net;
	struct net_device	*dev;	/* taken-over NIC, refcounted */
	struct a2tp_ep		ep;

	/* configuration, immutable after creation */
	u16			local_port;	/* host order */
	bool			self_filter;
	u32			peer_timeout_ms;
	bool			peer_fixed;
	struct a2tp_peer	peer;	/* fixed peer when peer_fixed */
	struct a2tp_filter	filter[A2TP_FILTER_MAX];
	int			filter_n;

	bool			was_promisc;	/* restore on teardown */

	/* learned peer (when !peer_fixed), refreshed from softirq */
	struct a2tp_peer_state	learned;
	atomic64_t		peer_last_ms;	/* ktime_get_boottime_ms() */

	struct a2tp_stats __percpu *stats;
};

/* client instance, via netdev_priv() of the rtnl_link netdev */
struct a2tp_cli {
	struct net		*net;
	struct net_device	*dev;	/* ourselves */
	struct a2tp_ep		ep;

	u16			local_port;
	struct a2tp_peer	remote;		/* configured server endpoint */
	u32			keepalive_ms;
	struct timer_list	ka_timer;
	bool			ka_on;		/* ndo_open sets, ndo_stop clears */

	/* learned server endpoint (roaming) */
	struct a2tp_peer_state	learned;

	struct a2tp_stats __percpu *stats;
};

/* ---------------- address helpers ---------------- */

static inline bool a2tp_addr_eq(const struct a2tp_addr *a,
				const struct a2tp_addr *b)
{
	if (a->family != b->family)
		return false;
	if (a->family == AF_INET)
		return a->v4 == b->v4;
	return !memcmp(&a->v6, &b->v6, sizeof(a->v6));
}

/* dst = a & b, family taken from a */
static inline void a2tp_addr_and(struct a2tp_addr *d,
				 const struct a2tp_addr *a,
				 const struct a2tp_addr *b)
{
	int i;

	d->family = a->family;
	if (a->family == AF_INET) {
		d->v4 = a->v4 & b->v4;
		return;
	}
	for (i = 0; i < 4; i++)
		((__be32 *)&d->v6)[i] = ((const __be32 *)&a->v6)[i] &
					((const __be32 *)&b->v6)[i];
}

/* ---------------- peer state ---------------- */

static inline bool a2tp_peer_eq(const struct a2tp_peer *a,
				const struct a2tp_peer *b)
{
	return a->port == b->port && a2tp_addr_eq(&a->a, &b->a);
}

/* refresh from softirq (encap_rcv) */
static inline void a2tp_peer_update(struct a2tp_peer_state *ps,
				    const struct a2tp_peer *p)
{
	spin_lock(&ps->lock);
	ps->peer = *p;
	ps->valid = true;
	spin_unlock(&ps->lock);
}

/* read from softirq (rx_handler, keepalive timer) */
static inline bool a2tp_peer_get(struct a2tp_peer_state *ps,
				 struct a2tp_peer *out)
{
	bool valid;

	spin_lock(&ps->lock);
	valid = ps->valid;
	if (valid)
		*out = ps->peer;
	spin_unlock(&ps->lock);
	return valid;
}

/* read from process context (genl status dump) */
static inline bool a2tp_peer_get_proc(struct a2tp_peer_state *ps,
				      struct a2tp_peer *out)
{
	bool valid;

	spin_lock_bh(&ps->lock);
	valid = ps->valid;
	if (valid)
		*out = ps->peer;
	spin_unlock_bh(&ps->lock);
	return valid;
}

/* ---------------- a2tp_core.c ---------------- */

/* open @ep: one socket per requested family, bound to @local (NULL =
 * wildcard); the pinned local address also becomes the transmit source */
int a2tp_ep_open(struct net *net, const struct a2tp_addr *local,
		 bool open_v4, bool open_v6, u16 local_port,
		 int (*encap_rcv)(struct sock *sk, struct sk_buff *skb),
		 void *priv, struct a2tp_ep *ep);
void a2tp_ep_close(struct a2tp_ep *ep);

/* send skb (type byte + ethernet frame, already pushed) to @peer; consumes
 * skb, returns false when routing/transmit failed (e.g. the carrier or the
 * route is temporarily gone -- the instance survives either way) */
bool a2tp_xmit(const struct a2tp_ep *ep, struct sk_buff *skb,
	       const struct a2tp_peer *peer);
/* tiny 1-byte keepalive datagram */
void a2tp_send_keepalive(const struct a2tp_ep *ep, const struct a2tp_peer *peer);

/* VLAN-unwrapped ethertype of a frame given its mac header, 0 if too short */
__be16 a2tp_frame_ethertype(const struct sk_buff *skb);
/* IPv4 dst of an Eth[+VLAN]+IPv4 frame (mac-header based), 0 when absent */
__be32 a2tp_frame_ipv4_dst(const struct sk_buff *skb);
/* IPv6 dst of an Eth[+VLAN]+IPv6 frame; false when the frame is not IPv6 */
bool a2tp_frame_ipv6_dst(const struct sk_buff *skb, struct in6_addr *dst);
/* true when the frame is IPv4/IPv6 + UDP matching the tunnel's own 5-tuple
 * (peer->a.family AF_UNSPEC: match on ports only) */
bool a2tp_frame_is_tunnel_l4(const struct sk_buff *skb, u16 local_port,
			     const struct a2tp_peer *peer);
/* mirror filter with --filter-ip/--filter-ip6 semantics: pure mask match
 * per family; ARP and IPv6 Neighbor Discovery always pass (the client
 * answers its own addresses) */
bool a2tp_mirror_filter(const struct a2tp_srv *srv, struct sk_buff *skb);

/* peer helpers */
bool a2tp_peer_expired(const struct a2tp_srv *srv);
void a2tp_srv_peer_learn(struct a2tp_srv *srv, const struct a2tp_peer *p);
/* fill @src from the outer headers of an encap-received skb (the family
 * comes from the IP version nibble, so one callback serves both sockets) */
void a2tp_skb_src_peer(struct sk_buff *skb, struct a2tp_peer *src);

/* stats */
static inline void a2tp_stat(struct a2tp_stats __percpu *stats,
			     enum a2tp_kstat st)
{
	this_cpu_inc(stats->cnt[st]);
}
u64 a2tp_stat_sum(const struct a2tp_stats __percpu *stats, enum a2tp_kstat st);

/* a2tp_netdev.c (client) */
extern struct rtnl_link_ops a2tp_link_ops;

/* a2tp_srv.c (server pump + genl control) */
int a2tp_srv_init(void);
void a2tp_srv_exit(void);
int a2tp_srv_pernet_init(struct net *net);
void a2tp_srv_pernet_exit(struct net *net);
struct a2tp_srv *a2tp_srv_find(struct net *net, const char *ifname);
void a2tp_srv_destroy(struct a2tp_srv *srv, bool restore_promisc);
extern struct pernet_operations a2tp_pernet_ops;

#endif /* __A2TP_H */
