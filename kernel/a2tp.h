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
 * Both directions transmit through ip_local_out() with a flow-based route
 * lookup (ip_route_output_flow), so outer packets get the full policy
 * stack: kernel IPsec (ip xfrm policy/state, ESP transport) applies to the
 * outer UDP transparently, policy routing can steer them into a WireGuard
 * interface, and IP fragmentation (DF=0) works like the userspace
 * IP_PMTUDISC_DONT.
 */

#ifndef __A2TP_H
#define __A2TP_H

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "../src/proto.h"	/* wire format constants, shared with userspace */
#include "../src/kapi.h"	/* control-plane ABI, shared with a2tpctl */

#define A2TP_IF_PREFIX		"a2tp"
#define A2TP_FILTER_IP_MAX	32

/* learned/roaming peer, written from softirq on every received datagram */
struct a2tp_peer {
	__be32			ip;	/* network order */
	__be16			port;	/* network order */
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
	struct socket		*sock;	/* kernel UDP socket, encap bound */

	/* configuration, immutable after creation */
	u16			local_port;	/* host order */
	__be32			bind_ip;	/* 0 = INADDR_ANY */
	bool			self_filter;
	u32			peer_timeout_ms;
	bool			peer_fixed;
	struct a2tp_peer	peer;	/* fixed peer when peer_fixed */
	__be32			filter_ip[A2TP_FILTER_IP_MAX];
	int			filter_n;

	bool			was_promisc;	/* restore on teardown */

	/* learned peer (when !peer_fixed): ip+port packed into one atomic
	 * word, refreshed from softirq on every received datagram -- the
	 * same lock-free pattern as the userspace tools (sockaddr_key);
	 * parallel UDP RX on several CPUs makes a seqcount unusable here */
	atomic64_t		learned;	/* 0 = unknown */
	atomic64_t		peer_last_ms;	/* ktime_get_boottime_ms() */

	struct a2tp_stats __percpu *stats;
};

/* client instance, via netdev_priv() of the rtnl_link netdev */
struct a2tp_cli {
	struct net		*net;
	struct net_device	*dev;	/* ourselves */
	struct socket		*sock;	/* kernel UDP socket, encap bound */

	u16			local_port;	/* host order */
	struct a2tp_peer	remote;		/* configured server endpoint */
	u32			keepalive_ms;
	struct timer_list	ka_timer;
	bool			ka_on;		/* ndo_open sets, ndo_stop clears */

	/* learned server endpoint (roaming), packed like a2tp_srv::learned */
	atomic64_t		learned;	/* 0 = unknown */

	struct a2tp_stats __percpu *stats;
};

/* a2tp_core.c */
int a2tp_sock_open(struct net *net, __be32 bind_ip, u16 local_port,
		   int (*encap_rcv)(struct sock *sk, struct sk_buff *skb),
		   void *priv, struct socket **sockp);
void a2tp_sock_close(struct socket *sock);
/* send skb (type byte + ethernet frame, already pushed) to peer; consumes
 * skb, returns false when routing/transmit failed */
bool a2tp_xmit(struct socket *sock, struct sk_buff *skb,
	       const struct a2tp_peer *peer);
/* tiny 1-byte keepalive datagram */
void a2tp_send_keepalive(struct socket *sock, const struct a2tp_peer *peer);

/* VLAN-unwrapped ethertype of a frame given its mac header, 0 if too short */
__be16 a2tp_frame_ethertype(const struct sk_buff *skb);
/* IPv4 dst of an Eth[+VLAN]+IPv4 frame (mac-header based), 0 when absent */
__be32 a2tp_frame_ipv4_dst(const struct sk_buff *skb);
/* true when the frame is IPv4/UDP matching the tunnel's own 5-tuple */
bool a2tp_frame_is_tunnel_l4(const struct sk_buff *skb, u16 local_port,
			     __be32 peer_ip, __be16 peer_port);
/* mirror filter with --filter-ip semantics (ARP always passes) */
bool a2tp_mirror_filter(const struct a2tp_srv *srv, struct sk_buff *skb);

/* peer helpers */
static inline bool a2tp_peer_eq(const struct a2tp_peer *a,
				const struct a2tp_peer *b)
{
	return a->ip == b->ip && a->port == b->port;
}
bool a2tp_peer_expired(const struct a2tp_srv *srv);

void a2tp_srv_peer_update(struct a2tp_srv *srv, const struct a2tp_peer *p);
bool a2tp_srv_peer_get(struct a2tp_srv *srv, struct a2tp_peer *out);
u64 a2tp_srv_peer_last_ms(const struct a2tp_srv *srv);
void a2tp_cli_peer_update(struct a2tp_cli *cli, const struct a2tp_peer *p);
bool a2tp_cli_peer_get(struct a2tp_cli *cli, struct a2tp_peer *out);

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
