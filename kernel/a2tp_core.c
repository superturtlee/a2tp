// SPDX-License-Identifier: GPL-2.0
/* a2tp_core.c - kernel UDP sockets, transmit path, frame parsing, peer state
 *
 * The transmit path mirrors what the userspace tools got for free from a
 * plain UDP socket: source address chosen by the routing layer, IP
 * fragmentation allowed (DF=0, the equivalent of IP_PMTUDISC_DONT), and the
 * full policy stack consulted on the outer header.  Routing goes through
 * ip_route_output_key() == ip_route_output_flow() / the ipv6 stub's
 * ipv6_dst_lookup_flow() with the proto set, so XFRM policy lookup runs on
 * every packet: `ip xfrm policy/state` (kernel IPsec, ESP transport) stacks
 * on the outer UDP exactly like it does for geneve/vxlan, and policy routing
 * (`ip rule`) can steer the outer packets into a WireGuard interface.  This
 * is the same shape as the vxlan/l2tp kernel tunnels.
 *
 * Nothing on this path is ever cached: no route, no connected peer, no
 * address.  A vanished carrier address, a gone default route or a down NIC
 * just fails the per-datagram lookup (counted as tx_err by the callers)
 * while the instance lives on; the first datagram after the underlay
 * returns routes again.  A pinned local address additionally forces the
 * outer source, so its absence fails the lookup on the invalid source --
 * wait-and-resume scoped to that carrier.
 */

#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <net/udp_tunnel.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ipv6_stubs.h>
#include <net/ndisc.h>
#include <net/net_namespace.h>

#include "a2tp.h"

/* order shared with a2tpctl's copy (kapi.h: a2tp_kstat_name) */
const char * const a2tp_kstat_name[A2TP_KSTAT_NR] = {
	[A2TP_KSTAT_MIRROR]	= "mirror",
	[A2TP_KSTAT_INJECT]	= "inject",
	[A2TP_KSTAT_TX_ERR]	= "tx_err",
	[A2TP_KSTAT_RX_DATA]	= "rx_data",
	[A2TP_KSTAT_RX_KA]	= "rx_ka",
	[A2TP_KSTAT_RX_BAD]	= "rx_bad",
	[A2TP_KSTAT_PASS_FILTER] = "pass_filter",
	[A2TP_KSTAT_PASS_SELF]	= "pass_self",
	[A2TP_KSTAT_PASS_NO_PEER] = "pass_no_peer",
	[A2TP_KSTAT_PASS_GSO]	= "pass_gso",
	[A2TP_KSTAT_PASS_MTU]	= "pass_mtu",
	[A2TP_KSTAT_PEER_PINNED] = "peer_pinned_drop",
	[A2TP_KSTAT_KEEPALIVE]	= "keepalive",
};

/* ---------------- kernel UDP sockets with encap ---------------- */

static void a2tp_sock_setup(struct net *net, struct socket *sock,
			    int (*encap_rcv)(struct sock *sk,
					     struct sk_buff *skb),
			    void *priv)
{
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data	= priv,
		.encap_type	= UDP_ENCAP_L2TPINUDP,
		.encap_rcv	= encap_rcv,
	};

	/* the userspace udp_bind() asked for 4 MB both ways; kernel sockets
	 * assign buffers directly (no rmem_max clamp) */
	sock->sk->sk_rcvbuf = 4 << 20;
	sock->sk->sk_sndbuf = 4 << 20;

	setup_udp_tunnel_sock(net, sock, &cfg);
}

/* open @ep: one socket per requested family, bound to @local (NULL =
 * wildcard); @local, when given, also becomes the pinned transmit source */
int a2tp_ep_open(struct net *net, const struct a2tp_addr *local,
		 bool open_v4, bool open_v6, u16 local_port,
		 int (*encap_rcv)(struct sock *sk, struct sk_buff *skb),
		 void *priv, struct a2tp_ep *ep)
{
	struct socket *sock;
	int err;

	memset(ep, 0, sizeof(*ep));
	if (local)
		ep->local = *local;

	if (open_v4) {
		struct udp_port_cfg pc = {
			.family			= AF_INET,
			.local_ip.s_addr	= (local && local->family == AF_INET) ?
						  local->v4 : 0,
			.local_udp_port		= htons(local_port),
			/* no peer_udp_port: the socket stays unconnected so
			 * the endpoint can roam (NAT rebind) and be set per
			 * packet */
		};

		err = udp_sock_create4(net, &pc, &sock);
		if (err)
			return err;
		a2tp_sock_setup(net, sock, encap_rcv, priv);
		ep->sock4 = sock;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (open_v6) {
		struct udp_port_cfg pc = {
			.family			= AF_INET6,
			.local_udp_port		= htons(local_port),
			/* v6-only: keeps the same port free for the v4 socket
			 * when both families are open */
			.ipv6_v6only		= 1,
		};

		if (local && local->family == AF_INET6)
			pc.local_ip6 = local->v6;
		err = udp_sock_create6(net, &pc, &sock);
		if (err) {
			a2tp_ep_close(ep);
			return err;
		}
		a2tp_sock_setup(net, sock, encap_rcv, priv);
		ep->sock6 = sock;
	}
#endif

	if (!ep->sock4 && !ep->sock6)
		return -EAFNOSUPPORT;	/* v6 on a !IPV6 kernel, or no family */
	return 0;
}

void a2tp_ep_close(struct a2tp_ep *ep)
{
	bool wait = false;

	/* clear sk_user_data before release so a concurrent encap callback
	 * does not dereference a freed instance (udp_tunnel_sock_release
	 * does not wait for readers) */
	if (ep->sock4) {
		rcu_assign_sk_user_data(ep->sock4->sk, NULL);
		wait = true;
	}
	if (ep->sock6) {
		rcu_assign_sk_user_data(ep->sock6->sk, NULL);
		wait = true;
	}
	if (wait)
		synchronize_net();
	if (ep->sock4) {
		udp_tunnel_sock_release(ep->sock4);
		ep->sock4 = NULL;
	}
	if (ep->sock6) {
		udp_tunnel_sock_release(ep->sock6);
		ep->sock6 = NULL;
	}
}

/* ---------------- transmit ---------------- */

static bool a2tp_xmit4(const struct a2tp_ep *ep, struct sk_buff *skb,
		       const struct a2tp_peer *peer)
{
	struct sock *sk = ep->sock4->sk;
	struct flowi4 fl4 = {
		.flowi4_proto		= IPPROTO_UDP,
		.daddr			= peer->a.v4,
		.fl4_sport		= inet_sk(sk)->inet_sport,
		.fl4_dport		= peer->port,
	};
	struct rtable *rt;

	/* a pinned carrier is also the source: while that address is not on
	 * the host, the lookup fails and the datagram waits */
	if (ep->local.family == AF_INET)
		fl4.saddr = ep->local.v4;

	/* headroom for the UDP + IP headers we are about to push, plus
	 * whatever the underlay route needs (e.g. a wg0 or ipsec dst) */
	if (skb_cow_head(skb, LL_MAX_HEADER))
		goto drop;

	rt = ip_route_output_key(sock_net(sk), &fl4);
	if (IS_ERR(rt))
		goto drop;

	/* fl4.saddr now holds the source the routing layer picked (same
	 * handoff udp_tunnel_dst_lookup() does for vxlan); df=0: fragment
	 * instead of failing, like IP_PMTUDISC_DONT; nocheck: the userspace
	 * sender never checksummed UDP either */
	udp_tunnel_xmit_skb(rt, sk, skb, fl4.saddr, peer->a.v4,
			    0 /* tos */,
			    sock_net(sk)->ipv4.sysctl_ip_default_ttl,
			    0 /* df */, fl4.fl4_sport, fl4.fl4_dport,
			    false, true, 0);
	return true;

drop:
	kfree_skb(skb);
	return false;
}

#if IS_ENABLED(CONFIG_IPV6)
static bool a2tp_xmit6(const struct a2tp_ep *ep, struct sk_buff *skb,
		       const struct a2tp_peer *peer)
{
	struct sock *sk = ep->sock6->sk;
	struct dst_entry *dst;
	struct flowi6 fl6 = {
		.flowi6_proto		= IPPROTO_UDP,
		.daddr			= peer->a.v6,
		.fl6_sport		= inet_sk(sk)->inet_sport,
		.fl6_dport		= peer->port,
	};

	if (ep->local.family == AF_INET6)
		fl6.saddr = ep->local.v6;	/* pinned carrier, as above */

	if (skb_cow_head(skb, LL_MAX_HEADER))
		goto drop;

	/* the wireguard/vxlan shape for in-tree tunnels that may be built
	 * without ipv6: per-packet, xfrm-aware lookup through the stub; NULL
	 * when ipv6 is a module that is not loaded */
	if (!ipv6_stub->ipv6_dst_lookup_flow)
		goto drop;
	dst = ipv6_stub->ipv6_dst_lookup_flow(sock_net(sk), sk, &fl6, NULL);
	if (IS_ERR(dst))
		goto drop;

	/* consumes skb and dst; NULL dev is fine (ip6tunnel_xmit only uses
	 * it for stats), nocheck matches the v4 path */
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &fl6.saddr, &peer->a.v6,
			     0 /* prio */, ip6_dst_hoplimit(dst),
			     0 /* label */, fl6.fl6_sport, fl6.fl6_dport,
			     true, 0);
	return true;

drop:
	kfree_skb(skb);
	return false;
}
#endif	/* CONFIG_IPV6 */

/* Send one a2tp datagram (skb->data at the type byte, payload = one
 * complete ethernet frame) to @peer.  Consumes skb on all paths, returns
 * false when it could not be sent (route gone, carrier gone).  Safe from
 * softirq (rx_handler, ndo_start_xmit, timer callbacks).
 */
bool a2tp_xmit(const struct a2tp_ep *ep, struct sk_buff *skb,
	       const struct a2tp_peer *peer)
{
	if (peer->a.family == AF_INET6) {
#if IS_ENABLED(CONFIG_IPV6)
		if (ep->sock6)
			return a2tp_xmit6(ep, skb, peer);
#endif
	} else if (ep->sock4) {
		return a2tp_xmit4(ep, skb, peer);
	}
	kfree_skb(skb);
	return false;
}

void a2tp_send_keepalive(const struct a2tp_ep *ep, const struct a2tp_peer *peer)
{
	struct sk_buff *skb;

	skb = alloc_skb(LL_MAX_HEADER + HDR_LEN, GFP_ATOMIC);
	if (!skb)
		return;
	*(u8 *)skb_put(skb, HDR_LEN) = A2TP_TYPE_KEEPALIVE;
	a2tp_xmit(ep, skb, peer);
}

/* ---------------- frame parsing (mac_header based) ---------------- *
 * The rx_handler sees frames after eth_type_trans(): skb->data is at the
 * L3 header but skb_mac_header() still points at the ethernet header, so
 * the userspace frame_* helpers translate to mac-header-based walks here.
 */

/* offset of the L3 header from the mac header + unwrapped ethertype */
static int a2tp_l3_off(const struct sk_buff *skb, __be16 *et_out)
{
	const u8 *mac = skb_mac_header(skb);
	unsigned int len = skb->len + (skb->data - skb_mac_header(skb));
	unsigned int off = ETH_HLEN;
	__be16 et;

	if (len < ETH_HLEN)
		return -1;
	et = get_unaligned((__be16 *)(mac + 12));
	/* bounded VLAN walk (802.1Q, 802.1ad), same set as userspace */
	while ((et == htons(ETH_P_8021Q) || et == htons(ETH_P_8021AD)) &&
	       len >= off + VLAN_HLEN) {
		et = get_unaligned((__be16 *)(mac + off + 2));
		off += VLAN_HLEN;
	}
	*et_out = et;
	return off;
}

__be16 a2tp_frame_ethertype(const struct sk_buff *skb)
{
	__be16 et = 0;

	a2tp_l3_off(skb, &et);
	return et;
}

__be32 a2tp_frame_ipv4_dst(const struct sk_buff *skb)
{
	const u8 *mac = skb_mac_header(skb);
	unsigned int flen = skb->len + (skb->data - skb_mac_header(skb));
	__be16 et;
	int off = a2tp_l3_off(skb, &et);
	const struct iphdr *iph;

	if (off < 0 || et != htons(ETH_P_IP))
		return 0;
	if (flen < (unsigned int)off + sizeof(struct iphdr))
		return 0;
	iph = (const struct iphdr *)(mac + off);
	if (iph->ihl < 5)
		return 0;
	return iph->daddr;
}

bool a2tp_frame_ipv6_dst(const struct sk_buff *skb, struct in6_addr *dst)
{
	const u8 *mac = skb_mac_header(skb);
	unsigned int flen = skb->len + (skb->data - skb_mac_header(skb));
	__be16 et;
	int off = a2tp_l3_off(skb, &et);

	if (off < 0 || et != htons(ETH_P_IPV6))
		return false;
	if (flen < (unsigned int)off + sizeof(struct ipv6hdr))
		return false;
	/* the fixed header carries the dst; extension headers never move it */
	memcpy(dst, mac + off + offsetof(struct ipv6hdr, daddr),
	       sizeof(*dst));
	return true;
}

bool a2tp_frame_is_tunnel_l4(const struct sk_buff *skb, u16 local_port,
			     const struct a2tp_peer *peer)
{
	const u8 *mac = skb_mac_header(skb);
	unsigned int flen = skb->len + (skb->data - skb_mac_header(skb));
	const struct a2tp_addr *pa = &peer->a;
	const struct udphdr *uh;
	__be16 et;
	int off = a2tp_l3_off(skb, &et);
	u16 sp, dp;
	bool v6;

	if (off < 0)
		return false;
	if (et == htons(ETH_P_IP))
		v6 = false;
	else if (et == htons(ETH_P_IPV6))
		v6 = true;
	else
		return false;

	if (!v6) {
		const struct iphdr *iph;

		if (flen < (unsigned int)off + sizeof(struct iphdr))
			return false;
		iph = (const struct iphdr *)(mac + off);
		if (iph->ihl < 5 || flen < (unsigned int)off + iph->ihl * 4 +
						 sizeof(struct udphdr))
			return false;
		if (iph->protocol != IPPROTO_UDP)
			return false;
		if (pa->family == AF_INET6)
			return false;	/* a v4 frame cannot match a v6 peer */
		if (pa->family == AF_INET && iph->saddr != pa->v4 &&
		    iph->daddr != pa->v4)
			return false;
		uh = (const struct udphdr *)(mac + off + iph->ihl * 4);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		const struct ipv6hdr *ip6h;

		if (flen < (unsigned int)off + sizeof(struct ipv6hdr) +
						 sizeof(struct udphdr))
			return false;
		ip6h = (const struct ipv6hdr *)(mac + off);
		if (ip6h->nexthdr != IPPROTO_UDP)
			return false;
		if (pa->family == AF_INET)
			return false;
		if (pa->family == AF_INET6 &&
		    memcmp(&ip6h->saddr, &pa->v6, sizeof(pa->v6)) &&
		    memcmp(&ip6h->daddr, &pa->v6, sizeof(pa->v6)))
			return false;
		uh = (const struct udphdr *)(mac + off + sizeof(struct ipv6hdr));
#else
		return false;
#endif
	}

	sp = ntohs(uh->source);
	dp = ntohs(uh->dest);
	if (peer->port)
		return (sp == ntohs(peer->port) && dp == local_port) ||
		       (sp == local_port && dp == ntohs(peer->port));
	return sp == local_port || dp == local_port;
}

/* IPv6 Neighbor Discovery plays the role ARP plays for v4: it must pass the
 * filter so the client can answer its own addresses (RS/RA/NS/NA).  Only
 * the fixed-header nexthdr is consulted -- NS/NA never carry extension
 * headers in practice. */
static bool a2tp_frame_is_nd(int off, __be16 et, unsigned int flen,
			     const u8 *mac)
{
	const struct ipv6hdr *ip6h;
	const struct icmp6hdr *icmp6h;

	if (et != htons(ETH_P_IPV6) ||
	    flen < (unsigned int)off + sizeof(struct ipv6hdr) +
				 sizeof(struct icmp6hdr))
		return false;
	ip6h = (const struct ipv6hdr *)(mac + off);
	if (ip6h->nexthdr != IPPROTO_ICMPV6)
		return false;
	icmp6h = (const struct icmp6hdr *)(mac + off + sizeof(struct ipv6hdr));
	return icmp6h->icmp6_type >= NDISC_ROUTER_SOLICITATION &&
	       icmp6h->icmp6_type <= NDISC_NEIGHBOUR_ADVERTISEMENT;
}

/* (x & m) == a for a 16-byte address */
static bool a2tp_v6_masked_eq(const struct in6_addr *x,
			      const struct in6_addr *a,
			      const struct in6_addr *m)
{
	int i;

	for (i = 0; i < 4; i++)
		if ((((const __be32 *)x)[i] & ((const __be32 *)m)[i]) !=
		    ((const __be32 *)a)[i])
			return false;
	return true;
}

bool a2tp_mirror_filter(const struct a2tp_srv *srv, struct sk_buff *skb)
{
	const u8 *mac = skb_mac_header(skb);
	unsigned int flen = skb->len + (skb->data - skb_mac_header(skb));
	struct in6_addr dst6;
	__be32 dst4;
	__be16 et = 0;
	int off = a2tp_l3_off(skb, &et);
	int i;

	if (!srv->filter_n)
		return true;
	if (et == htons(ETH_P_ARP))
		return true;	/* the client answers its own addresses */
	if (a2tp_frame_is_nd(off, et, flen, mac))
		return true;

	/* each family is constrained only by that family's entries: a v4
	 * frame never matches a v6 rule and vice versa */
	dst4 = a2tp_frame_ipv4_dst(skb);
	if (dst4) {
		for (i = 0; i < srv->filter_n; i++) {
			const struct a2tp_filter *f = &srv->filter[i];

			if (f->addr.family == AF_INET &&
			    (dst4 & f->mask.v4) == f->addr.v4)
				return true;
		}
		return false;
	}
	if (a2tp_frame_ipv6_dst(skb, &dst6)) {
		for (i = 0; i < srv->filter_n; i++) {
			const struct a2tp_filter *f = &srv->filter[i];

			if (f->addr.family == AF_INET6 &&
			    a2tp_v6_masked_eq(&dst6, &f->addr.v6, &f->mask.v6))
				return true;
		}
	}
	return false;
}

/* ---------------- peer state ---------------- */

static u64 a2tp_boottime_ms(void)
{
	return ktime_get_boottime_ns() / NSEC_PER_MSEC;
}

void a2tp_skb_src_peer(struct sk_buff *skb, struct a2tp_peer *src)
{
	src->port = udp_hdr(skb)->source;
	if ((*(u8 *)skb_network_header(skb)) >> 4 == 6) {
		src->a.family = AF_INET6;
		src->a.v6 = ipv6_hdr(skb)->saddr;
	} else {
		src->a.family = AF_INET;
		src->a.v4 = ip_hdr(skb)->saddr;
	}
}

void a2tp_srv_peer_learn(struct a2tp_srv *srv, const struct a2tp_peer *p)
{
	/* timestamp first: a racing expiry check must never see a fresh
	 * endpoint paired with an old "last seen" (would falsely count it
	 * expired and hold the mirror one packet longer) */
	atomic64_set(&srv->peer_last_ms, a2tp_boottime_ms());
	a2tp_peer_update(&srv->learned, p);
}

bool a2tp_peer_expired(const struct a2tp_srv *srv)
{
	return srv->peer_timeout_ms &&
	       a2tp_boottime_ms() - atomic64_read(&srv->peer_last_ms) >
	       srv->peer_timeout_ms;
}

/* ---------------- stats ---------------- */

u64 a2tp_stat_sum(const struct a2tp_stats __percpu *stats,
		  enum a2tp_kstat st)
{
	u64 total = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		total += *per_cpu_ptr(&stats->cnt[st], cpu);
	return total;
}
