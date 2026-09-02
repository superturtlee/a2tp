// SPDX-License-Identifier: GPL-2.0
/* a2tp_core.c - kernel UDP socket, transmit path, frame parsing, peer state
 *
 * The transmit path mirrors what the userspace tools got for free from a
 * plain UDP socket: source address chosen by the routing layer, IP
 * fragmentation allowed (DF=0, the equivalent of IP_PMTUDISC_DONT), and the
 * full policy stack consulted on the outer header.  Routing goes through
 * ip_route_output_key() == ip_route_output_flow() with flowi4_proto set, so
 * XFRM policy lookup runs on every packet: `ip xfrm policy/state` (kernel
 * IPsec, ESP transport mode) stacks on the outer UDP exactly like it does
 * for geneve/vxlan, and policy routing (`ip rule`) can steer the outer
 * packets into a WireGuard interface.  This is the same shape as the
 * vxlan/l2tp kernel tunnels.
 */

#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/udp_tunnel.h>
#include <net/route.h>
#include <net/ip.h>
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

/* ---------------- kernel UDP socket with encap ---------------- */

int a2tp_sock_open(struct net *net, __be32 bind_ip, u16 local_port,
		   int (*encap_rcv)(struct sock *sk, struct sk_buff *skb),
		   void *priv, struct socket **sockp)
{
	struct udp_tunnel_sock_cfg tunnel_cfg = {};
	struct udp_port_cfg port_cfg = {
		.family			= AF_INET,
		.local_ip.s_addr	= bind_ip,
		.local_udp_port		= htons(local_port),
		/* no peer_udp_port: the socket stays unconnected so the
		 * peer endpoint can roam (NAT rebind) and be set per packet */
	};
	struct socket *sock;
	int err;

	err = udp_sock_create4(net, &port_cfg, &sock);
	if (err)
		return err;

	/* the userspace udp_bind() asked for 4 MB both ways; kernel sockets
	 * assign buffers directly (no rmem_max clamp) */
	sock->sk->sk_rcvbuf = 4 << 20;
	sock->sk->sk_sndbuf = 4 << 20;

	tunnel_cfg.sk_user_data = priv;
	tunnel_cfg.encap_type = UDP_ENCAP_L2TPINUDP;
	tunnel_cfg.encap_rcv = encap_rcv;
	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	*sockp = sock;
	return 0;
}

void a2tp_sock_close(struct socket *sock)
{
	/* clear sk_user_data before release so a concurrent encap callback
	 * does not dereference a freed instance (udp_tunnel_sock_release
	 * does not wait for readers) */
	rcu_assign_sk_user_data(sock->sk, NULL);
	synchronize_net();
	udp_tunnel_sock_release(sock);
}

/* ---------------- transmit ---------------- */

/* Send one a2tp datagram (skb->data at the type byte, payload = one
 * complete ethernet frame) to @peer.  Consumes skb on all paths, returns
 * false when it could not be sent.  Safe from softirq (rx_handler,
 * ndo_start_xmit, timer callbacks).
 */
bool a2tp_xmit(struct socket *sock, struct sk_buff *skb,
	       const struct a2tp_peer *peer)
{
	struct sock *sk = sock->sk;
	struct flowi4 fl4 = {
		.flowi4_proto		= IPPROTO_UDP,
		.daddr			= peer->ip,
		.saddr			= 0,		/* let routing pick */
		.fl4_sport		= inet_sk(sk)->inet_sport,
		.fl4_dport		= peer->port,
	};
	struct rtable *rt;

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
	udp_tunnel_xmit_skb(rt, sk, skb, fl4.saddr, peer->ip,
			    0 /* tos */,
			    sock_net(sk)->ipv4.sysctl_ip_default_ttl,
			    0 /* df */, fl4.fl4_sport, fl4.fl4_dport,
			    false, true, 0);
	return true;

drop:
	kfree_skb(skb);
	return false;
}

void a2tp_send_keepalive(struct socket *sock, const struct a2tp_peer *peer)
{
	struct sk_buff *skb;

	skb = alloc_skb(LL_MAX_HEADER + HDR_LEN, GFP_ATOMIC);
	if (!skb)
		return;
	*(u8 *)skb_put(skb, HDR_LEN) = A2TP_TYPE_KEEPALIVE;
	a2tp_xmit(sock, skb, peer);
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

bool a2tp_frame_is_tunnel_l4(const struct sk_buff *skb, u16 local_port,
			     __be32 peer_ip, __be16 peer_port)
{
	const u8 *mac = skb_mac_header(skb);
	unsigned int flen = skb->len + (skb->data - skb_mac_header(skb));
	__be16 et;
	int off = a2tp_l3_off(skb, &et);
	const struct iphdr *iph;
	const struct udphdr *uh;
	u16 sp, dp;
	bool port_match;

	if (off < 0 || et != htons(ETH_P_IP))
		return false;
	if (flen < (unsigned int)off + sizeof(struct iphdr))
		return false;
	iph = (const struct iphdr *)(mac + off);
	if (iph->ihl < 5 || flen < (unsigned int)off + iph->ihl * 4 +
			     sizeof(struct udphdr))
		return false;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	uh = (const struct udphdr *)(mac + off + iph->ihl * 4);
	sp = ntohs(uh->source);
	dp = ntohs(uh->dest);

	if (peer_port)
		port_match = (sp == peer_port && dp == local_port) ||
			     (sp == local_port && dp == peer_port);
	else
		port_match = (sp == local_port || dp == local_port);
	if (!port_match)
		return false;
	if (peer_ip)
		return iph->saddr == peer_ip || iph->daddr == peer_ip;
	return true;
}

bool a2tp_mirror_filter(const struct a2tp_srv *srv, struct sk_buff *skb)
{
	__be32 dst;
	int i;

	if (!srv->filter_n)
		return true;
	if (a2tp_frame_ethertype(skb) == htons(ETH_P_ARP))
		return true;	/* ARP passes: the client answers its own IPs */
	dst = a2tp_frame_ipv4_dst(skb);
	if (!dst)
		return false;
	for (i = 0; i < srv->filter_n; i++)
		if (dst == srv->filter_ip[i])
			return true;
	return false;
}

/* ---------------- peer state ---------------- *
 * ip+port packed into one atomic word (the userspace sockaddr_key trick):
 * tear-free refresh from softirq without any lock.  0 means "unknown"
 * (a real peer always has a nonzero port, so the packing is injective).
 */

static u64 a2tp_peer_key(const struct a2tp_peer *p)
{
	return ((u64)p->ip << 16) | p->port;
}

static struct a2tp_peer a2tp_key_peer(u64 k)
{
	struct a2tp_peer p = {
		.ip	= (__force __be32)(k >> 16),
		.port	= (__force __be16)(k & 0xffff),
	};

	return p;
}

static u64 a2tp_boottime_ms(void)
{
	return ktime_get_boottime_ns() / NSEC_PER_MSEC;
}

void a2tp_srv_peer_update(struct a2tp_srv *srv, const struct a2tp_peer *p)
{
	/* timestamp first: a racing reader must never see a fresh endpoint
	 * paired with an old "last seen" (would falsely count it expired) */
	atomic64_set(&srv->peer_last_ms, a2tp_boottime_ms());
	atomic64_set(&srv->learned, a2tp_peer_key(p));
}

bool a2tp_srv_peer_get(struct a2tp_srv *srv, struct a2tp_peer *out)
{
	u64 k = atomic64_read(&srv->learned);

	if (!k)
		return false;
	*out = a2tp_key_peer(k);
	return true;
}

u64 a2tp_srv_peer_last_ms(const struct a2tp_srv *srv)
{
	return atomic64_read(&srv->peer_last_ms);
}

bool a2tp_peer_expired(const struct a2tp_srv *srv)
{
	return srv->peer_timeout_ms &&
	       a2tp_boottime_ms() - a2tp_srv_peer_last_ms(srv) >
	       srv->peer_timeout_ms;
}

void a2tp_cli_peer_update(struct a2tp_cli *cli, const struct a2tp_peer *p)
{
	atomic64_set(&cli->learned, a2tp_peer_key(p));
}

bool a2tp_cli_peer_get(struct a2tp_cli *cli, struct a2tp_peer *out)
{
	u64 k = atomic64_read(&cli->learned);

	if (!k)
		return false;
	*out = a2tp_key_peer(k);
	return true;
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
