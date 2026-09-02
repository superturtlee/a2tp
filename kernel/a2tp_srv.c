// SPDX-License-Identifier: GPL-2.0
/* a2tp_srv.c - server side: the frame pump installed on a physical NIC
 *
 *	a2tpctl srv add -i eth0 [--peer 1.2.3.4:1702]
 *	                         [--filter-ip 10.0.0.0/255.255.255.0,...]
 *	                         [--filter-ip6 fd00::/64,...] [-b <carrier>]
 *
 * No netdev of its own (the userspace design has none either): an
 * rx_handler -- the same hook the bridge uses -- is registered on the
 * taken-over NIC.  Each received frame is examined, and if it passes the
 * filters a clone is prefixed with the a2tp type byte and sent to the peer
 * over the kernel UDP socket; the frame itself always continues up the
 * stack (RX_HANDLER_PASS), so the mirror is a passive tap, exactly like the
 * AF_PACKET socket it replaces.  Datagrams from the peer are decapsulated
 * and transmitted on the NIC with dev_queue_xmit(), like an AF_PACKET raw
 * send.
 *
 * The underlay endpoint (struct a2tp_ep) holds one v4 and one v6-only
 * socket unless -b pinned a single family; the instance outlives any
 * underlay outage because nothing on the transmit path is cached (see
 * a2tp_core.c).
 */

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ktime.h>
#include <net/rtnetlink.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>

#include "a2tp.h"

static struct genl_family a2tp_nl_family;

/* max UDP payload (u16 length - header), one type byte + one frame */
#define A2TP_MAX_DGRAM		65507

/* ---------------- per-netns instance table ---------------- */

static unsigned int a2tp_net_id __read_mostly;

struct a2tp_net {
	struct list_head	srv_list;
};

int a2tp_srv_pernet_init(struct net *net)
{
	struct a2tp_net *an = net_generic(net, a2tp_net_id);

	INIT_LIST_HEAD(&an->srv_list);
	return 0;
}

void a2tp_srv_pernet_exit(struct net *net)
{
	struct a2tp_net *an = net_generic(net, a2tp_net_id);
	struct a2tp_srv *srv, *tmp;

	/* netns teardown unregisters every device, so the NETDEV_UNREGISTER
	 * notifier normally empties the list first; this is the backstop */
	rtnl_lock();
	list_for_each_entry_safe(srv, tmp, &an->srv_list, list)
		a2tp_srv_destroy(srv, false);
	rtnl_unlock();
}

struct a2tp_srv *a2tp_srv_find(struct net *net, const char *ifname)
{
	struct a2tp_net *an = net_generic(net, a2tp_net_id);
	struct a2tp_srv *srv;

	list_for_each_entry(srv, &an->srv_list, list)
		if (!strcmp(srv->dev->name, ifname))
			return srv;
	return NULL;
}

/* ---------------- mirror path (NIC -> peer), softirq ---------------- */

static rx_handler_result_t a2tp_srv_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct a2tp_srv *srv = rcu_dereference(skb->dev->rx_handler_data);
	struct a2tp_peer peer;
	unsigned int frame_len, mac_len;
	struct sk_buff *clone;

	if (unlikely(!srv))
		return RX_HANDLER_PASS;

	/* GRO ran before the rx_handler: a super-frame is several wire
	 * frames glued together and exceeds the datagram limit; the userspace
	 * pump had the same problem (a2tpctl turns the NIC offloads off) */
	if (skb_is_gso(skb)) {
		a2tp_stat(srv->stats, A2TP_KSTAT_PASS_GSO);
		return RX_HANDLER_PASS;
	}

	mac_len = skb->data - skb_mac_header(skb);
	frame_len = mac_len + skb->len;
	if (frame_len + HDR_LEN > A2TP_MAX_DGRAM) {
		a2tp_stat(srv->stats, A2TP_KSTAT_PASS_MTU);
		return RX_HANDLER_PASS;
	}

	/* never mirror the tunnel's own UDP: that is how "tunnel inside the
	 * tunnel" echo loops are born (userspace --no-self-filter to opt out,
	 * e.g. when a2tp runs inside another a2tp on purpose) */
	if (srv->self_filter) {
		struct a2tp_peer selfp = {};	/* zero = unknown, ports only */

		if (srv->peer_fixed)
			selfp = srv->peer;
		else
			a2tp_peer_get(&srv->learned, &selfp);
		if (a2tp_frame_is_tunnel_l4(skb, srv->local_port, &selfp)) {
			a2tp_stat(srv->stats, A2TP_KSTAT_PASS_SELF);
			return RX_HANDLER_PASS;
		}
	}

	/* multi-IP NIC: mirror only the addresses the client took over */
	if (!a2tp_mirror_filter(srv, skb)) {
		a2tp_stat(srv->stats, A2TP_KSTAT_PASS_FILTER);
		return RX_HANDLER_PASS;
	}

	if (srv->peer_fixed) {
		peer = srv->peer;
	} else if (!a2tp_peer_get(&srv->learned, &peer) ||
		   a2tp_peer_expired(srv)) {
		/* nobody has talked to us yet (or for a while): hold the
		 * mirror until the next packet re-learns the endpoint */
		a2tp_stat(srv->stats, A2TP_KSTAT_PASS_NO_PEER);
		return RX_HANDLER_PASS;
	}

	clone = skb_clone(skb, GFP_ATOMIC);
	if (!clone)
		return RX_HANDLER_PASS;

	/* the clone still carries how the NIC classified the *captured*
	 * frame: a unicast frame for the client's taken-over address is
	 * PACKET_OTHERHOST, and ip6_rcv_core() drops such skbs.  v4's
	 * iptunnel_xmit() scrubs this away for us; v6's ip6tunnel_xmit()
	 * does not, so scrub here once for both families */
	skb_scrub_packet(clone, false);

	/* re-push the ethernet header (data sits at L3 after
	 * eth_type_trans), then the type byte; cow for the UDP/IP headers */
	if (skb_cow_head(clone, LL_MAX_HEADER + HDR_LEN)) {
		kfree_skb(clone);
		return RX_HANDLER_PASS;
	}
	__skb_push(clone, mac_len + HDR_LEN);
	*(u8 *)clone->data = A2TP_TYPE_DATA;

	if (!a2tp_xmit(&srv->ep, clone, &peer)) {
		/* the underlay is (temporarily) gone; the frame stays with the
		 * local stack either way and the instance lives on */
		a2tp_stat(srv->stats, A2TP_KSTAT_TX_ERR);
		return RX_HANDLER_PASS;
	}
	a2tp_stat(srv->stats, A2TP_KSTAT_MIRROR);

	/* the original frame keeps flowing up the stack untouched */
	return RX_HANDLER_PASS;
}

/* ---------------- inject path (peer -> NIC), softirq ---------------- */

static int a2tp_srv_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct a2tp_srv *srv = rcu_dereference_sk_user_data(sk);
	struct a2tp_peer src = {};
	u8 type;

	if (unlikely(!srv))
		goto drop;

	/* encap delivery parks skb->data at the UDP header (the contract
	 * net/l2tp's l2tp_udp_encap_recv relies on): strip it */
	__skb_pull(skb, sizeof(struct udphdr));

	if (!pskb_may_pull(skb, HDR_LEN))
		goto bad;
	type = *(u8 *)skb->data;

	a2tp_skb_src_peer(skb, &src);

	if (srv->peer_fixed) {
		if (!a2tp_peer_eq(&src, &srv->peer)) {
			/* --peer locks the one allowed source: anything
			 * else is an injection attempt (count + drop) */
			a2tp_stat(srv->stats, A2TP_KSTAT_PEER_PINNED);
			goto drop;
		}
	} else {
		/* every datagram refreshes the peer (NAT roaming) */
		a2tp_srv_peer_learn(srv, &src);
	}

	if (type == A2TP_TYPE_KEEPALIVE) {
		a2tp_stat(srv->stats, A2TP_KSTAT_RX_KA);
		goto drop;
	}
	if (type != A2TP_TYPE_DATA)
		goto bad;

	__skb_pull(skb, HDR_LEN);
	if (!pskb_may_pull(skb, ETH_HLEN) || skb_is_gso(skb))
		goto bad;

	/* the packet_snd() shape: hand the frame to the NIC as if a raw
	 * AF_PACKET socket had sent it */
	secpath_reset(skb);
	nf_reset_ct(skb);
	skb->dev = srv->dev;
	skb->protocol = eth_hdr(skb)->h_proto;
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_HOST;
	skb->mark = 0;
	skb_reset_mac_header(skb);

	dev_queue_xmit(skb);
	a2tp_stat(srv->stats, A2TP_KSTAT_INJECT);
	return 0;

bad:
	a2tp_stat(srv->stats, A2TP_KSTAT_RX_BAD);
drop:
	kfree_skb(skb);
	return 0;	/* always consumed: nothing listens in userspace */
}

/* ---------------- instance lifecycle, rtnl held ---------------- */

/* parsed A2TP_CMD_SRV_ADD payload, gathered before creating anything */
struct a2tp_srv_cfg {
	u16			local_port;	/* A2TP_UDP_PORT default */
	struct a2tp_addr	bind;		/* AF_UNSPEC: dual-stack wildcards */
	bool			self_filter;
	u32			peer_timeout_ms;	/* 30s default */
	bool			peer_fixed;
	struct a2tp_peer	peer;		/* valid when peer_fixed */
	struct a2tp_filter	filter[A2TP_FILTER_MAX];
	int			filter_n;
};

/* caller holds rtnl; @restore_promisc false when the device is dying
 * (NETDEV_UNREGISTER) and its state is being torn down anyway */
void a2tp_srv_destroy(struct a2tp_srv *srv, bool restore_promisc)
{
	list_del(&srv->list);

	netdev_rx_handler_unregister(srv->dev);
	if (restore_promisc && !srv->was_promisc)
		dev_set_promiscuity(srv->dev, -1);

	a2tp_ep_close(&srv->ep);
	dev_put(srv->dev);
	free_percpu(srv->stats);
	kfree(srv);
}

static struct a2tp_srv *a2tp_srv_create(struct net *net, const char *ifname,
					const struct a2tp_srv_cfg *cfg)
{
	struct a2tp_net *an = net_generic(net, a2tp_net_id);
	bool open_v4, open_v6;
	struct net_device *dev;
	struct a2tp_srv *srv;
	int err;

	dev = dev_get_by_name(net, ifname);
	if (!dev)
		return ERR_PTR(-ENODEV);

	if (netdev_is_rx_handler_busy(dev)) {
		err = -EBUSY;	/* a bridge or macvlan already owns it */
		goto err_put;
	}

	srv = kzalloc(sizeof(*srv), GFP_KERNEL);
	if (!srv) {
		err = -ENOMEM;
		goto err_put;
	}

	srv->stats = alloc_percpu(struct a2tp_stats);
	if (!srv->stats) {
		err = -ENOMEM;
		goto err_free;
	}

	srv->net = net;
	srv->dev = dev;
	srv->local_port = cfg->local_port;
	srv->self_filter = cfg->self_filter;
	srv->peer_timeout_ms = cfg->peer_timeout_ms;
	srv->peer_fixed = cfg->peer_fixed;
	srv->peer = cfg->peer;
	srv->filter_n = cfg->filter_n;
	memcpy(srv->filter, cfg->filter, cfg->filter_n * sizeof(cfg->filter[0]));
	spin_lock_init(&srv->learned.lock);

	/* no -b: one wildcard socket per family (the v6 one is v6-only so
	 * both can hold the same port); with -b, the carrier's family alone */
	if (cfg->bind.family == AF_INET) {
		open_v4 = true;
		open_v6 = false;
	} else if (cfg->bind.family == AF_INET6) {
		open_v4 = false;
		open_v6 = true;
	} else {
		open_v4 = true;
		open_v6 = true;
	}

	/* open the sockets before installing the handler so the mirror path
	 * can never see a half-built instance (bind conflicts surface here
	 * as -EADDRINUSE, same as the userspace udp_bind) */
	err = a2tp_ep_open(net, cfg->bind.family ? &cfg->bind : NULL,
			   open_v4, open_v6, cfg->local_port,
			   a2tp_srv_encap_recv, srv, &srv->ep);
	if (err)
		goto err_stats;

	srv->was_promisc = !!(dev->flags & IFF_PROMISC);
	err = dev_set_promiscuity(dev, 1);
	if (err)
		goto err_sock;

	err = netdev_rx_handler_register(dev, a2tp_srv_frame, srv);
	if (err)
		goto err_promisc;

	list_add(&srv->list, &an->srv_list);
	return srv;

err_promisc:
	if (!srv->was_promisc)
		dev_set_promiscuity(dev, -1);
err_sock:
	a2tp_ep_close(&srv->ep);
err_stats:
	free_percpu(srv->stats);
err_free:
	kfree(srv);
err_put:
	dev_put(dev);
	return ERR_PTR(err);
}

/* NIC gone away (unregister or netns teardown); rtnl already held */
static int a2tp_netdev_event(struct notifier_block *nb, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct a2tp_net *an;
	struct a2tp_srv *srv, *tmp;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	an = net_generic(dev_net(dev), a2tp_net_id);
	list_for_each_entry_safe(srv, tmp, &an->srv_list, list)
		if (srv->dev == dev)
			a2tp_srv_destroy(srv, false);
	return NOTIFY_DONE;
}

static struct notifier_block a2tp_netdev_nb = {
	.notifier_call = a2tp_netdev_event,
};

/* ---------------- genl control plane ---------------- */

/* inner policy of one filter array element: {ADDR u32, MASK u32} or the
 * 16-byte v6 equivalents; enforced exact-len so nothing is ever read past
 * the attribute */
static const struct nla_policy a2tp_filter4_policy[__A2TP_FILTER_MAX] = {
	[A2TP_FILTER_ADDR]	= NLA_POLICY_EXACT_LEN(4),
	[A2TP_FILTER_MASK]	= NLA_POLICY_EXACT_LEN(4),
};

static const struct nla_policy a2tp_filter6_policy[__A2TP_FILTER_MAX] = {
	[A2TP_FILTER_ADDR]	= NLA_POLICY_EXACT_LEN(16),
	[A2TP_FILTER_MASK]	= NLA_POLICY_EXACT_LEN(16),
};

static const struct nla_policy a2tp_nl_policy[A2TP_ATTR_MAX + 1] = {
	[A2TP_ATTR_IFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
	[A2TP_ATTR_PORT]	= { .type = NLA_U16 },
	[A2TP_ATTR_BIND_IP]	= { .type = NLA_U32 },
	[A2TP_ATTR_BIND_IP6]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[A2TP_ATTR_PEER_IP]	= { .type = NLA_U32 },
	[A2TP_ATTR_PEER_IP6]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[A2TP_ATTR_PEER_PORT]	= { .type = NLA_U16 },
	[A2TP_ATTR_PEER_TIMEOUT]	= { .type = NLA_U32 },
	[A2TP_ATTR_NO_SELF_FILTER]	= { .type = NLA_FLAG },
	[A2TP_ATTR_PEER_FIXED]	= { .type = NLA_FLAG },
	[A2TP_ATTR_FILTER_IP]	= NLA_POLICY_NESTED_ARRAY(a2tp_filter4_policy),
	[A2TP_ATTR_FILTER_IP6]	= NLA_POLICY_NESTED_ARRAY(a2tp_filter6_policy),
};

/* one --filter-ip / --filter-ip6 entry into the reply */
static int a2tp_fill_one_filter(struct sk_buff *skb,
				const struct a2tp_filter *f)
{
	struct nlattr *nest;
	size_t len = f->addr.family == AF_INET ? 4 : 16;

	nest = nla_nest_start(skb, 1 /* dummy type */);
	if (!nest)
		return -EMSGSIZE;
	if (nla_put(skb, A2TP_FILTER_ADDR, len, &f->addr) ||
	    nla_put(skb, A2TP_FILTER_MASK, len, &f->mask))
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

/* one reply message describing @srv; used by SRV_ADD and SRV_GET */
static int a2tp_srv_fill(struct sk_buff *skb, u32 portid, u32 seq, int flags,
			 struct a2tp_srv *srv)
{
	struct a2tp_peer peer = {};
	bool known = false;
	struct nlattr *nest;
	void *hdr;
	u64 st;
	int i;

	hdr = genlmsg_put(skb, portid, seq, &a2tp_nl_family, flags,
			  A2TP_CMD_SRV_GET);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_string(skb, A2TP_ATTR_IFNAME, srv->dev->name) ||
	    nla_put_u16(skb, A2TP_ATTR_PORT, srv->local_port) ||
	    nla_put_u32(skb, A2TP_ATTR_PEER_TIMEOUT, srv->peer_timeout_ms))
		goto nla_put_failure;

	if (srv->ep.local.family == AF_INET &&
	    nla_put_u32(skb, A2TP_ATTR_BIND_IP,
			(__force u32)srv->ep.local.v4))
		goto nla_put_failure;
	if (srv->ep.local.family == AF_INET6 &&
	    nla_put_in6_addr(skb, A2TP_ATTR_BIND_IP6, &srv->ep.local.v6))
		goto nla_put_failure;

	if (srv->peer_fixed) {
		if (nla_put_flag(skb, A2TP_ATTR_PEER_FIXED))
			goto nla_put_failure;
		peer = srv->peer;
	} else {
		known = a2tp_peer_get_proc(&srv->learned, &peer);
		if (known && nla_put_flag(skb, A2TP_ATTR_PEER_KNOWN))
			goto nla_put_failure;
	}
	if (srv->peer_fixed || known) {
		int bad;

		if (peer.a.family == AF_INET6)
			bad = nla_put_in6_addr(skb, A2TP_ATTR_PEER_IP6,
					       &peer.a.v6);
		else
			bad = nla_put_u32(skb, A2TP_ATTR_PEER_IP,
					  (__force u32)peer.a.v4);
		if (bad ||
		    nla_put_u16(skb, A2TP_ATTR_PEER_PORT,
				(__force u16)peer.port))
			goto nla_put_failure;
		if (known &&
		    nla_put_u64_64bit(skb, A2TP_ATTR_PEER_AGE_MS,
				      ktime_get_boottime_ns() / NSEC_PER_MSEC -
				      atomic64_read(&srv->peer_last_ms),
				      A2TP_ATTR_PAD))
			goto nla_put_failure;
	}

	if (srv->filter_n) {
		struct nlattr *nest4 = NULL, *nest6 = NULL;

		/* two arrays, one per family, opened lazily */
		for (i = 0; i < srv->filter_n; i++) {
			const struct a2tp_filter *f = &srv->filter[i];

			if (f->addr.family == AF_INET && !nest4) {
				nest4 = nla_nest_start(skb, A2TP_ATTR_FILTER_IP);
				if (!nest4)
					goto nla_put_failure;
			} else if (f->addr.family == AF_INET6 && !nest6) {
				nest6 = nla_nest_start(skb, A2TP_ATTR_FILTER_IP6);
				if (!nest6)
					goto nla_put_failure;
			}
			if (a2tp_fill_one_filter(skb, f))
				goto nla_put_failure;
		}
		if (nest4)
			nla_nest_end(skb, nest4);
		if (nest6)
			nla_nest_end(skb, nest6);
	}

	nest = nla_nest_start(skb, A2TP_ATTR_STATS);
	if (!nest)
		goto nla_put_failure;
	for (i = 0; i < A2TP_KSTAT_NR; i++) {
		st = a2tp_stat_sum(srv->stats, i);
		if (nla_put_u64_64bit(skb, i, st, A2TP_ATTR_PAD))
			goto nla_put_failure;
	}
	nla_nest_end(skb, nest);

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

/* walk one nested filter array into cfg->filter[]; entries are stored
 * pre-masked (addr &= mask) so the match itself stays a pure compare */
static int a2tp_parse_filter_array(struct nlattr *nest,
				   const struct nla_policy *policy,
				   struct a2tp_srv_cfg *cfg,
				   struct netlink_ext_ack *extack)
{
	struct nlattr *ft[__A2TP_FILTER_MAX] = {};
	struct nlattr *na;
	bool v6 = policy == a2tp_filter6_policy;
	int rem, err;

	nla_for_each_nested(na, nest, rem) {
		struct a2tp_filter *f;

		if (cfg->filter_n >= A2TP_FILTER_MAX) {
			NL_SET_ERR_MSG(extack, "too many filter entries");
			return -E2BIG;
		}
		err = nla_parse_nested(ft, __A2TP_FILTER_MAX - 1, na, policy,
				       extack);
		if (err)
			return err;
		if (!ft[A2TP_FILTER_ADDR] || !ft[A2TP_FILTER_MASK]) {
			NL_SET_ERR_MSG(extack, "filter entry needs addr and mask");
			return -EINVAL;
		}

		f = &cfg->filter[cfg->filter_n++];
		f->addr.family = f->mask.family = v6 ? AF_INET6 : AF_INET;
		memcpy(&f->addr.v6, nla_data(ft[A2TP_FILTER_ADDR]),
		       v6 ? 16 : 4);
		memcpy(&f->mask.v6, nla_data(ft[A2TP_FILTER_MASK]),
		       v6 ? 16 : 4);
		a2tp_addr_and(&f->addr, &f->addr, &f->mask);
	}
	return 0;
}

static int a2tp_nl_srv_add(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct a2tp_srv_cfg cfg = {
		.local_port		= A2TP_UDP_PORT,
		.self_filter		= true,
		.peer_timeout_ms	= 30000,
	};
	const char *ifname;
	struct a2tp_srv *srv;
	struct sk_buff *rep = NULL;
	bool have_v4, have_v6;
	int err;

	if (!info->attrs[A2TP_ATTR_IFNAME])
		return -EINVAL;
	ifname = nla_data(info->attrs[A2TP_ATTR_IFNAME]);

	if (info->attrs[A2TP_ATTR_PORT])
		cfg.local_port = nla_get_u16(info->attrs[A2TP_ATTR_PORT]);
	if (info->attrs[A2TP_ATTR_PEER_TIMEOUT])
		cfg.peer_timeout_ms =
			nla_get_u32(info->attrs[A2TP_ATTR_PEER_TIMEOUT]);
	cfg.self_filter = !info->attrs[A2TP_ATTR_NO_SELF_FILTER];

	/* the carrier: -b 1.2.3.4 / -b fd00::1; absent = dual-stack wildcards */
	if (info->attrs[A2TP_ATTR_BIND_IP] && info->attrs[A2TP_ATTR_BIND_IP6]) {
		NL_SET_ERR_MSG(info->extack,
			       "bind ip and bind ip6 are mutually exclusive");
		return -EINVAL;
	}
	if (info->attrs[A2TP_ATTR_BIND_IP]) {
		cfg.bind.family = AF_INET;
		cfg.bind.v4 = (__force __be32)
			nla_get_u32(info->attrs[A2TP_ATTR_BIND_IP]);
	} else if (info->attrs[A2TP_ATTR_BIND_IP6]) {
		cfg.bind.family = AF_INET6;
		cfg.bind.v6 = nla_get_in6_addr(info->attrs[A2TP_ATTR_BIND_IP6]);
	}

	if (info->attrs[A2TP_ATTR_PEER_FIXED]) {
		have_v4 = info->attrs[A2TP_ATTR_PEER_IP];
		have_v6 = info->attrs[A2TP_ATTR_PEER_IP6];
		if (have_v4 == have_v6 || !info->attrs[A2TP_ATTR_PEER_PORT]) {
			NL_SET_ERR_MSG(info->extack,
				       "--peer needs exactly one address and a port");
			return -EINVAL;
		}
		cfg.peer_fixed = true;
		cfg.peer.a.family = have_v4 ? AF_INET : AF_INET6;
		if (have_v4)
			cfg.peer.a.v4 = (__force __be32)
				nla_get_u32(info->attrs[A2TP_ATTR_PEER_IP]);
		else
			cfg.peer.a.v6 =
				nla_get_in6_addr(info->attrs[A2TP_ATTR_PEER_IP6]);
		cfg.peer.port = nla_get_be16(info->attrs[A2TP_ATTR_PEER_PORT]);
	}

	if (info->attrs[A2TP_ATTR_FILTER_IP]) {
		err = a2tp_parse_filter_array(info->attrs[A2TP_ATTR_FILTER_IP],
					      a2tp_filter4_policy, &cfg,
					      info->extack);
		if (err)
			return err;
	}
	if (info->attrs[A2TP_ATTR_FILTER_IP6]) {
		err = a2tp_parse_filter_array(info->attrs[A2TP_ATTR_FILTER_IP6],
					      a2tp_filter6_policy, &cfg,
					      info->extack);
		if (err)
			return err;
	}

	rtnl_lock();
	if (a2tp_srv_find(net, ifname)) {
		err = -EEXIST;
	} else {
		srv = a2tp_srv_create(net, ifname, &cfg);
		err = PTR_ERR_OR_ZERO(srv);
	}
	/* build the reply under the lock: a concurrent srv del must not be
	 * able to free the instance while we describe it */
	if (!err) {
		rep = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
		if (!rep || a2tp_srv_fill(rep, info->snd_portid,
					  info->snd_seq, 0, srv)) {
			nlmsg_free(rep);
			rep = NULL;
		}
	}
	rtnl_unlock();

	if (err)
		return err;
	if (!rep)
		return -ENOMEM;
	return genlmsg_reply(rep, info);
}

static int a2tp_nl_srv_del(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct a2tp_srv *srv;
	int err = 0;

	if (!info->attrs[A2TP_ATTR_IFNAME])
		return -EINVAL;

	rtnl_lock();
	srv = a2tp_srv_find(net, nla_data(info->attrs[A2TP_ATTR_IFNAME]));
	if (srv)
		a2tp_srv_destroy(srv, true);
	else
		err = -ENOENT;
	rtnl_unlock();

	return err;
}

static int a2tp_nl_srv_get(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct a2tp_net *an = net_generic(sock_net(skb->sk), a2tp_net_id);
	struct a2tp_srv *srv;
	int err = 0;

	rtnl_lock();
	list_for_each_entry(srv, &an->srv_list, list) {
		err = a2tp_srv_fill(skb, NETLINK_CB(cb->skb).portid,
				    cb->nlh->nlmsg_seq, NLM_F_MULTI, srv);
		if (err)
			break;
	}
	rtnl_unlock();

	return err;
}

/* .validate (GENL_DONT_VALIDATE_*) must stay unset: ops at or above
 * resv_start_op (0 here = all of them) may not disable core validation
 * (genl_validate_ops, genetlink.c:585).  The family-level policy is
 * inherited by every op, and strict parsing is the new-op default. */
static const struct genl_small_ops a2tp_nl_ops[] = {
	{
		.cmd		= A2TP_CMD_SRV_ADD,
		.doit		= a2tp_nl_srv_add,
		.flags		= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd		= A2TP_CMD_SRV_DEL,
		.doit		= a2tp_nl_srv_del,
		.flags		= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd		= A2TP_CMD_SRV_GET,
		.dumpit		= a2tp_nl_srv_get,
		/* readable by anyone, like `ip link` */
	},
};

static struct genl_family a2tp_nl_family __ro_after_init = {
	.name		= A2TP_GENL_NAME,
	.version	= A2TP_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= A2TP_ATTR_MAX,
	.policy		= a2tp_nl_policy,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.small_ops	= a2tp_nl_ops,
	.n_small_ops	= ARRAY_SIZE(a2tp_nl_ops),
};

int a2tp_srv_init(void)
{
	int err;

	err = register_netdevice_notifier(&a2tp_netdev_nb);
	if (err)
		return err;

	err = genl_register_family(&a2tp_nl_family);
	if (err)
		goto err_notifier;

	return 0;

err_notifier:
	unregister_netdevice_notifier(&a2tp_netdev_nb);
	return err;
}

void a2tp_srv_exit(void)
{
	genl_unregister_family(&a2tp_nl_family);
	unregister_netdevice_notifier(&a2tp_netdev_nb);
}

struct pernet_operations a2tp_pernet_ops = {
	.init	= a2tp_srv_pernet_init,
	.exit	= a2tp_srv_pernet_exit,
	.id	= &a2tp_net_id,
	.size	= sizeof(struct a2tp_net),
};
