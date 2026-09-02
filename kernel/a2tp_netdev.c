// SPDX-License-Identifier: GPL-2.0
/* a2tp_netdev.c - client side: the a2tp rtnl_link netdev (l2tp_eth style)
 *
 *	ip link add a2tp0 type a2tp remote 1.2.3.4:1702 [local 9.9.9.9]
 *	                         [local-port N] [keepalive-ms N]
 *	                         [address ..] [mtu ..]
 *
 * The userspace client's TAP is replaced by this device: frames queued on
 * it are prefixed with the a2tp type byte and sent to the server over the
 * kernel UDP socket; datagrams from the server are decapsulated and pushed
 * up the stack with dev_forward_skb() (the tap-write equivalent).
 *
 * "remote" picks the family (v4 or v6); "local", when given, pins the outer
 * source address (the carrier).  Without it every datagram routes from
 * scratch and takes whatever source the routing table prefers, so a
 * vanishing default route or carrier only stalls the tunnel until the
 * underlay is back -- the device itself lives on.
 */

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/timer.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <net/rtnetlink.h>
#include <net/netlink.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/xfrm.h>

#include "a2tp.h"

/* the feature set tun.c clears for TUNSETOFFLOAD(0): without it the stack
 * hands out CHECKSUM_PARTIAL and super-MTU GSO frames, which the tunnel
 * cannot carry (the userspace client never negotiated them either) */
#define A2TP_OFF_FEATURES	(NETIF_F_HW_CSUM | NETIF_F_TSO_ECN | \
					 NETIF_F_TSO | NETIF_F_TSO6 | \
					 NETIF_F_GSO_UDP_L4 | \
					 NETIF_F_GSO_UDP_TUNNEL | \
					 NETIF_F_GSO_UDP_TUNNEL_CSUM)

/* ---------------- receive (server -> us) ---------------- */

static int a2tp_dev_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct a2tp_cli *cli = rcu_dereference_sk_user_data(sk);
	struct a2tp_peer src = {};
	u32 len;
	u8 type;

	if (unlikely(!cli))
		goto drop;

	/* encap delivery parks skb->data at the UDP header (the contract
	 * net/l2tp's l2tp_udp_encap_recv relies on): strip it */
	__skb_pull(skb, sizeof(struct udphdr));

	if (!pskb_may_pull(skb, HDR_LEN))
		goto bad;
	type = *(u8 *)skb->data;

	/* every datagram refreshes the server endpoint (NAT roaming) */
	a2tp_skb_src_peer(skb, &src);
	a2tp_peer_update(&cli->learned, &src);

	if (type == A2TP_TYPE_KEEPALIVE) {
		a2tp_stat(cli->stats, A2TP_KSTAT_RX_KA);
		goto drop;
	}
	if (type != A2TP_TYPE_DATA)
		goto bad;

	__skb_pull(skb, HDR_LEN);
	if (!pskb_may_pull(skb, ETH_HLEN))
		goto bad;
	len = skb->len;

	/* the l2tp_eth_dev_recv() shape: scrub outer-packet state, then
	 * dev_forward_skb() does eth_type_trans + netif_rx */
	secpath_reset(skb);
	skb->ip_summed = CHECKSUM_NONE;
	skb_clear_hash(skb);
	skb_dst_drop(skb);
	nf_reset_ct(skb);

	if (dev_forward_skb(cli->dev, skb) == NET_RX_SUCCESS) {
		a2tp_stat(cli->stats, A2TP_KSTAT_RX_DATA);
		dev_dstats_rx_add(cli->dev, len);
	} else {
		a2tp_stat(cli->stats, A2TP_KSTAT_RX_BAD);
		DEV_STATS_INC(cli->dev, rx_errors);
	}
	return 0;

bad:
	a2tp_stat(cli->stats, A2TP_KSTAT_RX_BAD);
drop:
	kfree_skb(skb);
	return 0;	/* always consumed: nothing listens in userspace */
}

/* ---------------- keepalive ---------------- */

static void a2tp_keepalive_timer(struct timer_list *t)
{
	struct a2tp_cli *cli = timer_container_of(cli, t, ka_timer);
	struct a2tp_peer peer;

	if (!READ_ONCE(cli->ka_on))
		return;

	if (!a2tp_peer_get(&cli->learned, &peer))
		peer = cli->remote;
	a2tp_stat(cli->stats, A2TP_KSTAT_KEEPALIVE);
	/* a dead underlay just drops this; the timer keeps firing and the
	 * first keepalive after the route/carrier returns re-arms everything
	 * (the server re-learns our endpoint from it) */
	a2tp_send_keepalive(&cli->ep, &peer);

	mod_timer(&cli->ka_timer,
		  jiffies + msecs_to_jiffies(cli->keepalive_ms));
}

/* ---------------- netdev ops ---------------- */

static int a2tp_dev_init(struct net_device *dev)
{
	struct a2tp_cli *cli = netdev_priv(dev);

	cli->dev = dev;
	cli->net = dev_net(dev);
	timer_setup(&cli->ka_timer, a2tp_keepalive_timer, 0);
	spin_lock_init(&cli->learned.lock);
	eth_hw_addr_random(dev);
	return 0;
}

static void a2tp_dev_uninit(struct net_device *dev)
{
	struct a2tp_cli *cli = netdev_priv(dev);

	timer_delete_sync(&cli->ka_timer);
	a2tp_ep_close(&cli->ep);
}

static int a2tp_dev_open(struct net_device *dev)
{
	struct a2tp_cli *cli = netdev_priv(dev);

	netif_start_queue(dev);
	if (cli->keepalive_ms) {
		/* fire the first keepalive immediately so the server
		 * learns our endpoint (userspace client parity) */
		WRITE_ONCE(cli->ka_on, true);
		mod_timer(&cli->ka_timer, jiffies);
	}
	return 0;
}

static int a2tp_dev_stop(struct net_device *dev)
{
	struct a2tp_cli *cli = netdev_priv(dev);

	WRITE_ONCE(cli->ka_on, false);
	netif_stop_queue(dev);
	timer_delete_sync(&cli->ka_timer);
	return 0;
}

static netdev_tx_t a2tp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct a2tp_cli *cli = netdev_priv(dev);
	u32 len = skb->len + HDR_LEN;
	struct a2tp_peer peer;

	if (skb_cow_head(skb, LL_MAX_HEADER + HDR_LEN)) {
		dev_dstats_tx_dropped(dev);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	*(u8 *)__skb_push(skb, HDR_LEN) = A2TP_TYPE_DATA;

	if (!a2tp_peer_get(&cli->learned, &peer))
		peer = cli->remote;	/* until the server has answered */

	if (!a2tp_xmit(&cli->ep, skb, &peer)) {
		/* routing/transmit failed: the underlay is (temporarily)
		 * gone; the frame is lost but the tunnel persists */
		a2tp_stat(cli->stats, A2TP_KSTAT_TX_ERR);
		dev_dstats_tx_dropped(dev);
		return NETDEV_TX_OK;
	}
	dev_dstats_tx_add(dev, len);
	return NETDEV_TX_OK;
}

static const struct net_device_ops a2tp_netdev_ops = {
	.ndo_init		= a2tp_dev_init,
	.ndo_uninit		= a2tp_dev_uninit,
	.ndo_open		= a2tp_dev_open,
	.ndo_stop		= a2tp_dev_stop,
	.ndo_start_xmit		= a2tp_dev_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

static void a2tp_dev_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops		= &a2tp_netdev_ops;
	dev->lltx		= true;		/* our own serialization */
	dev->needs_free_netdev	= true;
	dev->pcpu_stat_type	= NETDEV_PCPU_STAT_DSTATS;

	/* mirror of the userspace TAP's TUNSETOFFLOAD(0) state */
	dev->features		&= ~A2TP_OFF_FEATURES;
	dev->hw_features	&= ~A2TP_OFF_FEATURES;
	dev->hw_enc_features	&= ~A2TP_OFF_FEATURES;
}

/* ---------------- rtnl_link ops ---------------- */

static const struct nla_policy a2tp_policy[IFLA_A2TP_MAX + 1] = {
	[IFLA_A2TP_REMOTE_IP]	= { .type = NLA_U32 },
	[IFLA_A2TP_REMOTE_IP6]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[IFLA_A2TP_REMOTE_PORT]	= { .type = NLA_U16 },
	[IFLA_A2TP_LOCAL_PORT]	= { .type = NLA_U16 },
	[IFLA_A2TP_LOCAL_IP]	= { .type = NLA_U32 },
	[IFLA_A2TP_LOCAL_IP6]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[IFLA_A2TP_KEEPALIVE_MS] = { .type = NLA_U32 },
};

static int a2tp_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct nlattr * const *data = params->data;
	struct a2tp_cli *cli = netdev_priv(dev);
	struct net *net = rtnl_newlink_link_net(params);
	struct a2tp_addr local = {};
	bool have_v4, have_v6, l_v4, l_v6;
	int err;

	/* params->data is the IFLA_INFO_DATA payload already parsed into a
	 * type-indexed array by the rtnl core using our policy (macvlan /
	 * ipvlan style); index 0 (UNSPEC) is never sent */
	if (!data) {
		NL_SET_ERR_MSG(extack, "a2tp link requires IFLA_INFO_DATA");
		return -EINVAL;
	}
	have_v4 = data[IFLA_A2TP_REMOTE_IP];
	have_v6 = data[IFLA_A2TP_REMOTE_IP6];
	if (have_v4 == have_v6) {
		NL_SET_ERR_MSG(extack, "exactly one of remote ip / remote ip6 is required");
		return -EINVAL;
	}
	cli->remote.a.family = have_v4 ? AF_INET : AF_INET6;
	if (have_v4)
		cli->remote.a.v4 = nla_get_in_addr(data[IFLA_A2TP_REMOTE_IP]);
	else
		cli->remote.a.v6 = nla_get_in6_addr(data[IFLA_A2TP_REMOTE_IP6]);
	cli->remote.port = data[IFLA_A2TP_REMOTE_PORT] ?
		nla_get_be16(data[IFLA_A2TP_REMOTE_PORT]) :
		htons(A2TP_UDP_PORT);

	l_v4 = data[IFLA_A2TP_LOCAL_IP];
	l_v6 = data[IFLA_A2TP_LOCAL_IP6];
	if (l_v4 && l_v6) {
		NL_SET_ERR_MSG(extack, "local ip and local ip6 are mutually exclusive");
		return -EINVAL;
	}
	if ((l_v4 && !have_v4) || (l_v6 && !have_v6)) {
		NL_SET_ERR_MSG(extack, "local address family must match the remote");
		return -EINVAL;
	}
	if (l_v4) {
		local.family = AF_INET;
		local.v4 = nla_get_in_addr(data[IFLA_A2TP_LOCAL_IP]);
	} else if (l_v6) {
		local.family = AF_INET6;
		local.v6 = nla_get_in6_addr(data[IFLA_A2TP_LOCAL_IP6]);
	}

	cli->local_port = data[IFLA_A2TP_LOCAL_PORT] ?
		nla_get_u16(data[IFLA_A2TP_LOCAL_PORT]) : 0;
	cli->keepalive_ms = data[IFLA_A2TP_KEEPALIVE_MS] ?
		nla_get_u32(data[IFLA_A2TP_KEEPALIVE_MS]) : 10000;

	cli->stats = alloc_percpu(struct a2tp_stats);
	if (!cli->stats)
		return -ENOMEM;

	/* open the socket before registering so the device can never
	 * transmit into a half-built instance */
	err = a2tp_ep_open(net, local.family ? &local : NULL,
			   have_v4, have_v6, cli->local_port,
			   a2tp_dev_encap_recv, cli, &cli->ep);
	if (err) {
		free_percpu(cli->stats);
		return err;
	}

	err = register_netdevice(dev);
	if (err) {
		a2tp_ep_close(&cli->ep);
		free_percpu(cli->stats);
		return err;
	}

	if (have_v4)
		netdev_dbg(dev, "a2tp netdev up: remote %pI4:%hu local-port %u keepalive %ums\n",
			   &cli->remote.a.v4, ntohs(cli->remote.port),
			   cli->local_port, cli->keepalive_ms);
	else
		netdev_dbg(dev, "a2tp netdev up: remote [%pI6]:%hu local-port %u keepalive %ums\n",
			   &cli->remote.a.v6, ntohs(cli->remote.port),
			   cli->local_port, cli->keepalive_ms);
	return 0;
}

static void a2tp_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}

static size_t a2tp_get_size(const struct net_device *dev)
{
	return nla_total_size(4) +	/* IFLA_A2TP_REMOTE_IP */
	       nla_total_size(16) +	/* IFLA_A2TP_REMOTE_IP6 */
	       nla_total_size(2) +	/* IFLA_A2TP_REMOTE_PORT */
	       nla_total_size(2) +	/* IFLA_A2TP_LOCAL_PORT */
	       nla_total_size(4) +	/* IFLA_A2TP_LOCAL_IP */
	       nla_total_size(16) +	/* IFLA_A2TP_LOCAL_IP6 */
	       nla_total_size(4);	/* IFLA_A2TP_KEEPALIVE_MS */
}

static int a2tp_fill_info(struct sk_buff *skb,
			  const struct net_device *dev)
{
	struct a2tp_cli *cli = netdev_priv(dev);

	/* nla_put_* return 0 on success and -EMSGSIZE on overflow */
	if (cli->remote.a.family == AF_INET) {
		if (nla_put_in_addr(skb, IFLA_A2TP_REMOTE_IP,
				    cli->remote.a.v4))
			goto nla_put_failure;
	} else {
		if (nla_put_in6_addr(skb, IFLA_A2TP_REMOTE_IP6,
				     &cli->remote.a.v6))
			goto nla_put_failure;
	}
	if (nla_put_be16(skb, IFLA_A2TP_REMOTE_PORT, cli->remote.port) ||
	    nla_put_u16(skb, IFLA_A2TP_LOCAL_PORT, cli->local_port))
		goto nla_put_failure;

	if (cli->ep.local.family == AF_INET) {
		if (nla_put_in_addr(skb, IFLA_A2TP_LOCAL_IP,
				    cli->ep.local.v4))
			goto nla_put_failure;
	} else if (cli->ep.local.family == AF_INET6) {
		if (nla_put_in6_addr(skb, IFLA_A2TP_LOCAL_IP6,
				     &cli->ep.local.v6))
			goto nla_put_failure;
	}
	if (nla_put_u32(skb, IFLA_A2TP_KEEPALIVE_MS, cli->keepalive_ms))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

struct rtnl_link_ops a2tp_link_ops __read_mostly = {
	.kind		= A2TP_LINK_KIND,
	.priv_size	= sizeof(struct a2tp_cli),
	.setup		= a2tp_dev_setup,
	.policy		= a2tp_policy,
	.maxtype	= IFLA_A2TP_MAX,
	.newlink	= a2tp_newlink,
	.dellink	= a2tp_dellink,
	.get_size	= a2tp_get_size,
	.fill_info	= a2tp_fill_info,
};
