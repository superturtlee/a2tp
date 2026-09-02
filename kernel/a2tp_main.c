// SPDX-License-Identifier: GPL-2.0
/* a2tp_main.c - module glue: registers the rtnl link kind, the genl family
 * and the per-netns instance table
 *
 * Load order matters for unload: the genl family goes first (no new server
 * instances can appear), then rtnl_link_unregister() destroys every client
 * netdev (running their ndo_uninit), then the pernet exit is the backstop
 * for any server instance whose NIC never sent NETDEV_UNREGISTER.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

#include "a2tp.h"

static int __init a2tp_init(void)
{
	int err;

	err = register_pernet_subsys(&a2tp_pernet_ops);
	if (err)
		return err;

	err = rtnl_link_register(&a2tp_link_ops);
	if (err)
		goto err_pernet;

	err = a2tp_srv_init();
	if (err)
		goto err_link;

	pr_info("a2tp: kernel data plane loaded (link kind \"%s\", genl family \"%s\")\n",
		A2TP_LINK_KIND, A2TP_GENL_NAME);
	return 0;

err_link:
	rtnl_link_unregister(&a2tp_link_ops);
err_pernet:
	unregister_pernet_subsys(&a2tp_pernet_ops);
	return err;
}

static void __exit a2tp_exit(void)
{
	a2tp_srv_exit();
	rtnl_link_unregister(&a2tp_link_ops);
	unregister_pernet_subsys(&a2tp_pernet_ops);
}

module_init(a2tp_init);
module_exit(a2tp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("a2tp project");
MODULE_DESCRIPTION("a2tp kernel data plane: L2TPv3-over-UDP style Ethernet tunnel");
MODULE_VERSION("1.0");
MODULE_ALIAS_RTNL_LINK(A2TP_LINK_KIND);
MODULE_ALIAS_GENL_FAMILY(A2TP_GENL_NAME);	/* string concatenation */
