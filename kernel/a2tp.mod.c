#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcb8b6ec6, "kfree" },
	{ 0xa87fdb20, "dev_set_promiscuity" },
	{ 0xfc310354, "eth_validate_addr" },
	{ 0x2352b148, "timer_delete_sync" },
	{ 0x3d00653a, "ip_route_output_flow" },
	{ 0xe06e7bb6, "unregister_netdevice_queue" },
	{ 0xeb5b304f, "nf_conntrack_destroy" },
	{ 0x5ae9ee26, "__per_cpu_offset" },
	{ 0x5af09d8b, "_raw_spin_lock" },
	{ 0xe706beb8, "ether_setup" },
	{ 0xd272d446, "__fentry__" },
	{ 0x0b4f0302, "pskb_expand_head" },
	{ 0xabb3d0a5, "register_pernet_subsys" },
	{ 0xd4cf2bdf, "dev_addr_mod" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xd272d446, "dump_stack" },
	{ 0xe8213e80, "_printk" },
	{ 0x51905738, "do_trace_netlink_extack" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xc196991c, "netdev_rx_handler_unregister" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xff0106da, "refcount_warn_saturate" },
	{ 0x5af09d8b, "_raw_spin_unlock_bh" },
	{ 0x9479a1e8, "strnlen" },
	{ 0x6780c24b, "__alloc_skb" },
	{ 0x86d206f6, "__SCT__WARN_trap" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x2ced33a0, "rtnl_link_unregister" },
	{ 0xf2cbd78b, "ipv6_stub" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0xcb138788, "sk_skb_reason_drop" },
	{ 0x0092132d, "netlink_unicast" },
	{ 0x32feeafc, "mod_timer" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xdb4012a2, "nla_put" },
	{ 0x4f1e5fd0, "__list_del_entry_valid_or_report" },
	{ 0x86632fd6, "_find_next_bit" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xa291a12d, "unregister_pernet_subsys" },
	{ 0xb5c51982, "__cpu_possible_mask" },
	{ 0xb7f92a6c, "udp_tunnel_sock_release" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x5ff52f68, "nla_memcpy" },
	{ 0xf296206e, "nr_cpu_ids" },
	{ 0xcb811836, "__pskb_pull_tail" },
	{ 0x5dc6bd4b, "setup_udp_tunnel_sock" },
	{ 0x437afbbd, "udp_sock_create6" },
	{ 0x888b8f57, "strcmp" },
	{ 0x65ed6ca7, "skb_trim" },
	{ 0xfd285498, "unregister_netdevice_notifier" },
	{ 0x898d2244, "__dynamic_netdev_dbg" },
	{ 0x690cdb06, "free_percpu" },
	{ 0x058c185a, "jiffies" },
	{ 0x5c1c298f, "skb_scrub_packet" },
	{ 0xd343e1ed, "__dev_queue_xmit" },
	{ 0x23e7cd4a, "pcpu_alloc_noprof" },
	{ 0x4574d0c7, "__kmalloc_cache_noprof" },
	{ 0xab22a3e7, "udp_tunnel_xmit_skb" },
	{ 0xfd285498, "register_netdevice_notifier" },
	{ 0xd9bb798c, "dev_get_by_name" },
	{ 0x24380e4e, "skb_clone" },
	{ 0x5af09d8b, "_raw_spin_lock_bh" },
	{ 0x0d6267c8, "dst_release" },
	{ 0xd272d446, "rtnl_lock" },
	{ 0x6fa37c41, "netdev_rx_handler_register" },
	{ 0x02f9bbf0, "timer_init_key" },
	{ 0x224a53e7, "get_random_bytes" },
	{ 0x4dc233c5, "genl_unregister_family" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xa20c3799, "__nla_parse" },
	{ 0xbf0bdc57, "genl_register_family" },
	{ 0x5af09d8b, "_raw_spin_unlock" },
	{ 0x12ca6142, "ktime_get_with_offset" },
	{ 0x7738ad14, "dev_forward_skb" },
	{ 0xc4fee520, "kmalloc_caches" },
	{ 0xd272d446, "synchronize_net" },
	{ 0xd5eb29bd, "register_netdevice" },
	{ 0xd272d446, "rtnl_unlock" },
	{ 0xdc352a3b, "__list_add_valid_or_report" },
	{ 0x28e957d4, "eth_mac_addr" },
	{ 0xf122d403, "skb_put" },
	{ 0xaf1852f3, "netdev_is_rx_handler_busy" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0x534ed5f3, "__msecs_to_jiffies" },
	{ 0x0763e520, "ip6_dst_hoplimit" },
	{ 0x9d80d654, "consume_skb" },
	{ 0x11bd348d, "nla_put_64bit" },
	{ 0xafae58b8, "udp_sock_create4" },
	{ 0x21ba2cca, "__skb_ext_del" },
	{ 0xbd03ed67, "this_cpu_off" },
	{ 0xa5322d49, "udp_tunnel6_xmit_skb" },
	{ 0xd4ec5a9a, "rtnl_link_register" },
	{ 0x9ce5bb4a, "genlmsg_put" },
	{ 0xfbe7861b, "memcpy" },
	{ 0xe9196a28, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xcb8b6ec6,
	0xa87fdb20,
	0xfc310354,
	0x2352b148,
	0x3d00653a,
	0xe06e7bb6,
	0xeb5b304f,
	0x5ae9ee26,
	0x5af09d8b,
	0xe706beb8,
	0xd272d446,
	0x0b4f0302,
	0xabb3d0a5,
	0xd4cf2bdf,
	0x5a844b26,
	0xd272d446,
	0xe8213e80,
	0x51905738,
	0xbd03ed67,
	0xc196991c,
	0xd272d446,
	0xff0106da,
	0x5af09d8b,
	0x9479a1e8,
	0x6780c24b,
	0x86d206f6,
	0x90a48d82,
	0x2ced33a0,
	0xf2cbd78b,
	0xd272d446,
	0xcb138788,
	0x0092132d,
	0x32feeafc,
	0xbd03ed67,
	0xdb4012a2,
	0x4f1e5fd0,
	0x86632fd6,
	0xe54e0a6b,
	0xa291a12d,
	0xb5c51982,
	0xb7f92a6c,
	0xd272d446,
	0x5ff52f68,
	0xf296206e,
	0xcb811836,
	0x5dc6bd4b,
	0x437afbbd,
	0x888b8f57,
	0x65ed6ca7,
	0xfd285498,
	0x898d2244,
	0x690cdb06,
	0x058c185a,
	0x5c1c298f,
	0xd343e1ed,
	0x23e7cd4a,
	0x4574d0c7,
	0xab22a3e7,
	0xfd285498,
	0xd9bb798c,
	0x24380e4e,
	0x5af09d8b,
	0x0d6267c8,
	0xd272d446,
	0x6fa37c41,
	0x02f9bbf0,
	0x224a53e7,
	0x4dc233c5,
	0xe4de56b4,
	0xa20c3799,
	0xbf0bdc57,
	0x5af09d8b,
	0x12ca6142,
	0x7738ad14,
	0xc4fee520,
	0xd272d446,
	0xd5eb29bd,
	0xd272d446,
	0xdc352a3b,
	0x28e957d4,
	0xf122d403,
	0xaf1852f3,
	0xd272d446,
	0x534ed5f3,
	0x0763e520,
	0x9d80d654,
	0x11bd348d,
	0xafae58b8,
	0x21ba2cca,
	0xbd03ed67,
	0xa5322d49,
	0xd4ec5a9a,
	0x9ce5bb4a,
	0xfbe7861b,
	0xe9196a28,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"kfree\0"
	"dev_set_promiscuity\0"
	"eth_validate_addr\0"
	"timer_delete_sync\0"
	"ip_route_output_flow\0"
	"unregister_netdevice_queue\0"
	"nf_conntrack_destroy\0"
	"__per_cpu_offset\0"
	"_raw_spin_lock\0"
	"ether_setup\0"
	"__fentry__\0"
	"pskb_expand_head\0"
	"register_pernet_subsys\0"
	"dev_addr_mod\0"
	"__x86_indirect_thunk_rax\0"
	"dump_stack\0"
	"_printk\0"
	"do_trace_netlink_extack\0"
	"__ref_stack_chk_guard\0"
	"netdev_rx_handler_unregister\0"
	"__stack_chk_fail\0"
	"refcount_warn_saturate\0"
	"_raw_spin_unlock_bh\0"
	"strnlen\0"
	"__alloc_skb\0"
	"__SCT__WARN_trap\0"
	"__ubsan_handle_out_of_bounds\0"
	"rtnl_link_unregister\0"
	"ipv6_stub\0"
	"__rcu_read_unlock\0"
	"sk_skb_reason_drop\0"
	"netlink_unicast\0"
	"mod_timer\0"
	"random_kmalloc_seed\0"
	"nla_put\0"
	"__list_del_entry_valid_or_report\0"
	"_find_next_bit\0"
	"__fortify_panic\0"
	"unregister_pernet_subsys\0"
	"__cpu_possible_mask\0"
	"udp_tunnel_sock_release\0"
	"__x86_return_thunk\0"
	"nla_memcpy\0"
	"nr_cpu_ids\0"
	"__pskb_pull_tail\0"
	"setup_udp_tunnel_sock\0"
	"udp_sock_create6\0"
	"strcmp\0"
	"skb_trim\0"
	"unregister_netdevice_notifier\0"
	"__dynamic_netdev_dbg\0"
	"free_percpu\0"
	"jiffies\0"
	"skb_scrub_packet\0"
	"__dev_queue_xmit\0"
	"pcpu_alloc_noprof\0"
	"__kmalloc_cache_noprof\0"
	"udp_tunnel_xmit_skb\0"
	"register_netdevice_notifier\0"
	"dev_get_by_name\0"
	"skb_clone\0"
	"_raw_spin_lock_bh\0"
	"dst_release\0"
	"rtnl_lock\0"
	"netdev_rx_handler_register\0"
	"timer_init_key\0"
	"get_random_bytes\0"
	"genl_unregister_family\0"
	"__ubsan_handle_load_invalid_value\0"
	"__nla_parse\0"
	"genl_register_family\0"
	"_raw_spin_unlock\0"
	"ktime_get_with_offset\0"
	"dev_forward_skb\0"
	"kmalloc_caches\0"
	"synchronize_net\0"
	"register_netdevice\0"
	"rtnl_unlock\0"
	"__list_add_valid_or_report\0"
	"eth_mac_addr\0"
	"skb_put\0"
	"netdev_is_rx_handler_busy\0"
	"__rcu_read_lock\0"
	"__msecs_to_jiffies\0"
	"ip6_dst_hoplimit\0"
	"consume_skb\0"
	"nla_put_64bit\0"
	"udp_sock_create4\0"
	"__skb_ext_del\0"
	"this_cpu_off\0"
	"udp_tunnel6_xmit_skb\0"
	"rtnl_link_register\0"
	"genlmsg_put\0"
	"memcpy\0"
	"module_layout\0"
;

MODULE_INFO(depends, "udp_tunnel,ip6_udp_tunnel");


MODULE_INFO(srcversion, "04ECF4FFFBBEBE54646C553");
