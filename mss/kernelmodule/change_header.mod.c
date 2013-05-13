#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x68d372d2, "module_layout" },
	{ 0x794a2c29, "kmalloc_caches" },
	{ 0xd0d8621b, "strlen" },
	{ 0x2441ddb, "sock_release" },
	{ 0x85df9b6c, "strsep" },
	{ 0x3a1beaac, "nf_register_hook" },
	{ 0x91715312, "sprintf" },
	{ 0x7d11c268, "jiffies" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x38b12fd0, "netlink_kernel_create" },
	{ 0x50eedeb8, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6c2e3320, "strncmp" },
	{ 0xa2b3b417, "ip_route_me_harder" },
	{ 0x3f18dce5, "netlink_unicast" },
	{ 0xba2bf109, "init_net" },
	{ 0x50e7037, "skb_copy_expand" },
	{ 0xbfb5c0f5, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xa2e715a, "kfree_skb" },
	{ 0x3f9b9190, "kmem_cache_alloc_trace" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0xa7043528, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xbebe21f0, "skb_put" },
	{ 0x5b124237, "sock_wfree" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "BB0A2BC71AB029145FB3845");
