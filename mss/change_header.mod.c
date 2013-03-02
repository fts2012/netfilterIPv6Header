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
	{ 0x5eadf54a, "module_layout" },
	{ 0x85e90336, "kmalloc_caches" },
	{ 0xd0d8621b, "strlen" },
	{ 0xab49a59a, "sock_release" },
	{ 0x85df9b6c, "strsep" },
	{ 0xaf22ee5a, "nf_register_hook" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x734bd149, "netlink_kernel_create" },
	{ 0x50eedeb8, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x5152e605, "memcmp" },
	{ 0xb4390f9a, "mcount" },
	{ 0xdb5d998d, "ip_route_me_harder" },
	{ 0x8ec13a88, "netlink_unicast" },
	{ 0xf191b542, "init_net" },
	{ 0x7503df2e, "skb_copy_expand" },
	{ 0xd59a192, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x8b9fe4a7, "kfree_skb" },
	{ 0x83699014, "kmem_cache_alloc_trace" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x75c35888, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xe4346f71, "skb_put" },
	{ 0xc0e99c05, "sock_wfree" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "51B771F8C65B081B3AA6ED9");
