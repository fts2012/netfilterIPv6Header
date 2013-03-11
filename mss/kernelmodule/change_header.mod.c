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
	{ 0xbd144d5, "sock_release" },
	{ 0x85df9b6c, "strsep" },
	{ 0xbc555ba4, "nf_register_hook" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xc2e0eb00, "netlink_kernel_create" },
	{ 0x50eedeb8, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x5152e605, "memcmp" },
	{ 0xb4390f9a, "mcount" },
	{ 0x9e0cf698, "ip_route_me_harder" },
	{ 0xbcac58ff, "netlink_unicast" },
	{ 0x50fd15f2, "init_net" },
	{ 0xfe77bec1, "skb_copy_expand" },
	{ 0x87957d03, "__alloc_skb" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xec778bbd, "kfree_skb" },
	{ 0x3f9b9190, "kmem_cache_alloc_trace" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x4b324b89, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x29158b36, "skb_put" },
	{ 0x448bdc16, "sock_wfree" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "F4D5B7144FED302B3E6A52C");
