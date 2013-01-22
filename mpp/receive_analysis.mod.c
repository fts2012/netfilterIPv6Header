#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x5eadf54a, "module_layout" },
	{ 0x85e90336, "kmalloc_caches" },
	{ 0xd0d8621b, "strlen" },
	{ 0x85df9b6c, "strsep" },
	{ 0x50eedeb8, "printk" },
	{ 0x5152e605, "memcmp" },
	{ 0xb4390f9a, "mcount" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x83699014, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "7AF8CA4A9945BA25C2E8CE8");
