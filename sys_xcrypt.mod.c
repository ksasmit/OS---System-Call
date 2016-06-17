#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
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
	{ 0x225980c, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x4c4fef19, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0x2bc95bd4, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xaf963fcb, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x46991692, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x94867424, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0xfe90a9d0, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0xe67d81ba, __VMLINUX_SYMBOL_STR(strlen_user) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0x5e3b3ab4, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x56cb2648, __VMLINUX_SYMBOL_STR(sysptr) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "219ECC1EB1B40B5CBC20EB6");
