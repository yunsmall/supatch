// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 yunsmall */
/*
 * kpm_host.c - resident KPM loader agent (LKM) for pure Magisk / temp-root.
 *
 * This module is NOT a one-shot loader.  It registers a generic netlink
 * family (no /dev node) as the control channel
 * and stays resident; the .kpm ELF image is delivered later as a whole
 * memory buffer via ioctl(LOAD), so no firmware path / filp_open / file I/O
 * is used anywhere.
 *
 * The only bootstrap data needed from userspace is the address of the
 * kernel's kallsyms_lookup_name (passed via the kpm_syms live-table
 * module parameter, e.g. kpm_syms="kallsyms_lookup_name:0xffff008000123456").
 * Everything else (module_alloc, set_memory_*, CFI shadow, kf_* slots) is
 * resolved at runtime through that anchor.  The kprobe fallback that the
 * classic adb-net stack used is gone entirely.
 *
 * The rest is KernelPatch compatible: parses the .kpm ELF64 relocatable
 * image, resolves symbols + aarch64 RELA relocations, then calls .kpm.init.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/elf.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/moduleloader.h>
#include <linux/stop_machine.h>
#include <linux/log2.h>
#include <linux/overflow.h>

#include "kpm_host.h"
#include "kpm_insn.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("suzhi, yunsmall");
MODULE_DESCRIPTION("resident KPM loader agent for temp-root environments");

/*
 * Live symbol table (bootstrap anchor).  Format is a comma separated list of
 *   kpm_syms="name:0xffff0080...,name2:0x..."
 * Minimal entry required to come up: kallsyms_lookup_name.  All other
 * runtime names are then resolved through it.  Entries here always win over
 * the runtime lookup in klookup().
 */
static char *kpm_syms = NULL;
module_param(kpm_syms, charp, 0644);

/* GKI does not export __ubsan_handle_cfi_check_fail_abort; every
 * CFI-instrumented module ships its own copy (see weak __cfi_check_fail in
 * in-tree drivers).  This is the -ftrap-function slot for our module's own
 * indirect-call type-check failures.  Direct calls are never CFI-checked, so
 * no recursion here.
 *
 * The .kpm image carries NO CFI metadata (built with a bare freestanding
 * clang), so kernel CFI instrumentation around e.g. workqueue callbacks that
 * reenter KPM code WILL trip the type check.  Panicking there turns a benign
 * instrumentation mismatch into a device reboot.  We degrade the handler to
 * log-and-return so the KPM keeps running; a rate-limited counter avoids log
 * flooding. */
static unsigned int kpm_cfi_flags;
__attribute__((no_sanitize("cfi")))
void __ubsan_handle_cfi_check_fail_abort(void *data, void *ptr)
{
	(void)data;
	if (kpm_cfi_flags++)
		pr_warn_ratelimited("kpm_host: CFI mismatch (target: %pS), ignored\n", ptr);
	else
		pr_warn("kpm_host: CFI mismatch (target: %pS), ignored (no panic)\n", ptr);
}

/* The device kernel was built with a different Clang than ours, so the CFI
 * type hashes computed by our LTO pass (clang-r416183) do not match the ones
 * stored in device functions.  Indirect calls that cross the module boundary
 * (our slots -> real kernel functions, or -> the .kpm image whose code does
 * not carry CFI metadata at all) would fail __cfi_check and panic.  Only
 * functions that perform such calls are exempted; everything else stays
 * instrumented, and - critically - module_init/module_exit keep their
 * __cfi_jt_* canonical-jump-table entries so the device loader can still
 * invoke them safely. */
#define __kpm_nocfi __attribute__((no_sanitize("cfi")))

/* ------------------------------------------------------------------ */
/* symbol resolution backend                                          */
/* ------------------------------------------------------------------ */

/* layout globals expected by the KPM's current.h / ksyms.h */
int thread_size = 16384;
int thread_info_in_task = 1;
int sp_el0_is_current = 1;
int sp_el0_is_thread_info = 0;
int task_in_thread_info_offset = 0;
int stack_in_task_offset = 0;
int stack_end_offset = 0;
unsigned int kver = LINUX_VERSION_CODE;
unsigned int kpver = 0x00000001;

/* kf_* function pointer globals resolved by the KPM itself at init via
 * kallsyms_lookup_name (INIT_USE_KALLSYMS_LOOKUP_NAME).  The .kpm sees
 * &kf_memcpy etc., so we only need to provide the symbol addresses. */
void *(*kf_memcpy)(void *, const void *, size_t);
void *(*kf_memset)(void *, int, size_t);
char *(*kf_strsep)(char **, const char *);
int (*kf_kstrtoull)(const char *, unsigned int, unsigned long long *);
int (*kf_snprintf)(char *, size_t, const char *, ...);
size_t (*kf_strlen)(const char *);
int (*kf_memcmp)(const void *, const void *, size_t);
char *(*kf_strncat)(char *, const char *, size_t);

/* printk is declared by the KPM headers as a function-pointer *variable*
 * (extern void (*printk)(...)), so a KPM references it with adrp+ldr+blr and
 * loads the pointer stored *at* the symbol address.  Export the address of a
 * writable slot (not the function's own code address). */
int (*host_printk)(const char *fmt, ...);

/* compat_copy_to_user is branched to directly (R_AARCH64_CALL26) and must be
 * a real function.  Mirror KernelPatch's ABI: full success -> n, else 0. */
static unsigned long (*host_copy_to_user)(void __user *to, const void *from,
					  unsigned long n);
static __kpm_nocfi int host_compat_copy_to_user(void __user *to, const void *from, int n)
{
	if (!host_copy_to_user)
		return -ENOSYS;
	return host_copy_to_user(to, from, n) ? 0 : n;
}

/* KPM 镜像和 agent text 可能相距超过 ±128MB，KPM 直调 compat_copy_to_user
 * 会触发 CALL26 重定位溢出，所以额外导出一个函数指针变量供 KPM 间接调用。 */
static int (*host_compat_copy_to_user_ptr)(void __user *to, const void *from, int n);

/* anchor filled from the kpm_syms live table (kprobe-free) */
static unsigned long (*kallsyms_lookup_name_fn)(const char *) = NULL;

static struct {
	const char *name;
	void *addr;
} host_exports[] = {
	{ "kver", &kver },
	{ "kpver", &kpver },
	{ "thread_size", &thread_size },
	{ "thread_info_in_task", &thread_info_in_task },
	{ "sp_el0_is_current", &sp_el0_is_current },
	{ "sp_el0_is_thread_info", &sp_el0_is_thread_info },
	{ "task_in_thread_info_offset", &task_in_thread_info_offset },
	{ "stack_in_task_offset", &stack_in_task_offset },
	{ "stack_end_offset", &stack_end_offset },
	{ "printk", &host_printk },
	{ "kallsyms_lookup_name", &kallsyms_lookup_name_fn },
	{ "compat_copy_to_user", (void *)host_compat_copy_to_user },
	{ "compat_copy_to_user_ptr", &host_compat_copy_to_user_ptr },
	{ "kf_memcpy", &kf_memcpy },
	{ "kf_memset", &kf_memset },
	{ "kf_strsep", &kf_strsep },
	{ "kf_kstrtoull", &kf_kstrtoull },
	{ "kf_snprintf", &kf_snprintf },
	{ "kf_strlen", &kf_strlen },
	{ "kf_memcmp", &kf_memcmp },
	{ "kf_strncat", &kf_strncat },
};

static void *(*host_module_alloc)(unsigned long);
static void (*host_module_memfree)(void *);
static int (*host_set_memory_rw)(unsigned long, int);
static int (*host_set_memory_ro)(unsigned long, int);
static int (*host_set_memory_x)(unsigned long, int);
static void (*host_kick_all_cpus_sync)(void);

/* 6.12 起 module_alloc 被 execmem 子系统取代。kCFI 的类型 hash 按参数的
 * 类型名计算，必须用内核的 enum execmem_type 原类型；写成 int 或
 * unsigned int 都会 CFI 失败（已实测两次）。 */
/* execmem 从 6.10 起进入主线（v6.9 没有 include/linux/execmem.h，v6.10 有），
 * 因此这里的版本门槛是 6.10 而不是 6.12。 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#include <linux/execmem.h>
typedef enum execmem_type kpm_execmem_type_t;
#else
typedef int kpm_execmem_type_t;
#define EXECMEM_DEFAULT 0
#endif
static void *(*host_execmem_alloc)(kpm_execmem_type_t type, unsigned long size);

/* 6.12 的 vmlinux text 不在 set_memory_rw 允许的模块/vmalloc 区域，
 * 必须走 fixmap 的 aarch64_insn_patch_text_nosync（写 + cache flush）。 */
static int (*host_insn_patch)(void *addr, u32 insn);

static __kpm_nocfi void *kpm_alloc_exec(unsigned long size)
{
	if (host_module_alloc)
		return host_module_alloc(size);
	if (host_execmem_alloc)
		return host_execmem_alloc(EXECMEM_DEFAULT, size);
	return NULL;
}

/* __cfi_slowpath_diag neuter — nuclear guarantee for kernel→KPM callbacks.
 *
 * Even after shadow registration (kpm_cfi_register), the shadow may silently
 * fail on OEM kernels where CONFIG_CFI_CLANG_SHADOW=n or the check page
 * lands in the direct-map region.  The neuter patches __cfi_slowpath_diag
 * (and __cfi_slowpath where present) to `ret` at load, restoring on exit.
 *
 * Classic CFI semantics: check fn returning from slowpath means the
 * callsite proceeds with the actual indirect call — so a *working* shadow
 * + no-op __cfi_check is the happy path.  But if find_check_fn()==NULL
 * (shadow absent), handle_cfi_failure() panics unconditionally — this is
 * the unconditional death path that neuter eliminates.
 *
 * On kernels with CONFIG_CFI_CLANG_SHADOW=y AND the shadow registered
 * successfully, neuter is harmless (the check already passes inline before
 * reaching slowpath).  On broken shadow, neuter is the only safety net. */
static unsigned long kpm_slowpath_diag;
static unsigned long kpm_slowpath_plain;
static u32 kpm_slowpath_diag_orig;
static u32 kpm_slowpath_plain_orig;
static bool kpm_slowpath_patched;
/* restore 必须用与 patch 相同的页数，否则会把相邻的 rodata 页一起改权限 */
static int kpm_slowpath_diag_npages;
static int kpm_slowpath_plain_npages;

/* __cfi_slowpath is the sole slow-path entry for the kernel's CFI shadow
 * check.  The .kpm image is built with a bare freestanding clang and carries
 * no CFI metadata, so any kernel-side indirect call that re-enters KPM code
 * (e.g. the workqueue handoff inside suzhiDD's rearm path) fails the check
 * and, in the stock kernel, lands in __cfi_slowpath -> __ubsan_handle_cfi_
 * check_fail_abort -> panic().  A module-declared strong symbol cannot
 * shadow that handler (the in-kernel call site is bound to the vmlinux copy
 * at LTO), so the only reliable lever is to neuter __cfi_slowpath itself:
 * replace its prologue with `ret`.  We keep the original word to restore it
 * at module exit. */
/* CFI handling for the .kpm image.
 *
 * The device kernel is built with LLVM CFI + shadow (CONFIG_CFI_CLANG_SHADOW).
 * kernel/cfi.c routes any indirect call that cannot be checked inline to
 * __cfi_slowpath(id, ptr, diag), which resolves a check function for the
 * TARGET address:
 *
 *   find_check_fn(ptr):
 *     - shadow table (vtmalloc module area): shadow[slot] -> that module's
 *       __cfi_check, when the module was registered via cfi_module_add()
 *     - vmlinux text  -> __cfi_check
 *     - loaded module (via __module_address) -> mod->cfi_check
 *     - otherwise     -> NULL  => handle_cfi_failure() => PANIC
 *
 * Our .kpm image is loaded out-of-band (not via the module loader), so it has
 * no __cfi_check of its own and nothing registered in the shadow.  Kernel
 * callbacks that reenter KPM code therefore hit find_check_fn() == NULL and
 * panic unconditionally - the failure is not about type hashes, it is about a
 * missing check function for the KPM address range.
 *
 * The clean fix (mirroring what kernel/module.c does for real modules) is to
 * register the KPM's address range in the CFI shadow ourselves via
 * cfi_module_add().  We supply a synthetic struct module whose cfi_check is a
 * page-aligned no-op (single `ret`): find_check_fn() then returns it and the
 * indirect call is accepted. */
/* Android 5.10 的 CFI shadow 接口是两参：cfi_module_add(mod, base)，
 * 范围由 mod->core_layout.size 推导；6.10+ 不走这个函数。 */
static void (*host_cfi_module_add)(struct module *, unsigned long);
static void (*host_cfi_module_remove)(struct module *, unsigned long);
static u32 kpm_cfi_check_word __maybe_unused = 0xd65f03c0; /* aarch64 `ret` */
/* slowpath neuter 是全局内核 text 补丁，多个 KPM 共用；最后一个卸载时恢复 */
static unsigned int kpm_cfi_users;

static __kpm_nocfi void resolve_cfi_shadow(void)
{
	if (kallsyms_lookup_name_fn)
		host_cfi_module_add = (void *)kallsyms_lookup_name_fn("cfi_module_add");
	host_cfi_module_remove =
		host_cfi_module_add ?
		(void *)kallsyms_lookup_name_fn("cfi_module_remove") : NULL;
	pr_alert("kpm: cfi_module_add=%px cfi_module_remove=%px\n",
		(void *)host_cfi_module_add, (void *)host_cfi_module_remove);
}

/* Allocate a page-aligned no-op check function and register the KPM image
 * range in the CFI shadow.  Must be called while the image is still RWX (i.e.
 * between l4 and the init call).  Returns 0 on success. */
static __kpm_nocfi int kpm_cfi_register(struct kpm_image *img,
					unsigned long base, unsigned long size)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
	struct module *m;
	void *check;

	/* 注册后必须能移除，否则 shadow 条目会指向已释放的镜像 */
	if (!host_cfi_module_add || !host_cfi_module_remove)
		return -ENOSYS;

	/* check page 必须和 KPM 一样位于 module/vmalloc 区；direct map 的页
	 * 不在 CFI shadow 覆盖范围内，注册也不会生效，直接放弃并交给
	 * slowpath neuter 兜底。 */
	check = kpm_alloc_exec(PAGE_SIZE);
	if (!check)
		return -ENOSYS;
	img->cfi_check_page = check;
	WRITE_ONCE(*(u32 *)img->cfi_check_page, kpm_cfi_check_word);
	flush_icache_range((unsigned long)img->cfi_check_page,
			   (unsigned long)img->cfi_check_page + 4);
	if (host_set_memory_x)
		host_set_memory_x((unsigned long)img->cfi_check_page, 1);

	img->cfi_mod = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!img->cfi_mod) {
		host_module_memfree(img->cfi_check_page);
		img->cfi_check_page = NULL;
		return -ENOMEM;
	}

	m = img->cfi_mod;
#ifdef CONFIG_CFI_CLANG
	m->cfi_check = (cfi_check_fn)img->cfi_check_page;
#endif

	/* 只注册 KPM 镜像本身的区间。check page 只是 shadow 表项的值，
	 * 不需要（也不能）并进注册范围——并集会把中间的其他分配也盖进去，
	 * 多个 KPM 的并集还会互相重叠，卸载时把别人的 shadow 一起清掉。 */
	{
		unsigned long regbase = base & PAGE_MASK;
		unsigned long end = ALIGN(base + size, PAGE_SIZE);

		m->core_layout.base = (void *)regbase;
		m->core_layout.text_size = size;
		m->core_layout.size = end - regbase;
		img->cfi_regbase = regbase;
		host_cfi_module_add(m, regbase);
		pr_alert("kpm: cfi shadow registered regbase=%px base=%px size=%lu check=%px\n",
			(void *)regbase, (void *)base, size, img->cfi_check_page);
	}
	return 0;
#else
	/* 6.10 起 struct module 改为 module_memory 数组，6.12 的 kCFI 也没有
	 * shadow，不需要注册；CFI 失败由 report_cfi_failure 补丁兜底。 */
	(void)base;
	(void)size;
	return -ENOSYS;
#endif
}

static __kpm_nocfi void kpm_cfi_unregister(struct kpm_image *img)
{
	if (host_cfi_module_remove && img->cfi_mod && img->cfi_regbase)
		host_cfi_module_remove(img->cfi_mod, img->cfi_regbase);
	if (img->cfi_mod) {
		kfree(img->cfi_mod);
		img->cfi_mod = NULL;
	}
	if (img->cfi_check_page) {
		if (host_module_memfree)
			host_module_memfree(img->cfi_check_page);
		img->cfi_check_page = NULL;
	}
	img->cfi_regbase = 0;
	pr_alert("kpm: cfi shadow unregistered\n");
}

static __kpm_nocfi unsigned long klookup(const char *name);

/* ------------------------------------------------------------------ */
/* live symbol table (kpm_syms param, replaces the kprobe bootstrap)  */
/* ------------------------------------------------------------------ */

struct kpm_live_entry {
	const char *name;
	unsigned long addr;
};

static struct kpm_live_entry kpm_live[KPM_LIVE_MAX];
static unsigned int kpm_live_n;

static void kpm_live_parse(const char *str)
{
	const char *p = str;
	unsigned int n = 0;

	if (!str)
		return;

	while (p && *p && n < KPM_LIVE_MAX) {
		const char *comma = strchr(p, ',');
		const char *colon = strchr(p, ':');
		char name[128];
		size_t namelen;
		unsigned long long tmp;
		unsigned long addr;

		if (!colon || (comma && colon > comma))
			break;
		namelen = colon - p;
		if (namelen == 0 || namelen >= sizeof(name))
			break;
		memcpy(name, p, namelen);
		name[namelen] = '\0';
		if (sscanf(colon + 1, "%llx", &tmp) != 1) {
			p = comma ? comma + 1 : NULL;
			continue;
		}
		addr = (unsigned long)tmp;
		if (!addr) {
			/* 地址为 0 时必须推进指针，否则死循环卡住模块加载 */
			p = comma ? comma + 1 : NULL;
			continue;
		}
		kpm_live[n].name = kstrdup(name, GFP_KERNEL);
		kpm_live[n].addr = addr;
		n++;
		p = comma ? comma + 1 : NULL;
	}
	kpm_live_n = n;
	pr_alert("kpm: live table parsed %u entries\n", kpm_live_n);
}

static void kpm_live_free(void)
{
	unsigned int i;

	for (i = 0; i < kpm_live_n; i++)
		kfree(kpm_live[i].name);
	kpm_live_n = 0;
}

static __kpm_nocfi unsigned long kpm_live_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < kpm_live_n; i++) {
		if (kpm_live[i].name && strcmp(kpm_live[i].name, name) == 0)
			return kpm_live[i].addr;
	}
	return 0;
}

/* Patch a single kernel-text word to `ret`, remembering the original for
 * restore.  Returns true on success.  Best-effort: skips cleanly when the
 * symbol is absent or the text page cannot be made writable. */
static __kpm_nocfi bool kpm_cfi_patch_ret(unsigned long *addr, u32 *orig,
					  int *npages_out)
{
	u32 word;
	int rc;
	int npages;

	if (!addr || !*addr)
		return false;
	if (!host_set_memory_rw) {
		pr_alert("kpm: cfi slowpath neuter SKIPPED (%px): set_memory_rw unresolved\n",
			 (void *)*addr);
		return false;
	}
	/* 4 字节补丁一般只跨 1 页，只有落在页尾时才是 2 页 */
	npages = ((*addr & ~PAGE_MASK) + 4 > PAGE_SIZE) ? 2 : 1;
	word = *(u32 *)*addr;
	rc = host_set_memory_rw(*addr & PAGE_MASK, npages);
	if (rc) {
		pr_alert("kpm: cfi slowpath neuter SKIPPED (%px): set_memory_rw rc=%d\n",
			 (void *)*addr, rc);
		return false;
	}
	*orig = word;
	*npages_out = npages;
	WRITE_ONCE(*(u32 *)*addr, 0xd65f03c0); /* aarch64 `ret` */
	flush_icache_range(*addr, *addr + 4);
	if (host_kick_all_cpus_sync)
		host_kick_all_cpus_sync();
	if (host_set_memory_ro) {
		int rorc = host_set_memory_ro(*addr & PAGE_MASK, npages);

		if (rorc)
			pr_warn("kpm: set_memory_ro rc=%d (text stays RW)\n", rorc);
	}
	pr_alert("kpm: cfi slowpath NEUTERED %px (0x%08x -> ret)\n",
		 (void *)*addr, word);
	return true;
}

/* 8 字节补丁必须停住其他 CPU：两条指令分开写时，中间状态可能让并发
 * 执行者在 push 栈后直接 ret（sp 未恢复）。4 字节补丁是单条对齐 store，
 * 原子，不需要停机。 */
struct kpm_patch_ctx {
	unsigned long addr;
	u64 word;
};

static int kpm_patch_word_cb(void *data)
{
	struct kpm_patch_ctx *ctx = data;
	int rc;

	if (host_insn_patch) {
		rc = host_insn_patch((void *)ctx->addr, (u32)ctx->word);
		if (!rc)
			rc = host_insn_patch((void *)(ctx->addr + 4),
					     (u32)(ctx->word >> 32));
		return rc;
	}

	/* 旧内核回退：调用者已 set_memory_rw，直接写两条 4 字节；
	 * stop_machine 已停住其他 CPU，中间状态不会被观察到。 */
	WRITE_ONCE(*(u32 *)ctx->addr, (u32)ctx->word);
	WRITE_ONCE(*(u32 *)(ctx->addr + 4), (u32)(ctx->word >> 32));
	flush_icache_range(ctx->addr, ctx->addr + 8);
	return 0;
}

static __kpm_nocfi int kpm_patch_word(unsigned long addr, u64 word)
{
	struct kpm_patch_ctx ctx = { .addr = addr, .word = word };

	return stop_machine(kpm_patch_word_cb, &ctx, NULL);
}

static __kpm_nocfi bool kpm_cfi_patch_report_failure(void);
static __kpm_nocfi void kpm_cfi_restore_report_failure(void);

/* 6.12 上如果没有成功关掉 CFI 失败路径，加载 KPM 后第一次内核回调就会
 * die()，所以加载前必须检查返回值并拒绝加载。 */

/* Neutering __cfi_slowpath_diag (+__cfi_slowpath where present).  Must run
 * before the KPM init_fn so no kernel callback into KPM code can ever hit
 * the CFI panic path.  Kept active for the whole module lifetime, restored
 * at exit. */
static __kpm_nocfi bool kpm_cfi_neuter_slowpath(void)
{
	unsigned long addr;
	u32 orig;
	bool one = false;
	bool report_ok;

	addr = klookup("__cfi_slowpath_diag");
	if (addr) {
		orig = 0;
		if (kpm_cfi_patch_ret(&addr, &orig,
				      &kpm_slowpath_diag_npages)) {
			kpm_slowpath_diag = addr;
			kpm_slowpath_diag_orig = orig;
			one = true;
		}
	}

	addr = klookup("__cfi_slowpath");
	if (addr && addr != kpm_slowpath_diag) {
		orig = 0;
		if (kpm_cfi_patch_ret(&addr, &orig,
				      &kpm_slowpath_plain_npages)) {
			kpm_slowpath_plain = addr;
			kpm_slowpath_plain_orig = orig;
			one = true;
		}
	}

	if (one)
		kpm_slowpath_patched = true;
	else
		pr_alert("kpm: cfi slowpath neuter: neither __cfi_slowpath_diag nor __cfi_slowpath resolved!\n");

	report_ok = kpm_cfi_patch_report_failure();
	return one || report_ok;
}

/* 6.12 的 kCFI 没有 shadow/slowpath：间接调用检查失败会走 BRK ->
 * cfi_handler() -> report_cfi_failure()，返回 BUG 时直接 die()。KPM 镜像
 * 没有 CFI 元数据，内核回调进 KPM 必然失败，所以把 report_cfi_failure
 * 入口改成 `mov w0, #1; ret`（返回 BUG_TRAP_TYPE_WARN），cfi_handler 会
 * 跳过 BRK 继续执行，等效于只对失败路径关闭 CFI。 */
static unsigned long kpm_report_failure;
static u64 kpm_report_failure_orig;

static __kpm_nocfi bool kpm_cfi_patch_report_failure(void)
{
	unsigned long addr = klookup("report_cfi_failure");
	u32 w0, w1;
	int rc;

	if (!addr) {
		pr_alert("kpm: report_cfi_failure not found, skip kCFI neuter\n");
		return false;
	}
	if (!host_insn_patch && !host_set_memory_rw) {
		pr_alert("kpm: no text patch interface, skip kCFI neuter\n");
		return false;
	}

	w0 = *(u32 *)addr;
	w1 = *(u32 *)(addr + 4);
	if (!host_insn_patch) {
		rc = host_set_memory_rw(addr & PAGE_MASK, 2);
		if (rc) {
			pr_alert("kpm: report_cfi_failure patch SKIPPED (%px): rc=%d\n",
				 (void *)addr, rc);
			return false;
		}
	}
	kpm_report_failure = addr;
	kpm_report_failure_orig = ((u64)w1 << 32) | w0;
	/* 地址只有 4 字节对齐，必须停机后整体写入，避免并发执行到
	 * "mov w0,#1 + 原第二条指令"的中间状态。 */
	rc = kpm_patch_word(addr,
			    ((u64)0xd65f03c0ULL << 32) | 0x0000000052800020ULL);
	if (rc) {
		pr_err("kpm: report_cfi_failure patch failed rc=%d\n", rc);
		/* 补丁没写成，把刚设为 RW 的 text 页恢复为 RO */
		if (!host_insn_patch && host_set_memory_ro) {
			int rorc = host_set_memory_ro(addr & PAGE_MASK, 2);

			if (rorc)
				pr_warn("kpm: set_memory_ro rc=%d (text stays RW)\n", rorc);
		}
		kpm_report_failure = 0;
		kpm_report_failure_orig = 0;
		return false;
	}
	if (host_kick_all_cpus_sync)
		host_kick_all_cpus_sync();
	if (!host_insn_patch && host_set_memory_ro) {
		int rorc = host_set_memory_ro(addr & PAGE_MASK, 2);

		if (rorc)
			pr_warn("kpm: set_memory_ro rc=%d (text stays RW)\n", rorc);
	}
	pr_alert("kpm: report_cfi_failure NEUTERED %px (0x%08x%08x -> warn/ret)\n",
		 (void *)addr, w1, w0);
	return true;
}

static __kpm_nocfi void kpm_cfi_restore_report_failure(void)
{
	unsigned long addr = kpm_report_failure;
	u64 orig = kpm_report_failure_orig;
	int rc;

	if (!addr)
		return;
	rc = (!host_insn_patch && host_set_memory_rw) ?
		host_set_memory_rw(addr & PAGE_MASK, 2) : 0;
	if (rc) {
		pr_alert("kpm: report_cfi_failure restore SKIPPED (%px): rc=%d\n",
			 (void *)addr, rc);
		/* 放弃恢复并清零，避免下次 LOAD 把已 patch 的值当成原始值 */
		kpm_report_failure = 0;
		kpm_report_failure_orig = 0;
		return;
	}
	rc = kpm_patch_word(addr, orig);
	if (rc) {
		pr_err("kpm: report_cfi_failure restore failed rc=%d\n", rc);
		kpm_report_failure = 0;
		kpm_report_failure_orig = 0;
		return;
	}
	if (host_kick_all_cpus_sync)
		host_kick_all_cpus_sync();
	if (!host_insn_patch && host_set_memory_ro) {
		int rorc = host_set_memory_ro(addr & PAGE_MASK, 2);

		if (rorc)
			pr_warn("kpm: set_memory_ro rc=%d (text stays RW)\n", rorc);
	}
	pr_alert("kpm: report_cfi_failure restored\n");
	kpm_report_failure = 0;
	kpm_report_failure_orig = 0;
}

/* Restore the original CFI slowpath words.  Called at module exit, and on
 * any load path that returns without marking the image loaded. */
static __kpm_nocfi void kpm_cfi_restore_slowpath(void)
{
	unsigned long addr;

	kpm_cfi_restore_report_failure();

	if (!kpm_slowpath_patched)
		return;

	addr = kpm_slowpath_diag;
	if (addr && kpm_slowpath_diag_orig) {
		int rc = 0;
		int npages = kpm_slowpath_diag_npages ?: 1;

		if (host_set_memory_rw)
			rc = host_set_memory_rw(addr & PAGE_MASK, npages);
		if (rc)
			pr_alert("kpm: cfi slowpath restore SKIPPED (%px): set_memory_rw rc=%d\n",
				 (void *)addr, rc);
		else {
			WRITE_ONCE(*(u32 *)addr, kpm_slowpath_diag_orig);
			flush_icache_range(addr, addr + 4);
			if (host_kick_all_cpus_sync)
				host_kick_all_cpus_sync();
			if (host_set_memory_ro) {
				int rorc = host_set_memory_ro(addr & PAGE_MASK, npages);

				if (rorc)
					pr_warn("kpm: set_memory_ro rc=%d (text stays RW)\n", rorc);
			}
			pr_alert("kpm: cfi slowpath restored %px (0x%08x)\n",
				 (void *)addr, kpm_slowpath_diag_orig);
			kpm_slowpath_diag = 0;
			kpm_slowpath_diag_orig = 0;
			kpm_slowpath_diag_npages = 0;
		}
	}

	addr = kpm_slowpath_plain;
	if (addr && kpm_slowpath_plain_orig) {
		int rc = 0;
		int npages = kpm_slowpath_plain_npages ?: 1;

		if (host_set_memory_rw)
			rc = host_set_memory_rw(addr & PAGE_MASK, npages);
		if (rc)
			pr_alert("kpm: cfi slowpath restore SKIPPED (%px): set_memory_rw rc=%d\n",
				 (void *)addr, rc);
		else {
			WRITE_ONCE(*(u32 *)addr, kpm_slowpath_plain_orig);
			flush_icache_range(addr, addr + 4);
			if (host_kick_all_cpus_sync)
				host_kick_all_cpus_sync();
			if (host_set_memory_ro) {
				int rorc = host_set_memory_ro(addr & PAGE_MASK, npages);

				if (rorc)
					pr_warn("kpm: set_memory_ro rc=%d (text stays RW)\n", rorc);
			}
			pr_alert("kpm: cfi slowpath restored %px (0x%08x)\n",
				 (void *)addr, kpm_slowpath_plain_orig);
			kpm_slowpath_plain = 0;
			kpm_slowpath_plain_orig = 0;
			kpm_slowpath_plain_npages = 0;
		}
	}

	kpm_slowpath_patched = false;
}

static __kpm_nocfi unsigned long klookup(const char *name)
{
	unsigned long addr;

	/* explicit kpm_syms entries always win */
	addr = kpm_live_find(name);
	if (addr)
		return addr;

	/* runtime resolution through the kpm_syms-provided anchor */
	if (kallsyms_lookup_name_fn)
		return kallsyms_lookup_name_fn(name);

	return 0;
}

/* module_alloc/module_memfree are NOT exported on GKI 5.10 (they are on
 * 4.14) -- resolve them at runtime through kallsyms so the same .c works
 * for the 4.14 host as well. */
static __kpm_nocfi void __maybe_unused resolve_exec_alloc(void)
{
	unsigned long addr;

	if (kallsyms_lookup_name_fn) {
		/* 分配/释放不会跨分配器混用：5.10 的 module_alloc/module_memfree
		 * 成对存在；6.10+ 的 module_memfree 本身就是 execmem_free 的
		 * 包装，execmem_free 存在时 module_memfree 一定也存在。 */
		addr = kallsyms_lookup_name_fn("module_alloc");
		if (addr)
			host_module_alloc = (void *(*)(unsigned long))addr;
		addr = kallsyms_lookup_name_fn("module_memfree");
		if (addr)
			host_module_memfree = (void (*)(void *))addr;
		if (!host_module_alloc) {
			addr = kallsyms_lookup_name_fn("execmem_alloc");
			if (addr)
				host_execmem_alloc = (void *(*)(kpm_execmem_type_t, unsigned long))addr;
		}
		if (!host_module_memfree) {
			addr = kallsyms_lookup_name_fn("execmem_free");
			if (addr)
				host_module_memfree = (void (*)(void *))addr;
		}
		addr = kallsyms_lookup_name_fn("aarch64_insn_patch_text_nosync");
		if (!addr)
			addr = kallsyms_lookup_name_fn("aarch64_insn_write");
		if (addr)
			host_insn_patch = (int (*)(void *, u32))addr;
		addr = kallsyms_lookup_name_fn("set_memory_rw");
		if (addr)
			host_set_memory_rw = (int (*)(unsigned long, int))addr;
		addr = kallsyms_lookup_name_fn("set_memory_ro");
		if (addr)
			host_set_memory_ro = (int (*)(unsigned long, int))addr;
		addr = kallsyms_lookup_name_fn("set_memory_x");
		if (addr)
			host_set_memory_x = (int (*)(unsigned long, int))addr;
		addr = kallsyms_lookup_name_fn("kick_all_cpus_sync");
		if (addr)
			host_kick_all_cpus_sync = (void (*)(void))addr;
		pr_alert("kpm: slowpath syms: diag=%px plain=%px kick=%px\n",
			 (void *)kallsyms_lookup_name_fn("__cfi_slowpath_diag"),
			 (void *)kallsyms_lookup_name_fn("__cfi_slowpath"),
			 (void *)host_kick_all_cpus_sync);
	}
}

/* The load path is fully memory-buffer based (ioctl LOAD), so there is no
 * firmware file and no filp_open / kernel_read anywhere in this module. */

/* Populate the kf_* / printk / copy_to_user slots that KPMs read through the
 * exported symbol addresses.  KPMs compiled with INIT_USE_KALLSYMS_LOOKUP_NAME
 * resolve these themselves via kallsyms_lookup_name, but we pre-fill them so a
 * KPM works even without its own self-resolution step and so that all kf_*
 * function calls are functional. */
static __kpm_nocfi void __maybe_unused resolve_kpm_syms(void)
{
	if (!kallsyms_lookup_name_fn)
		return;

	host_printk = (int (*)(const char *, ...))kallsyms_lookup_name_fn("printk");
	if (!host_printk)
		host_printk = (int (*)(const char *, ...))kallsyms_lookup_name_fn("_printk");
	host_compat_copy_to_user_ptr = host_compat_copy_to_user;
	host_copy_to_user = (unsigned long (*)(void __user *, const void *, unsigned long))
		(kallsyms_lookup_name_fn("_copy_to_user") ?: kallsyms_lookup_name_fn("copy_to_user"));

	kf_memcpy = (void *(*)(void *, const void *, size_t))kallsyms_lookup_name_fn("memcpy");
	kf_memset = (void *(*)(void *, int, size_t))kallsyms_lookup_name_fn("memset");
	kf_strsep = (char *(*)(char **, const char *))kallsyms_lookup_name_fn("strsep");
	kf_kstrtoull = (int (*)(const char *, unsigned int, unsigned long long *))kallsyms_lookup_name_fn("kstrtoull");
	kf_snprintf = (int (*)(char *, size_t, const char *, ...))kallsyms_lookup_name_fn("snprintf");
	kf_strlen = (size_t (*)(const char *))kallsyms_lookup_name_fn("strlen");
	kf_memcmp = (int (*)(const void *, const void *, size_t))kallsyms_lookup_name_fn("memcmp");
	kf_strncat = (char *(*)(char *, const char *, size_t))kallsyms_lookup_name_fn("strncat");

	pr_alert("kpm: kf slots: printk=%px copy_to_user=%px strncat=%px\n",
		host_printk ? (void *)host_printk : NULL,
		host_copy_to_user ? (void *)host_copy_to_user : NULL,
		kf_strncat ? (void *)kf_strncat : NULL);
}

u64 kpm_get_symbol(const char *name)
{
	int i;
	unsigned long addr;

	if (name[0] == '\0')
		return 0;

	for (i = 0; i < ARRAY_SIZE(host_exports); i++) {
		if (strcmp(name, host_exports[i].name) == 0)
			return (u64)(unsigned long)host_exports[i].addr;
	}

	addr = klookup(name);
	if (addr)
		return (u64)addr;

	return 0;
}

/* ------------------------------------------------------------------ */
/* ELF loader                                                          */
/* ------------------------------------------------------------------ */

/* 布局阶段的硬上限：正常 KPM 只有几十 KB，留 64MB 给 BSS；超过就拒绝，
 * 顺便保证后续 ALIGN 不会在接近 ULONG_MAX 时回绕。 */
#define KPM_MAX_IMAGE_SIZE (64UL * 1024 * 1024)

/* 把 *size 对齐到 align，并对齐前检查上限与加法回绕 */
static int kpm_size_align(unsigned long *size, unsigned long align)
{
	unsigned long end;

	if (!is_power_of_2(align) || align > PAGE_SIZE)
		return -ENOEXEC;
	if (*size > KPM_MAX_IMAGE_SIZE)
		return -ENOEXEC;
	if (check_add_overflow(*size, align - 1, &end))
		return -ENOEXEC;
	*size = end & ~(align - 1);
	return 0;
}

/* 失败返回 -1：sh_addralign 非法、对齐/加法回绕或超过镜像上限。
 * 这些都不是正常 KPM 会出现的值，一旦放过会让 img->size 小于实际
 * 段大小，后面的 memcpy 就越界写了。 */
static long kpm_get_offset(unsigned long *size, Elf64_Shdr *sechdr)
{
	unsigned long align = sechdr->sh_addralign ?: 1;
	unsigned long start, end;

	if (kpm_size_align(size, align))
		return -1;
	start = *size;
	if (check_add_overflow(start, sechdr->sh_size, &end) ||
	    end > KPM_MAX_IMAGE_SIZE)
		return -1;
	*size = end;
	return (long)start;
}

static int kpm_layout_sections(struct kpm_image *img, struct kpm_load_info *info)
{
	static const unsigned long masks[][2] = {
		{ SHF_EXECINSTR | SHF_ALLOC, 0 },
		{ SHF_ALLOC, SHF_WRITE },
		{ SHF_WRITE | SHF_ALLOC, 0 },
		{ SHF_ALLOC, 0 },
	};
	int i, m;

	for (i = 0; i < info->hdr->e_shnum; i++)
		info->sechdrs[i].sh_entsize = ~0UL;

	for (m = 0; m < ARRAY_SIZE(masks); ++m) {
		for (i = 0; i < info->hdr->e_shnum; ++i) {
			Elf64_Shdr *s = &info->sechdrs[i];
			long off;

			if ((s->sh_flags & masks[m][0]) != masks[m][0] ||
			    (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
				continue;
			off = kpm_get_offset(&img->size, s);
			if (off < 0)
				return -ENOEXEC;
			s->sh_entsize = off;
		}
		switch (m) {
		case 0:
			if (kpm_size_align(&img->size, PAGE_SIZE))
				return -ENOEXEC;
			img->text_size = img->size;
			break;
		case 1:
			if (kpm_size_align(&img->size, PAGE_SIZE))
				return -ENOEXEC;
			img->ro_size = img->size;
			break;
		case 2:
			break;
		case 3:
			if (kpm_size_align(&img->size, PAGE_SIZE))
				return -ENOEXEC;
			break;
		}
	}
	return 0;
}

/* 名称偏移落在表内还不够，必须保证该位置到表尾之间有 NUL，否则 strlen/
 * strcmp 会越界读。损坏的 KPM 可以让表尾没有终止符。 */
static bool kpm_name_ok(const char *tab, unsigned long size, unsigned int off)
{
	if (!tab || off >= size)
		return false;
	return memchr(tab + off, '\0', size - off) != NULL;
}

static bool kpm_is_core_symbol(const Elf64_Sym *src, const Elf64_Shdr *sechdrs, unsigned int shnum)
{
	const Elf64_Shdr *sec;
	if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
		return false;
	sec = sechdrs + src->st_shndx;
	if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR))
		return false;
	return true;
}

static int kpm_simplify_symbols(struct kpm_image *img, const struct kpm_load_info *info)
{
	Elf64_Shdr *symsec = &info->sechdrs[info->symtab];
	Elf64_Sym *sym = (Elf64_Sym *)symsec->sh_addr;
	unsigned int i;
	int ret = 0;

	for (i = 1; i < symsec->sh_size / sizeof(Elf64_Sym); i++) {
		const char *name;

		if (!kpm_name_ok(info->strtab_data,
				 info->sechdrs[info->strtab].sh_size,
				 sym[i].st_name)) {
			pr_err("kpm: symbol %u st_name OOB: %u\n", i, sym[i].st_name);
			ret = -ENOEXEC;
			break;
		}
		name = info->strtab_data + sym[i].st_name;
		switch (sym[i].st_shndx) {
		case SHN_COMMON:
			/* common 符号没有分配 BSS，st_value 只是对齐值；保留它会让
			 * 重定位写入 8/16 这种小地址，跳到它直接内核 Oops。KPM
			 * 默认 -fno-common 编译，正常不会出现。 */
			pr_err("kpm: common symbol not supported: %s\n", name);
			ret = -ENOEXEC;
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF: {
			unsigned long addr = kpm_get_symbol(name);
			if (!addr) {
				pr_err("kpm: unknown symbol: %s\n", name);
				ret = -ENOENT;
				break;
			}
			sym[i].st_value = addr;
			break;
		}
		default: {
			unsigned long secbase;

			if (sym[i].st_shndx >= info->hdr->e_shnum) {
				pr_err("kpm: symbol %u st_shndx OOB: %u\n",
				       i, sym[i].st_shndx);
				ret = -ENOEXEC;
				break;
			}
			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
		}
	}
	return ret;
}

static int kpm_apply_relocations(struct kpm_image *img, const struct kpm_load_info *info)
{
	int rc = 0;
	unsigned int i;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		unsigned int infosec = info->sechdrs[i].sh_info;
		if (infosec >= info->hdr->e_shnum)
			continue;
		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
			continue;
		if (info->sechdrs[i].sh_type == SHT_RELA) {
			rc = kpm_apply_relocate_add(info->sechdrs, info->strtab_data, info->symtab, i, img);
			if (rc < 0)
				break;
		}
	}
	return rc;
}

static int kpm_layout_symtab(struct kpm_image *img, struct kpm_load_info *info)
{
	Elf64_Shdr *symsect = info->sechdrs + info->symtab;
	Elf64_Shdr *strsect = info->sechdrs + info->sechdrs[info->symtab].sh_link;
	const Elf64_Sym *src;
	unsigned int i, nsrc, ndst, strtab_size = 0;

	symsect->sh_flags |= SHF_ALLOC;
	{
		long off = kpm_get_offset(&img->size, symsect);

		if (off < 0)
			return -ENOEXEC;
		symsect->sh_entsize = off;
	}

	src = (const Elf64_Sym *)((const char *)info->hdr + symsect->sh_offset);
	nsrc = symsect->sh_size / sizeof(*src);

	strtab_size = 1;
	for (ndst = i = 0; i < nsrc; i++) {
		if (i == 0 || kpm_is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
			if (!kpm_name_ok(info->strtab_data, strsect->sh_size,
					 src[i].st_name)) {
				pr_err("kpm: symbol %u st_name OOB: %u\n",
				       i, src[i].st_name);
				return -ENOEXEC;
			}
			strtab_size += strlen(&info->strtab_data[src[i].st_name]) + 1;
			ndst++;
		}
	}

	{
		unsigned long end;

		if (kpm_size_align(&img->size, symsect->sh_addralign ?: 1))
			return -ENOEXEC;
		if (check_add_overflow(img->size, ndst * sizeof(Elf64_Sym), &end) ||
		    end > KPM_MAX_IMAGE_SIZE)
			return -ENOEXEC;
		if (check_add_overflow(end, strtab_size, &end) ||
		    end > KPM_MAX_IMAGE_SIZE)
			return -ENOEXEC;
		img->size = end;
	}

	strsect->sh_flags |= SHF_ALLOC;
	{
		long off = kpm_get_offset(&img->size, strsect);

		if (off < 0)
			return -ENOEXEC;
		strsect->sh_entsize = off;
	}
	return 0;
}

static int kpm_rewrite_section_headers(struct kpm_load_info *info)
{
	int i;
	info->sechdrs[0].sh_addr = 0;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];
		/* 用减法避免 sh_offset + sh_size 的 64 位溢出绕过检查 */
		if (shdr->sh_type != SHT_NOBITS &&
		    (shdr->sh_offset > info->len ||
		     shdr->sh_size > info->len - shdr->sh_offset))
			return -ENOEXEC;
		shdr->sh_addr = (unsigned long)((const char *)info->hdr + shdr->sh_offset);
	}
	return 0;
}

static char *kpm_next_string(char *string, unsigned long *secsize)
{
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}
	return string;
}

static char *kpm_get_next_modinfo(const struct kpm_load_info *info, const char *tag, char *prev)
{
	char *p;
	unsigned int taglen = strlen(tag);
	Elf64_Shdr *infosec;
	unsigned long size;
	char *modinfo;
	char *end;

	infosec = &info->sechdrs[info->modinfo_secobj];
	size = infosec->sh_size;
	/* kpm_next_string 先读 string[0] 再检查剩余长度，零长度段会越界 */
	if (!size)
		return NULL;
	modinfo = (char *)info->hdr + infosec->sh_offset;
	/* kpm_next_string 沿用内核原版逻辑，段尾没有 NUL 时可能多读一个
	 * 字节；比较 tag 前先按段边界确认 p[taglen] 可读。 */
	end = modinfo + infosec->sh_size;

	if (prev) {
		size -= prev - modinfo;
		modinfo = kpm_next_string(prev, &size);
	}
	for (p = modinfo; p; p = kpm_next_string(p, &size)) {
		if (p < end && (unsigned long)(end - p) > taglen + 1 &&
		    strncmp(p, tag, taglen) == 0 && p[taglen] == '=') {
			char *val = p + taglen + 1;

			/* 值必须在段内有 NUL 终止，否则后续 strlen/strscpy
			 * 会越过段尾读 */
			if (memchr(val, '\0', end - val))
				return val;
		}
	}
	return NULL;
}

static int kpm_find_sec(const struct kpm_load_info *info, const char *name)
{
	int i;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];

		if (!kpm_name_ok(info->secstrings, info->shstrtab_size,
				 shdr->sh_name))
			continue;
		if ((shdr->sh_flags & SHF_ALLOC) &&
		    strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

/* 名字会出现在 kpatch kpm list/info 的行协议里：控制字符会把一行拆成
 * 多行，也会让 WebUI 回调时拿到的名字与 agent 里的原名对不上。 */
static bool kpm_name_is_printable(const char *s)
{
	/* 空名字会让 kpm list 显示 unknown，但 unload 按原名匹配不上 */
	if (!s || !*s)
		return false;

	for (; *s; s++) {
		unsigned char c = *s;

		if (c < 0x20 || c == 0x7f)
			return false;
	}
	return true;
}

static int kpm_setup_load_info(struct kpm_load_info *info)
{
	int rc = 0;
	Elf64_Shdr *sections;

	if (info->hdr->e_shstrndx >= info->hdr->e_shnum) {
		pr_err("kpm: e_shstrndx OOB\n");
		return -ENOEXEC;
	}
	info->sechdrs = (Elf64_Shdr *)((const char *)info->hdr + info->hdr->e_shoff);
	{
		Elf64_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];

		/* shstrtab 必须是真实文件数据；SHT_NOBITS 的 sh_offset 不受
		 * kpm_rewrite_section_headers 的范围检查约束。 */
		if (shstr->sh_type != SHT_STRTAB ||
		    shstr->sh_offset > info->len ||
		    shstr->sh_size > info->len - shstr->sh_offset) {
			pr_err("kpm: bad shstrtab\n");
			return -ENOEXEC;
		}
		info->secstrings = (char *)((const char *)info->hdr + shstr->sh_offset);
		info->shstrtab_size = shstr->sh_size;
	}

	if ((rc = kpm_rewrite_section_headers(info))) {
		pr_err("kpm: rewrite section error\n");
		return rc;
	}

	if (!kpm_find_sec(info, KPM_SECT_INIT) || !kpm_find_sec(info, KPM_SECT_EXIT)) {
		pr_err("kpm: no .kpm.init or .kpm.exit section\n");
		return -ENOEXEC;
	}

	/* locate modinfo section */
	{
		int i;
		info->modinfo_secobj = 0;
		for (i = 1; i < info->hdr->e_shnum; i++) {
			if (!kpm_name_ok(info->secstrings, info->shstrtab_size,
					 info->sechdrs[i].sh_name))
				continue;
			if ((info->sechdrs[i].sh_flags & SHF_ALLOC) &&
			    strcmp(info->secstrings + info->sechdrs[i].sh_name, KPM_SECT_INFO) == 0) {
				info->modinfo_secobj = i;
				break;
			}
		}
	}
	if (!info->modinfo_secobj) {
		pr_err("kpm: no .kpm.info section\n");
		return -ENOEXEC;
	}
	{
		Elf64_Shdr *mi = &info->sechdrs[info->modinfo_secobj];

		/* .kpm.info 必须来自文件数据，不能是 NOBITS 或零长度 */
		if (mi->sh_type == SHT_NOBITS || mi->sh_size == 0 ||
		    mi->sh_offset > info->len ||
		    mi->sh_size > info->len - mi->sh_offset) {
			pr_err("kpm: bad modinfo section\n");
			return -ENOEXEC;
		}
		info->modinfo_base = (const char *)info->hdr + mi->sh_offset;
		info->modinfo_size = mi->sh_size;
	}

	{
		char *name = kpm_get_next_modinfo(info, KPM_MODINFO_NAME, NULL);
		if (!name) {
			pr_err("kpm: module name not found\n");
			return -ENOEXEC;
		}
		/* 名字要能完整放进 ioctl 的固定长度字段；超长会在 STATUS/LIST
		 * 里被截断，WebUI 拿截断名回调时按完整名 strcmp 匹配不上。 */
		if (!kpm_name_is_printable(name) ||
		    strnlen(name, KPM_CTL_NAME_MAX) >= KPM_CTL_NAME_MAX) {
			pr_err("kpm: module name invalid or too long\n");
			return -ENOEXEC;
		}
		info->modinfo_name = name;
		pr_alert("kpm: loading [%s]\n", name);
	}
	{
		char *version = kpm_get_next_modinfo(info, KPM_MODINFO_VERSION, NULL);
		if (version)
			info->modinfo_version = version;
	}
	info->modinfo_license = kpm_get_next_modinfo(info, KPM_MODINFO_LICENSE, NULL);
	info->modinfo_author = kpm_get_next_modinfo(info, KPM_MODINFO_AUTHOR, NULL);
	info->modinfo_description = kpm_get_next_modinfo(info, KPM_MODINFO_DESCRIPTION, NULL);

	info->symtab = 0;
	for (sections = info->sechdrs; sections < info->sechdrs + info->hdr->e_shnum; sections++) {
		if (sections->sh_type == SHT_SYMTAB) {
			Elf64_Shdr *strsect;

			if (sections->sh_link >= info->hdr->e_shnum) {
				pr_err("kpm: symtab sh_link OOB: %u\n",
				       sections->sh_link);
				return -ENOEXEC;
			}
			strsect = &info->sechdrs[sections->sh_link];
			/* 符号名字符串表也必须是真实文件数据，否则后面的
			 * kpm_name_ok()/strlen() 会越界读 */
			if (strsect->sh_type != SHT_STRTAB ||
			    strsect->sh_offset > info->len ||
			    strsect->sh_size > info->len - strsect->sh_offset) {
				pr_err("kpm: bad symtab strtab\n");
				return -ENOEXEC;
			}
			info->symtab = sections - info->sechdrs;
			info->strtab = sections->sh_link;
			info->strtab_data = (const char *)info->hdr + strsect->sh_offset;
			break;
		}
	}
	if (!info->symtab) {
		pr_err("kpm: module has no symbols (stripped?)\n");
		return -ENOEXEC;
	}
	return 0;
}

/* .kpm.init/.kpm.ctl0/.kpm.ctl1/.kpm.exit 里存的是函数指针：段必须来自
 * 真实文件数据，且至少有一个指针大小，否则读出来的“指针”没有意义。 */
static bool kpm_sect_ptr_ok(const Elf64_Shdr *s)
{
	return s->sh_type != SHT_NOBITS && s->sh_size >= sizeof(void *);
}

static __kpm_nocfi int kpm_move_module(struct kpm_image *img, struct kpm_load_info *info)
{
	int i;

	if (!host_module_alloc && !host_execmem_alloc) {
		pr_err("kpm: module_alloc/execmem_alloc unresolved\n");
		return -ENOENT;
	}
	img->base = kpm_alloc_exec(img->size);
	if (!img->base) {
		pr_err("kpm: module_alloc/execmem_alloc failed, need %lu bytes\n", img->size);
		return -ENOMEM;
	}
	if (host_set_memory_rw) {
		int rwrc = host_set_memory_rw((unsigned long)img->base,
					      DIV_ROUND_UP(img->size, PAGE_SIZE));

		if (rwrc) {
			pr_err("kpm: set_memory_rw rc=%d\n", rwrc);
			return -EIO;
		}
	}
	memset(img->base, 0, img->size);

	for (i = 1; i < info->hdr->e_shnum; i++) {
		void *dest;
		Elf64_Shdr *shdr = &info->sechdrs[i];
		const char *sname;
		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;
		if (!kpm_name_ok(info->secstrings, info->shstrtab_size,
				 shdr->sh_name)) {
			pr_err("kpm: section %d sh_name OOB: %u\n",
			       i, shdr->sh_name);
			return -ENOEXEC;
		}

		dest = (char *)img->base + shdr->sh_entsize;
		sname = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

		shdr->sh_addr = (unsigned long)dest;

		/* 这几段里存的是函数指针，必须来自文件且能容纳一个指针 */
		if (!strcmp(KPM_SECT_INIT, sname)) {
			if (!kpm_sect_ptr_ok(shdr))
				return -ENOEXEC;
			if (!img->init)
				img->init = (const char *)dest;
		}
		if (!strcmp(KPM_SECT_CTL0, sname)) {
			if (!kpm_sect_ptr_ok(shdr))
				return -ENOEXEC;
			img->ctl0 = (const char *)dest;
		}
		if (!strcmp(KPM_SECT_CTL1, sname)) {
			if (!kpm_sect_ptr_ok(shdr))
				return -ENOEXEC;
			img->ctl1 = (const char *)dest;
		}
		if (!strcmp(KPM_SECT_EXIT, sname)) {
			if (!kpm_sect_ptr_ok(shdr))
				return -ENOEXEC;
			if (!img->exit)
				img->exit = (const char *)dest;
		}
		if (!img->info && !strcmp(KPM_SECT_INFO, sname))
			img->info = (const char *)dest;
	}

	/* rebase modinfo pointers */
	{
		long delta = (const char *)img->info - info->modinfo_base;
		img->info_name = (char *)info->modinfo_name + delta;
		if (info->modinfo_version)
			img->info_version = (char *)info->modinfo_version + delta;
		if (info->modinfo_license)
			img->info_license = (char *)info->modinfo_license + delta;
		if (info->modinfo_author)
			img->info_author = (char *)info->modinfo_author + delta;
		if (info->modinfo_description)
			img->info_description = (char *)info->modinfo_description + delta;
	}
	return 0;
}

static int kpm_elf_header_check(struct kpm_load_info *info)
{
	if (info->len <= sizeof(*info->hdr))
		return -ENOEXEC;
	if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL ||
	    info->hdr->e_machine != EM_AARCH64 || info->hdr->e_shentsize != sizeof(Elf64_Shdr))
		return -ENOEXEC;
	if (info->hdr->e_shoff >= info->len ||
	    (info->hdr->e_shnum * sizeof(Elf64_Shdr) > info->len - info->hdr->e_shoff))
		return -ENOEXEC;
	return 0;
}

struct kpm_image kpm_images[KPM_CTL_MAX_MODULES];

__kpm_nocfi long kpm_load_module(struct kpm_image *img, const void *data,
				 unsigned long len, const char *args,
				 const char *event, void *reserved)
{
	struct kpm_load_info info = { .hdr = data, .len = len };
	long rc = 0;
	bool newly_neutered = false;
	kpm_initcall_t init_fn;

	if ((rc = kpm_elf_header_check(&info)))
		goto out;
	pr_alert("kpm: l1 header ok len=%lu\n", len);
	if ((rc = kpm_setup_load_info(&info)))
		goto out;
	pr_alert("kpm: l2 setup ok name=%s\n", info.modinfo_name ?: "?");

	memset(img, 0, sizeof(*img));
	if ((rc = kpm_layout_sections(img, &info)))
		goto out;
	if ((rc = kpm_layout_symtab(img, &info)))
		goto out;
	pr_alert("kpm: l3 layout size=%lu text=%lu\n", img->size, img->text_size);

	if ((rc = kpm_move_module(img, &info)))
		goto out;
	pr_alert("kpm: l4 move base=%px size=%lu\n", img->base, img->size);

	if ((rc = kpm_simplify_symbols(img, &info)))
		goto out;
	pr_alert("kpm: l5 simplify ok\n");

	if ((rc = kpm_apply_relocations(img, &info)))
		goto out;
	pr_alert("kpm: l6 reloc ok\n");

	flush_icache_range((unsigned long)img->base, (unsigned long)img->base + img->size);
	pr_alert("kpm: l7 flush done\n");
	/* NOTE: do NOT set_memory_ro here.  KP-2.x-style KPMs keep .kpm.ctl0
	 * writable during init (they write their control/interface fields);
	 * the whole image stays RWX like KernelPatch's own module loader
	 * (which only calls set_memory_x). */
	if (!host_set_memory_x) {
		pr_err("kpm: set_memory_x unresolved, refuse to load\n");
		rc = -ENOSYS;
		goto out;
	}
	rc = host_set_memory_x((unsigned long)img->base,
			       DIV_ROUND_UP(img->size, PAGE_SIZE));
	if (rc) {
		pr_err("kpm: set_memory_x rc=%ld, refuse to load\n", rc);
		goto out;
	}

	if (!img->init) {
		rc = -ENOEXEC;
		goto out;
	}
	pr_alert("kpm: l8 call kpm init at %px\n", img->init);

	/* Register the KPM image range in the CFI shadow before the kernel can
	 * reenter it (rearm thread etc.).  Without this, __cfi_slowpath() finds
	 * no check function for the KPM pages and panics on the first kernel
	 * callback into KPM code. */
	{
		int cret = kpm_cfi_register(img, (unsigned long)img->base,
					    img->size);

		if (cret)
			pr_warn("kpm: cfi shadow register failed rc=%d\n", cret);
	}

	/* Neutralize the kernel CFI slowpath — the unconditional safety net.  Even
	 * if the shadow above registered, the OEM kernel may never consult it; the
	 * neuter guarantees the first kernel→KPM indirect callback cannot panic.
	 * 6.12 上找不到 report_cfi_failure 或 patch 失败时必须拒绝加载。
	 * 补丁是全局的：只在第一个 KPM 加载时打，最后一个卸载时恢复。 */
	if (kpm_cfi_users == 0) {
		if (!kpm_cfi_neuter_slowpath()) {
			pr_err("kpm: no CFI failure path neutered, refuse to load\n");
			rc = -ENOSYS;
			goto out;
		}
		newly_neutered = true;
	}

	init_fn = *(kpm_initcall_t *)img->init;
	if (!init_fn) {
		pr_err("kpm: init pointer is NULL\n");
		rc = -ENOEXEC;
		goto out;
	}
	pr_alert("kpm: init_fn addr=%px event=%s\n", (void *)init_fn, event ?: "");
	rc = init_fn(args, event, reserved);
	pr_alert("kpm: l9 kpm init rc=%ld\n", rc);

	if (!rc) {
		/* info_args 是 agent 自己的拷贝：args 指针属于 ioctl 的临时
		 * 缓冲，kpm_load_module() 返回后就不能再引用。 */
		strscpy(img->info_args, args ? args : "",
			sizeof(img->info_args));
		pr_alert("kpm: [%s] succeed\n", img->info_name ?: "?");
		img->loaded = true;
		kpm_cfi_users++;
	} else {
		pr_err("kpm: [%s] failed rc=%ld, try exit ...\n",
		       img->info_name ?: "?", rc);
		if (img->exit) {
			kpm_exitcall_t exit_fn = *(kpm_exitcall_t *)img->exit;

			if (exit_fn)
				exit_fn(reserved);
		}
	}

out:
	/* 加载失败时统一释放并清空该槽位：留着已释放的 base 或 modinfo 指针
	 * 会让后续 STATUS ioctl 读野指针。 */
	if (!img->loaded) {
		if (img->base) {
			kpm_cfi_unregister(img);
			if (host_set_memory_rw)
				host_set_memory_rw((unsigned long)img->base,
						   DIV_ROUND_UP(img->size, PAGE_SIZE));
			host_module_memfree(img->base);
		}
		memset(img, 0, sizeof(*img));
		/* 本次是第一个 KPM 且加载失败：全局 slowpath 补丁要恢复。
		 * 如果其它 KPM 还在，补丁必须保留。 */
		if (newly_neutered)
			kpm_cfi_restore_slowpath();
	}
	return rc;
}

/* ------------------------------------------------------------------ */
/* module lifecycle                                                    */
/* ------------------------------------------------------------------ */

static int __kpm_nocfi kpm_host_do_init(void)
{
	int rc;

	pr_alert("kpm: host init (agent mode)\n");

	/* live table from kpm_syms param: the ONLY out-of-band input */
	kpm_live_parse(kpm_syms);

	kallsyms_lookup_name_fn =
		(unsigned long (*)(const char *))kpm_live_find("kallsyms_lookup_name");
	if (!kallsyms_lookup_name_fn) {
		pr_err("kpm: live table has no kallsyms_lookup_name entry, refusing\n");
		kpm_live_free();
		return -EINVAL;
	}
	pr_alert("kpm: t1 anchor kallsyms_lookup_name=%px\n", (void *)kallsyms_lookup_name_fn);

	/* resolve everything else through the anchor */
	resolve_exec_alloc();
	resolve_cfi_shadow();
	resolve_kpm_syms();
	pr_alert("kpm: t2 module_alloc=%px execmem_alloc=%px module_memfree=%px printk=%px copy_to_user=%px\n",
		host_module_alloc, host_execmem_alloc, host_module_memfree,
		host_printk, host_copy_to_user);

	if ((!host_module_alloc && !host_execmem_alloc) || !host_module_memfree) {
		pr_err("kpm: exec alloc/free unresolved, refusing\n");
		kpm_live_free();
		return -ENOSYS;
	}
	/* 6.12 的 execmem 分配出来是 RW 不可执行，必须有 set_memory_x */
	if (host_execmem_alloc && !host_set_memory_x) {
		pr_err("kpm: set_memory_x unresolved, refusing\n");
		kpm_live_free();
		return -ENOSYS;
	}

	/* register the control node; this module stays resident now */
	rc = kpm_ctl_init();
	if (rc) {
		kpm_live_free();
		return rc;
	}

	pr_alert("kpm: host ready. push .kpm via generic netlink (%s)\n",
		 KPM_GENL_FAMILY_NAME);
	return 0;
}

static int __init kpm_host_init(void)
{
	return kpm_host_do_init();
}

/* 卸载单个 KPM 镜像（exit_fn、CFI shadow、镜像内存）。 */
void __kpm_nocfi kpm_unload_image(struct kpm_image *img)
{
	bool was_loaded;

	if (!img || (!img->loaded && !img->base))
		return;

	was_loaded = img->loaded;
	pr_alert("kpm: unload image %s\n",
		 (img->loaded && img->info_name) ? img->info_name : "(partial)");
	if (img->loaded && img->exit) {
		kpm_exitcall_t exit_fn = *(kpm_exitcall_t *)img->exit;

		if (exit_fn)
			exit_fn(NULL);
	}
	img->loaded = false;

	if (img->base)
		kpm_cfi_unregister(img);

	/* 全局 slowpath 补丁只在最后一个镜像卸载时恢复；exit_fn 和 shadow
	 * 移除仍然会重入内核 text，恢复必须放在它们之后。 */
	if (was_loaded) {
		if (kpm_cfi_users > 0)
			kpm_cfi_users--;
		if (kpm_cfi_users == 0)
			kpm_cfi_restore_slowpath();
	}

	if (img->base) {
		if (host_set_memory_rw)
			host_set_memory_rw((unsigned long)img->base,
					   DIV_ROUND_UP(img->size, PAGE_SIZE));
		host_module_memfree(img->base);
	}
	memset(img, 0, sizeof(*img));
}

int kpm_is_loaded(void)
{
	int i, n = 0;

	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		if (kpm_images[i].loaded)
			n++;
	}
	return n;
}

/*
 * 调用 .kpm.ctl0 段保存的函数指针。KPM 由 clang 单独编译，函数类型 hash
 * 不保证与本模块看到的类型完全一致；关掉调用点的 CFI 检查，避免一个
 * 参数类型写法差异直接把内核打死（目标函数仍是合法入口）。
 */
long __kpm_nocfi kpm_call_ctl0(struct kpm_image *img, const char *ctl_args,
			       char __user *out_msg, int outlen)
{
	kpm_ctl0call_t fn;

	if (!img || !img->loaded || !img->ctl0)
		return -ENOENT;

	fn = *(kpm_ctl0call_t *)img->ctl0;
	if (!fn)
		return -ENOENT;

	return fn(ctl_args, out_msg, outlen);
}

static void __kpm_nocfi kpm_host_do_exit(void)
{
	int i;

	pr_alert("kpm: host exit\n");
	for (i = 0; i < KPM_CTL_MAX_MODULES; i++)
		kpm_unload_image(&kpm_images[i]);
	kpm_ctl_exit();
	kpm_live_free();
	pr_alert("kpm: host exit done\n");
}

static void __exit kpm_host_exit(void)
{
	kpm_host_do_exit();
}

module_init(kpm_host_init);
module_exit(kpm_host_exit);