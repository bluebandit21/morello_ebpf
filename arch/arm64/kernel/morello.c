/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Arm Ltd.
 */

#define pr_fmt(fmt) "morello: " fmt

#include <linux/binfmts.h>
#include <linux/cache.h>
#include <linux/capability.h>
#include <linux/cheri.h>
#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched/coredump.h>
#include <linux/sched/mm.h>
#include <linux/sched/task_stack.h>

#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/morello.h>
#include <asm/ptrace.h>
#include <asm/vdso.h>

#ifdef CONFIG_CHERI_PURECAP_UABI
#include <generated/vdso-purecap-offsets.h>
#endif

static uintcap_t morello_sentry_unsealcap __ro_after_init;

/* DDC_ELx reset value (low/high 64 bits), as defined in the Morello spec */
#define DDC_RESET_VAL_LOW_64	0x0
#define DDC_RESET_VAL_HIGH_64	0xffffc00000010005ULL

#define CAP_OTYPE_FIELD_BITS	15

static void cap_lo_hi_tag(uintcap_t cap, u64 *lo_val, u64 *hi_val,
			     u8 *tag)
{
	*lo_val = (u64)cap;
	*hi_val = __builtin_cheri_copy_from_high((void * __capability)cap);
	*tag = cheri_tag_get(cap);
}

static bool cap_has_executive(uintcap_t cap)
{
	return cheri_perms_get(cap) & ARM_CAP_PERMISSION_EXECUTIVE;
}

static bool is_pure_task(void)
{
	return IS_ENABLED(CONFIG_CHERI_PURECAP_UABI) && !is_compat_task();
}

static void update_regs_c64(struct pt_regs *regs, unsigned long pc)
{
	if (pc & 0x1) {
		/*
		 * The LSB of the entry point is set, start the thread in the
		 * C64 ISA by setting PSTATE.C64. Unlike T32 in AArch32, the
		 * architecture also requires PC's LSB to be cleared.
		 */
		regs->pstate |= PSR_C64_BIT;
		regs->pc = pc & ~0x1;
	}
}

#ifdef CONFIG_CHERI_PURECAP_UABI
static void set_creg_user_ptr(struct pt_regs *regs, int r, void __user *val)
{
	regs->regs[r] = user_ptr_addr(val);
	regs->cregs[r] = (uintcap_t)val;
}

static user_uintptr_t make_purecap_signal_return_clr(void)
{
	user_uintptr_t clr = current->mm->context.vdso;

	clr = cheri_perms_and(clr, CHERI_PERM_GLOBAL |
				   CHERI_PERMS_READ | CHERI_PERMS_EXEC);
	clr = cheri_address_set(clr, VDSO_SYMBOL(clr, sigtramp));
	clr = cheri_sentry_create(clr);

	return clr;
}
#endif

void morello_cap_get_val_tag(uintcap_t cap, __uint128_t *val, u8 *tag)
{
	*((uintcap_t *)val) = cheri_tag_clear(cap);
	*tag = cheri_tag_get(cap);
}

void morello_merge_cap_xval(uintcap_t *creg, u64 xreg)
{
	if (cheri_address_get(*creg) != xreg)
		*creg = cheri_address_set(*creg, xreg);
}

uintcap_t morello_build_any_user_cap(const __uint128_t *val, u8 tag)
{
	uintcap_t cap = *((uintcap_t *)val);
	uintcap_t sealing_cap;

	if (!tag)
		return cheri_tag_clear(cap);

	sealing_cap = cheri_type_copy(cheri_user_root_allperms_cap, cap);

	cap = (uintcap_t)cheri_cap_build(cheri_user_root_allperms_cap, cap);
	cap = cheri_seal_conditionally(cap, sealing_cap);
	return cap;
}

int morello_thread_start(struct pt_regs *regs, unsigned long pc,
			  struct linux_binprm *bprm)
{
	int ret = 0;

	update_regs_c64(regs, pc);

	/*
	 * Note: there is no need to explicitly set the address of PCC/CSP as
	 * PC/SP are already set to the appropriate values in regs, and X/C
	 * register merging automatically happens during ret_to_user.
	 */
	if (is_pure_task()) {
#ifdef CONFIG_CHERI_PURECAP_UABI
		regs->pcc = (uintcap_t)bprm->pcuabi.pcc;
		regs->csp = (uintcap_t)bprm->pcuabi.csp;

		ret = bprm->argc; /* Set x0 */
		set_creg_user_ptr(regs, 1, bprm->pcuabi.argv);
		set_creg_user_ptr(regs, 2, bprm->pcuabi.envp);
		set_creg_user_ptr(regs, 3, bprm->pcuabi.auxv);
#endif
	} else /* Hybrid */ {
		regs->pcc = cheri_user_root_allperms_cap;
		/* CSP is null-derived in hybrid */
	}

	return ret;
}

void morello_thread_init_user(void)
{
	struct morello_state *morello_state = &current->thread.morello_user_state;
	uintcap_t ddc;
	u64 cctlr;

	if (is_pure_task()) {
		ddc = 0;
		cctlr = CCTLR_ELx_SBL;
	} else {
		ddc = cheri_user_root_allperms_cap;
		cctlr = 0;
	}

	/*
	 * CTPIDR doesn't need to be initialised explicitly:
	 * - tls_thread_flush() already zeroes tpidr_el0, zeroing ctpidr_el0 as
	 *   well
	 * - The value stored in thread.morello_user_state will be set the next
	 *   time task_save_user_tls() is called, like thread_struct.uw.tp_value.
	 *
	 * tls_thread_flush() does not touch rctpidr_el0 so this must be zeroed
	 * here. We do not need to initialise its value in morello_user_state.
	 * Only the ddc_el0 register must be initialised to the specific value;
	 * RDDC is set to a null capability as processes are always started in
	 * Executive.
	 */
	write_cap_sysreg(0, rctpidr_el0);

	write_cap_sysreg(ddc, ddc_el0);
	morello_state->ddc = ddc;

	write_cap_sysreg(0, cid_el0);
	morello_state->cid = (uintcap_t)0;

	write_sysreg(cctlr, cctlr_el0);
	morello_state->cctlr = cctlr;

	if (is_pure_task()) {
		/*
		 * arch_user_ptr_owning_perms_from_prot() checks the permissions
		 * of PCC to decide which permissions to return. It ends up
		 * being called from binfmt_elf before the thread has even
		 * started, at which point the value of PCC will be that of the
		 * old process. To avoid this issue, set PCC to a temporary
		 * value with all permissions, so that initial reservations
		 * (executable, interpreter, etc.) are assigned appropriate
		 * permissions (especially Executive). This value is never
		 * visible to userspace as morello_thread_start() will set the
		 * final value.
		 */
		task_pt_regs(current)->pcc = cheri_user_root_cap;
	}
}

void morello_thread_save_user_state(struct task_struct *tsk)
{
	struct morello_state *morello_state = &tsk->thread.morello_user_state;

	/* (R)CTPIDR is handled by task_save_user_tls */
	morello_state->ddc = read_cap_sysreg(ddc_el0);
	morello_state->cid = read_cap_sysreg(cid_el0);
	morello_state->cctlr = read_sysreg(cctlr_el0);
}

void morello_thread_restore_user_state(struct task_struct *tsk)
{
	struct morello_state *morello_state = &tsk->thread.morello_user_state;

	/* (R)CTPIDR is handled by task_restore_user_tls */
	write_cap_sysreg(morello_state->ddc, ddc_el0);
	write_cap_sysreg(morello_state->cid, cid_el0);
	write_sysreg(morello_state->cctlr, cctlr_el0);
}

void morello_task_save_user_tls(struct task_struct *tsk, user_uintptr_t *tp_ptr)
{
	struct morello_state *morello_state = &tsk->thread.morello_user_state;
	struct pt_regs *regs = task_pt_regs(tsk);
	uintcap_t active_ctpidr;

	morello_state->ctpidr = read_cap_sysreg(ctpidr_el0);
	morello_state->rctpidr = read_cap_sysreg(rctpidr_el0);

	if (cap_has_executive(regs->pcc))
		active_ctpidr = morello_state->ctpidr;
	else
		active_ctpidr = morello_state->rctpidr;

	*tp_ptr = (user_uintptr_t)active_ctpidr;
}

void morello_task_restore_user_tls(struct task_struct *tsk,
				   const user_uintptr_t *tp_ptr)
{
	struct morello_state *morello_state = &tsk->thread.morello_user_state;
	struct pt_regs *regs = task_pt_regs(tsk);
	uintcap_t *active_ctpidr;

	if (cap_has_executive(regs->pcc))
		active_ctpidr = &morello_state->ctpidr;
	else
		active_ctpidr = &morello_state->rctpidr;

#ifdef CONFIG_CHERI_PURECAP_UABI
	*active_ctpidr = *tp_ptr;
#else
	morello_merge_cap_xval(active_ctpidr, *tp_ptr);
#endif

	write_cap_sysreg(morello_state->ctpidr, ctpidr_el0);
	write_cap_sysreg(morello_state->rctpidr, rctpidr_el0);
}

#ifdef CONFIG_CHERI_PURECAP_UABI
void morello_thread_set_csp(struct pt_regs *regs, user_uintptr_t sp)
{
	uintcap_t *thread_sp = cap_has_executive(regs->pcc) ?
				    &regs->csp : &regs->rcsp;
	*thread_sp = sp;
}
#endif

void morello_setup_signal_return(struct pt_regs *regs)
{
	/*
	 * Setup PC/PCC for the signal handler like for the program's entry
	 * point (this means in particular that the signal handler is invoked in
	 * Executive).
	 */
	update_regs_c64(regs, regs->pc);

	if (is_pure_task()) {
#ifdef CONFIG_CHERI_PURECAP_UABI
		/* Unseal if the pcc has sentry object type */
		if (cheri_is_sentry(regs->pcc))
			regs->pcc = cheri_unseal(regs->pcc,
						 morello_sentry_unsealcap);

		regs->cregs[30] = make_purecap_signal_return_clr();
#endif
	} else /* Hybrid */ {
		regs->pcc = cheri_user_root_allperms_cap;

		/*
		 * Also set CLR to a valid capability, to allow a C64 handler
		 * to return to the trampoline using `ret clr`.
		 */
		regs->cregs[30] = cheri_user_root_allperms_cap;
	}
}

static char *format_cap(char *buf, size_t size, uintcap_t cap)
{
	u64 lo_val, hi_val;
	u8 tag;

	cap_lo_hi_tag(cap, &lo_val, &hi_val, &tag);

	if (snprintf(buf, size, "%u:%016llx:%016llx", tag, hi_val, lo_val) <= 0)
		buf[0] = '\0';
	return buf;
}

void morello_show_regs(struct pt_regs *regs)
{
	char buf[48], buf2[48];
	int i;

	/*
	 * To ensure that the 64-bit and capability views are consistent,
	 * perform the standard register merging, like when saving registers on
	 * the signal frame.
	 */
	morello_merge_cap_regs(regs);

	/* Same layout as the X registers (see __show_regs()) */
	printk("pcc: %s\n", format_cap(buf, sizeof(buf), regs->pcc));
	printk("clr: %s\n", format_cap(buf, sizeof(buf), regs->cregs[30]));

	printk("csp: %s\n", format_cap(buf, sizeof(buf), regs->csp));
	printk("rcsp: %s\n", format_cap(buf, sizeof(buf), regs->rcsp));

	for (i = 29; i > 0; i -= 2) {
		printk("c%-2d: %s c%-2d: %s\n",
		       i, format_cap(buf, sizeof(buf), regs->cregs[i]),
		       i - 1, format_cap(buf2, sizeof(buf2), regs->cregs[i - 1]));
	}
}

/* Inspired by __access_remote_vm() */
static int access_remote_cap(struct task_struct *tsk, struct mm_struct *mm,
			     unsigned long addr, struct user_cap *user_cap,
			     unsigned int gup_flags)
{
	int write = gup_flags & FOLL_WRITE;
	struct vm_area_struct *vma;
	struct page *page;
	uintcap_t *kaddr;
	int ret;

	/* This guarantees that the access will not cross pages */
	if ((addr & (sizeof(uintcap_t) - 1)) != 0)
		return -EINVAL;

	if (mmap_read_lock_killable(mm))
		return -EIO;

	page = get_user_page_vma_remote(mm, addr, gup_flags, &vma);
	if (IS_ERR(page)) {
		ret = -EIO;
		goto out_unlock;
	}

	kaddr = (uintcap_t *)(page_address(page) + offset_in_page(addr));

	if (write) {
		/*
		 * Disallow writing a valid (tagged) capability to a mapping
		 * without store capability permission.
		 *
		 * Reading/writing an untagged capability is always allowed
		 * (just like regular load and store instructions).
		 */
		if (user_cap->tag && !(vma->vm_flags & VM_WRITE_CAPS)) {
			ret = -EOPNOTSUPP;
			goto out_put;
		}

		*kaddr = morello_build_any_user_cap(&user_cap->val,
						    user_cap->tag);
		flush_ptrace_access(vma, (unsigned long)kaddr,
				    (unsigned long)kaddr + sizeof(uintcap_t));
		set_page_dirty_lock(page);
	} else {
		morello_cap_get_val_tag(*kaddr, &user_cap->val, &user_cap->tag);
	}
	ret = 0;

out_put:
	put_page(page);
out_unlock:
	mmap_read_unlock(mm);
	return ret;
}

/* Inspired by ptrace_access_vm() */
int morello_ptrace_access_remote_cap(struct task_struct *tsk,
				     unsigned long addr,
				     struct user_cap *user_cap,
				     unsigned int gup_flags)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return -EIO;

	if (!tsk->ptrace ||
	    (current != tsk->parent) ||
	    ((get_dumpable(mm) != SUID_DUMP_USER) &&
	     !ptracer_capable(tsk, mm->user_ns))) {
		mmput(mm);
		return -EPERM;
	}

	ret = access_remote_cap(tsk, mm, addr, user_cap, gup_flags);
	mmput(mm);

	return ret;
}

void morello_merge_cap_regs(struct pt_regs *regs)
{
	int i;
	uintcap_t *active_csp;

	if (cap_has_executive(regs->pcc))
		active_csp = &regs->csp;
	else
		active_csp = &regs->rcsp;

	for (i = 0; i < ARRAY_SIZE(regs->cregs); i++)
		morello_merge_cap_xval(&regs->cregs[i], regs->regs[i]);

	morello_merge_cap_xval(active_csp, regs->sp);
	morello_merge_cap_xval(&regs->pcc, regs->pc);
}

void morello_flush_cap_regs_to_64_regs(struct task_struct *tsk)
{
	struct pt_regs *regs = task_pt_regs(tsk);
	struct morello_state *morello_state =
		&tsk->thread.morello_user_state;
	uintcap_t active_csp;
	uintcap_t active_ctpidr;
	int i;

	if (cap_has_executive(regs->pcc)) {
		active_csp = regs->csp;
		active_ctpidr = morello_state->ctpidr;
	} else {
		active_csp = regs->rcsp;
		active_ctpidr = morello_state->rctpidr;
	}

	for (i = 0; i < ARRAY_SIZE(regs->cregs); i++)
		regs->regs[i] = (u64)regs->cregs[i];
	regs->pc = (u64)regs->pcc;

	regs->sp = (u64)active_csp;

	tsk->thread.uw.tp_value = (user_uintptr_t)active_ctpidr;
}

int memcmp_pages(struct page *page1, struct page *page2)
{
	/*
	 * Always report that the pages are different. This should not create
	 * correctness issues with the ways memcmp_pages() is currently used.
	 *
	 * A precise implementation for Morello should compare both data and
	 * tags, for those pages whose tags are actually accessible (currently
	 * most of them). It is unclear whether the extra overhead would
	 * justify a precise approach.
	 */
	return 1;
}


static void __init check_root_cap(uintcap_t cap)
{
	u64 lo_val, hi_val;
	u8 tag;

	cap_lo_hi_tag(cap, &lo_val, &hi_val, &tag);

	/*
	 * Check that DDC has the reset value, otherwise root capabilities and
	 * all capabilities derived from them (notably those exposed to
	 * userspace) may not be reliable.
	 */
	if (!(tag == 1 &&
	      lo_val == DDC_RESET_VAL_LOW_64 &&
	      hi_val == DDC_RESET_VAL_HIGH_64))
		pr_warn("DDC does not have its reset value, this may be a firmware bug\n");
}

#define __build_cap(root, perms, length, ...)				\
({									\
	uintcap_t c = (root);						\
	size_t len = (length);						\
									\
	c = cheri_perms_and(c, (perms));				\
	if (len)							\
		c = cheri_bounds_set(c, len);				\
									\
	c;								\
})
#define build_cap(root, perms, ...) __build_cap((root), (perms), ##__VA_ARGS__, 0)

static int __init morello_cap_init(void)
{
	uintcap_t root_cap;
	cheri_perms_t perms;

	root_cap = (uintcap_t)cheri_ddc_get();
	check_root_cap(root_cap);

	/* Initialise standard CHERI root capabilities. */

	perms = CHERI_PERMS_ROOTCAP |
		CHERI_PERMS_READ | CHERI_PERMS_WRITE | CHERI_PERMS_EXEC |
		ARM_CAP_PERMISSION_BRANCH_SEALED_PAIR |
		CHERI_PERM_SEAL | CHERI_PERM_UNSEAL |
		ARM_CAP_PERMISSION_COMPARTMENT_ID;
	/* Same upper limit as for access_ok() and __uaccess_mask_ptr() */
	cheri_user_root_allperms_cap = build_cap(root_cap, perms, TASK_SIZE_MAX);

	perms = CHERI_PERMS_ROOTCAP |
		CHERI_PERMS_READ | CHERI_PERMS_WRITE | CHERI_PERMS_EXEC |
		ARM_CAP_PERMISSION_BRANCH_SEALED_PAIR;
	cheri_user_root_cap = build_cap(cheri_user_root_allperms_cap, perms);

	perms = CHERI_PERM_GLOBAL | CHERI_PERM_SEAL | CHERI_PERM_UNSEAL;
	/*
	 * Includes all object types, not a final decision - some of them may
	 * be later reserved to the kernel.
	 */
	cheri_user_root_seal_cap = build_cap(cheri_user_root_allperms_cap,
					     perms, 1u << CAP_OTYPE_FIELD_BITS);

	perms = CHERI_PERM_GLOBAL | ARM_CAP_PERMISSION_COMPARTMENT_ID;
	/* Maximum userspace bounds for the time being. */
	cheri_user_root_cid_cap = build_cap(cheri_user_root_allperms_cap, perms);

	/* Initialize a capability able to unseal sentry capabilities. */
	perms = CHERI_PERM_GLOBAL | CHERI_PERM_UNSEAL;
	morello_sentry_unsealcap = cheri_address_set(root_cap, CHERI_OTYPE_SENTRY);
	morello_sentry_unsealcap = build_cap(morello_sentry_unsealcap, perms, 1);

	return 0;
}
arch_initcall(morello_cap_init);
