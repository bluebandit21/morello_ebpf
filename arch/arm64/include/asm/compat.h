/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_COMPAT_H
#define __ASM_COMPAT_H

#ifdef CONFIG_COMPAT32
#define compat_mode_t compat_mode_t
typedef u16		compat_mode_t;
#endif

#define __compat_uid_t	__compat_uid_t
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;

#define compat_ipc_pid_t compat_ipc_pid_t
typedef u16		compat_ipc_pid_t;

#define compat_statfs	compat_statfs

#include <asm-generic/compat.h>

#ifdef CONFIG_COMPAT

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/cheri.h>

#ifdef __AARCH64EB__
#define COMPAT_UTS_MACHINE	"armv8b\0\0"
#else
#define COMPAT_UTS_MACHINE	"armv8l\0\0"
#endif

typedef u16		__compat_uid16_t;
typedef u16		__compat_gid16_t;
typedef s32		compat_nlink_t;

struct compat_stat {
#ifdef __AARCH64EB__
	short		st_dev;
	short		__pad1;
#else
	compat_dev_t	st_dev;
#endif
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_ushort_t	st_nlink;
	__compat_uid16_t	st_uid;
	__compat_gid16_t	st_gid;
#ifdef __AARCH64EB__
	short		st_rdev;
	short		__pad2;
#else
	compat_dev_t	st_rdev;
#endif
	compat_off_t	st_size;
	compat_off_t	st_blksize;
	compat_off_t	st_blocks;
	old_time32_t	st_atime;
	compat_ulong_t	st_atime_nsec;
	old_time32_t	st_mtime;
	compat_ulong_t	st_mtime_nsec;
	old_time32_t	st_ctime;
	compat_ulong_t	st_ctime_nsec;
	compat_ulong_t	__unused4[2];
};

struct compat_statfs {
	compat_long_t	f_type;
	compat_long_t	f_bsize;
	compat_long_t	f_blocks;
	compat_long_t	f_bfree;
	compat_long_t	f_bavail;
	compat_long_t	f_files;
	compat_long_t	f_ffree;
	compat_fsid_t	f_fsid;
	compat_long_t	f_namelen;	/* SunOS ignores this field. */
	compat_long_t	f_frsize;
	compat_long_t	f_flags;
	compat_long_t	f_spare[4];
};

#ifdef CONFIG_CHERI_PURECAP_UABI
static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	ptraddr_t addr = untagged_addr(uptr);

	/*
	 * TODO [Morello] - this should be done using the current user DDC, not
	 * the root user capability.
	 */
	return likely(addr >= PAGE_SIZE && addr < TASK_SIZE_MAX) ?
		(void __user *)cheri_address_set(cheri_user_root_allperms_cap, uptr) :
		as_user_ptr(uptr);
}
#define compat_ptr(uptr) compat_ptr(uptr)
#endif

#define compat_user_stack_pointer() (user_stack_pointer(task_pt_regs(current)))
#ifdef CONFIG_COMPAT32
#define COMPAT_MINSIGSTKSZ	2048
#endif

#ifdef CONFIG_COMPAT64
#define COMPAT_USE_64BIT_TIME	1
#endif

static inline int is_compat32_task(void)
{
	return IS_ENABLED(CONFIG_COMPAT32) && test_thread_flag(TIF_32BIT);
}

static inline bool is_compat64_task(void)
{
	return IS_ENABLED(CONFIG_COMPAT64) && test_thread_flag(TIF_64BIT_COMPAT);
}

static inline int is_compat_task(void)
{
	return (IS_ENABLED(CONFIG_COMPAT32) && test_thread_flag(TIF_32BIT)) ||
	       (IS_ENABLED(CONFIG_COMPAT64) && test_thread_flag(TIF_64BIT_COMPAT));
}

static inline int is_compat32_thread(struct thread_info *thread)
{
	return IS_ENABLED(CONFIG_COMPAT32) && test_ti_thread_flag(thread, TIF_32BIT);
}

long compat_arm_syscall(struct pt_regs *regs, int scno);

#else /* !CONFIG_COMPAT */

static inline int is_compat32_thread(struct thread_info *thread)
{
	return 0;
}

#endif /* CONFIG_COMPAT */
#endif /* __ASM_COMPAT_H */
