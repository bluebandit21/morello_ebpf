/* SPDX-License-Identifier: GPL-2.0-only */
/* A pointer that can point to either kernel or userspace memory. */
#ifndef _LINUX_BPFPTR_H
#define _LINUX_BPFPTR_H

#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/sockptr.h>

typedef sockptr_t bpfptr_t;

#define __bpfptr_put_uattr(type, x, uattr, to_field) \
	(copy_to_bpfptr_offset(uattr, offsetof(type, to_field), &x, sizeof(x)))

#define bpfptr_put_uattr(x, uattr, to_field) \
	(in_compat64_syscall() ? \
		__bpfptr_put_uattr(union compat_bpf_attr, x, uattr, to_field) : \
		__bpfptr_put_uattr(union bpf_attr, x, uattr, to_field))

static inline bool bpfptr_is_kernel(bpfptr_t bpfptr)
{
	return bpfptr.is_kernel;
}

static inline bpfptr_t KERNEL_BPFPTR(void *p)
{
	return (bpfptr_t) { .kernel = p, .is_kernel = true };
}

static inline bpfptr_t USER_BPFPTR(void __user *p)
{
	return (bpfptr_t) { .user = p };
}

static inline bpfptr_t make_bpfptr(__kernel_uintptr_t ptr, bool is_kernel)
{
	if (is_kernel)
		return KERNEL_BPFPTR((void *)(uintptr_t)ptr);
	else
		return USER_BPFPTR((void __user *)ptr);
}

static inline bool bpfptr_is_null(bpfptr_t bpfptr)
{
	if (bpfptr_is_kernel(bpfptr))
		return !bpfptr.kernel;
	return !bpfptr.user;
}

static inline void bpfptr_add(bpfptr_t *bpfptr, size_t val)
{
	if (bpfptr_is_kernel(*bpfptr))
		bpfptr->kernel += val;
	else
		bpfptr->user += val;
}

static inline int copy_from_bpfptr_offset(void *dst, bpfptr_t src,
					  size_t offset, size_t size)
{
	if (!bpfptr_is_kernel(src))
		return copy_from_user(dst, src.user + offset, size);
	return copy_from_kernel_nofault(dst, src.kernel + offset, size);
}

static inline int copy_from_bpfptr_offset_with_ptr(void *dst, bpfptr_t src,
						   size_t offset, size_t size)
{
	if (!bpfptr_is_kernel(src))
		return copy_from_user_with_ptr(dst, src.user + offset, size);
	return copy_from_kernel_nofault(dst, src.kernel + offset, size);
}

static inline int copy_from_bpfptr(void *dst, bpfptr_t src, size_t size)
{
	return copy_from_bpfptr_offset(dst, src, 0, size);
}

static inline int copy_from_bpfptr_with_ptr(void *dst, bpfptr_t src, size_t size)
{
	return copy_from_bpfptr_offset_with_ptr(dst, src, 0, size);
}

static inline int copy_to_bpfptr_offset(bpfptr_t dst, size_t offset,
					const void *src, size_t size)
{
	return copy_to_sockptr_offset((sockptr_t) dst, offset, src, size);
}

static inline void *kvmemdup_bpfptr(bpfptr_t src, size_t len)
{
	void *p = kvmalloc(len, GFP_USER | __GFP_NOWARN);

	if (!p)
		return ERR_PTR(-ENOMEM);
	if (copy_from_bpfptr(p, src, len)) {
		kvfree(p);
		return ERR_PTR(-EFAULT);
	}
	return p;
}

static inline long strncpy_from_bpfptr(char *dst, bpfptr_t src, size_t count)
{
	if (bpfptr_is_kernel(src))
		return strncpy_from_kernel_nofault(dst, src.kernel, count);
	return strncpy_from_user(dst, src.user, count);
}

#endif /* _LINUX_BPFPTR_H */
