/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  include/linux/eventpoll.h ( Efficient event polling implementation )
 *  Copyright (C) 2001,...,2006	 Davide Libenzi
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 */
#ifndef _LINUX_EVENTPOLL_H
#define _LINUX_EVENTPOLL_H

#include <linux/compat.h>
#include <uapi/linux/eventpoll.h>
#include <uapi/linux/kcmp.h>


/* Forward declarations to avoid compiler errors */
struct file;


#ifdef CONFIG_EPOLL

#ifdef CONFIG_KCMP
struct file *get_epoll_tfile_raw_ptr(struct file *file, int tfd, unsigned long toff);
#endif

/* Used to release the epoll bits inside the "struct file" */
void eventpoll_release_file(struct file *file);

/*
 * This is called from inside fs/file_table.c:__fput() to unlink files
 * from the eventpoll interface. We need to have this facility to cleanup
 * correctly files that are closed without being removed from the eventpoll
 * interface.
 */
static inline void eventpoll_release(struct file *file)
{

	/*
	 * Fast check to avoid the get/release of the semaphore. Since
	 * we're doing this outside the semaphore lock, it might return
	 * false negatives, but we don't care. It'll help in 99.99% of cases
	 * to avoid the semaphore lock. False positives simply cannot happen
	 * because the file in on the way to be removed and nobody ( but
	 * eventpoll ) has still a reference to this file.
	 */
	if (likely(!file->f_ep))
		return;

	/*
	 * The file is being closed while it is still linked to an epoll
	 * descriptor. We need to handle this by correctly unlinking it
	 * from its containers.
	 */
	eventpoll_release_file(file);
}

int do_epoll_ctl(int epfd, int op, int fd, struct epoll_event *epds,
		 bool nonblock);

/* Tells if the epoll_ctl(2) operation needs an event copy from userspace */
static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}

#else

static inline void eventpoll_release(struct file *file) {}

#endif

struct compat_epoll_event {
	__poll_t events;
	__u64 data;
};

#if defined(CONFIG_ARM) && defined(CONFIG_OABI_COMPAT)
/* ARM OABI has an incompatible struct layout and needs a special handler */
extern struct epoll_event __user *
epoll_put_uevent(__poll_t revents, __u64 data,
		 struct epoll_event __user *uevent);
#else
static inline struct epoll_event __user *
epoll_put_uevent(__poll_t revents, __kernel_uintptr_t data,
		 struct epoll_event __user *uevent)
{
	if (in_compat_syscall()) {
		struct compat_epoll_event __user *compat_uevent =
				(struct compat_epoll_event __user *)uevent;

		if (__put_user(revents, &compat_uevent->events) ||
		    __put_user((__u64)data, &compat_uevent->data))
			return NULL;

		return (struct epoll_event __user *)(compat_uevent+1);
	}

	if (__put_user(revents, &uevent->events) ||
	    __put_user_ptr(data, &uevent->data))
		return NULL;

	return uevent+1;
}
#endif

int copy_epoll_event_from_user(struct epoll_event *epds,
			       const void __user *user_epds,
			       bool compat);

#endif /* #ifndef _LINUX_EVENTPOLL_H */
