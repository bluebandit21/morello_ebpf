#ifndef IOU_CORE_H
#define IOU_CORE_H

#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/eventpoll.h>
#include "io-wq.h"
#include "uring_cmd.h"
#include "slist.h"
#include "filetable.h"

#ifndef CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>
#endif

enum {
	/*
	 * A hint to not wake right away but delay until there are enough of
	 * tw's queued to match the number of CQEs the task is waiting for.
	 *
	 * Must not be used wirh requests generating more than one CQE.
	 * It's also ignored unless IORING_SETUP_DEFER_TASKRUN is set.
	 */
	IOU_F_TWQ_LAZY_WAKE			= 1,
};

enum {
	IOU_OK			= 0,
	IOU_ISSUE_SKIP_COMPLETE	= -EIOCBQUEUED,

	/*
	 * Intended only when both IO_URING_F_MULTISHOT is passed
	 * to indicate to the poll runner that multishot should be
	 * removed and the result is set on req->cqe.res.
	 */
	IOU_STOP_MULTISHOT	= -ECANCELED,
};

struct io_uring_cqe *__io_get_ith_cqe(struct io_ring_ctx *ctx, unsigned int i);
bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow);
void io_req_cqe_overflow(struct io_kiocb *req);
int io_run_task_work_sig(struct io_ring_ctx *ctx);
void io_req_defer_failed(struct io_kiocb *req, s32 res);
void io_req_complete_post(struct io_kiocb *req, unsigned issue_flags);
bool io_post_aux_cqe(struct io_ring_ctx *ctx, __kernel_uintptr_t user_data,
		     s32 res, u32 cflags);
bool io_fill_cqe_req_aux(struct io_kiocb *req, bool defer, s32 res, u32 cflags);
void __io_commit_cqring_flush(struct io_ring_ctx *ctx);

struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages);

struct file *io_file_get_normal(struct io_kiocb *req, int fd);
struct file *io_file_get_fixed(struct io_kiocb *req, int fd,
			       unsigned issue_flags);

void __io_req_task_work_add(struct io_kiocb *req, unsigned flags);
bool io_is_uring_fops(struct file *file);
bool io_alloc_async_data(struct io_kiocb *req);
void io_req_task_queue(struct io_kiocb *req);
void io_queue_iowq(struct io_kiocb *req, struct io_tw_state *ts_dont_use);
void io_req_task_complete(struct io_kiocb *req, struct io_tw_state *ts);
void io_req_task_queue_fail(struct io_kiocb *req, int ret);
void io_req_task_submit(struct io_kiocb *req, struct io_tw_state *ts);
void tctx_task_work(struct callback_head *cb);
__cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd);
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);

int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
				     int start, int end);

int io_poll_issue(struct io_kiocb *req, struct io_tw_state *ts);
int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr);
int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin);
void __io_submit_flush_completions(struct io_ring_ctx *ctx);
int io_req_prep_async(struct io_kiocb *req);

struct io_wq_work *io_wq_free_work(struct io_wq_work *work);
void io_wq_submit_work(struct io_wq_work *work);

void io_free_req(struct io_kiocb *req);
void io_queue_next(struct io_kiocb *req);
void io_task_refs_refill(struct io_uring_task *tctx);
bool __io_alloc_req_refill(struct io_ring_ctx *ctx);

bool io_match_task_safe(struct io_kiocb *head, struct task_struct *task,
			bool cancel_all);

void *io_mem_alloc(size_t size);
void io_mem_free(void *ptr);

#if defined(CONFIG_PROVE_LOCKING)
static inline void io_lockdep_assert_cq_locked(struct io_ring_ctx *ctx)
{
	lockdep_assert(in_task());

	if (ctx->flags & IORING_SETUP_IOPOLL) {
		lockdep_assert_held(&ctx->uring_lock);
	} else if (!ctx->task_complete) {
		lockdep_assert_held(&ctx->completion_lock);
	} else if (ctx->submitter_task) {
		/*
		 * ->submitter_task may be NULL and we can still post a CQE,
		 * if the ring has been setup with IORING_SETUP_R_DISABLED.
		 * Not from an SQE, as those cannot be submitted, but via
		 * updating tagged resources.
		 */
		if (ctx->submitter_task->flags & PF_EXITING)
			lockdep_assert(current_work());
		else
			lockdep_assert(current == ctx->submitter_task);
	}
}
#else
static inline void io_lockdep_assert_cq_locked(struct io_ring_ctx *ctx)
{
}
#endif

static inline void io_req_task_work_add(struct io_kiocb *req)
{
	__io_req_task_work_add(req, 0);
}

#define io_for_each_link(pos, head) \
	for (pos = (head); pos; pos = pos->link)

static inline bool io_in_compat64(struct io_ring_ctx *ctx)
{
	return IS_ENABLED(CONFIG_COMPAT64) && ctx->compat;
}

static inline bool io_user_data_is_same(__kernel_uintptr_t d1,
					__kernel_uintptr_t d2)
{
#ifdef CONFIG_CHERI_PURECAP_UABI
	return __builtin_cheri_equal_exact(d1, d2);
#else
	return d1 == d2;
#endif
}

static inline void convert_compat64_io_uring_sqe(struct io_ring_ctx *ctx,
						 struct io_uring_sqe *sqe,
						 const struct compat_io_uring_sqe *compat_sqe)
{
/*
 * The struct io_uring_sqe contains anonymous unions and there is no field
 * keeping track of which union's member is active. Because in all the cases,
 * the unions are between integral types and the types are compatible, use the
 * largest member of each union to perform the copy. Use this compile-time check
 * to ensure that the union's members are not truncated during the conversion.
 */
#define BUILD_BUG_COMPAT_SQE_UNION_ELEM(elem1, elem2) \
	BUILD_BUG_ON(sizeof_field(struct compat_io_uring_sqe, elem1) != \
		(offsetof(struct compat_io_uring_sqe, elem2) - \
		 offsetof(struct compat_io_uring_sqe, elem1)))

	sqe->opcode = READ_ONCE(compat_sqe->opcode);
	sqe->flags = READ_ONCE(compat_sqe->flags);
	sqe->ioprio = READ_ONCE(compat_sqe->ioprio);
	sqe->fd = READ_ONCE(compat_sqe->fd);
	BUILD_BUG_COMPAT_SQE_UNION_ELEM(addr2, addr);
	/*
	 * Some opcodes set a user_data value in the addr2 field to propagate
	 * it as-is to the user_data field of a CQE. It's not dereferenced
	 * by the kernel, so don't modify it.
	 */
	switch (sqe->opcode) {
	case IORING_OP_POLL_REMOVE:
	case IORING_OP_MSG_RING:
		sqe->addr2 = (__kernel_uintptr_t)READ_ONCE(compat_sqe->addr2);
		break;
	default:
		sqe->addr2 = (__kernel_uintptr_t)compat_ptr(READ_ONCE(compat_sqe->addr2));
		break;
	}

	BUILD_BUG_COMPAT_SQE_UNION_ELEM(addr, len);
	/*
	 * Some opcodes set a user_data value in the addr field to be matched
	 * with a pre-existing IO event's user_data. It's not dereferenced by
	 * the kernel, so don't modify it.
	 */
	switch (sqe->opcode) {
	case IORING_OP_POLL_REMOVE:
	case IORING_OP_TIMEOUT_REMOVE:
	case IORING_OP_ASYNC_CANCEL:
		sqe->addr = (__kernel_uintptr_t)READ_ONCE(compat_sqe->addr);
		break;
	default:
		sqe->addr = (__kernel_uintptr_t)compat_ptr(READ_ONCE(compat_sqe->addr));
		break;
	}

	sqe->len = READ_ONCE(compat_sqe->len);
	BUILD_BUG_COMPAT_SQE_UNION_ELEM(rw_flags, user_data);
	sqe->rw_flags = READ_ONCE(compat_sqe->rw_flags);
	sqe->user_data = (__kernel_uintptr_t)READ_ONCE(compat_sqe->user_data);
	BUILD_BUG_COMPAT_SQE_UNION_ELEM(buf_index, personality);
	sqe->buf_index = READ_ONCE(compat_sqe->buf_index);
	sqe->personality = READ_ONCE(compat_sqe->personality);
	BUILD_BUG_COMPAT_SQE_UNION_ELEM(splice_fd_in, addr3);
	sqe->splice_fd_in = READ_ONCE(compat_sqe->splice_fd_in);
	if (sqe->opcode == IORING_OP_URING_CMD) {
		size_t native_cmd_size, compat_cmd_size;

		native_cmd_size = sizeof(struct io_uring_sqe) -
				  offsetof(struct io_uring_sqe, cmd);
		compat_cmd_size = sizeof(struct compat_io_uring_sqe) -
				  offsetof(struct compat_io_uring_sqe, cmd);
		if (ctx->flags & IORING_SETUP_SQE128) {
			native_cmd_size += sizeof(struct io_uring_sqe);
			compat_cmd_size += sizeof(struct compat_io_uring_sqe);
		}

		memcpy_and_pad(sqe->cmd, native_cmd_size,
			       compat_sqe->cmd, compat_cmd_size, 0);
	} else {
		sqe->addr3 = (__kernel_uintptr_t)compat_ptr(READ_ONCE(compat_sqe->addr3));
		sqe->__pad2[0] = READ_ONCE(compat_sqe->__pad2[0]);
	}
#undef BUILD_BUG_COMPAT_SQE_UNION_ELEM
}

static inline bool io_get_cqe_overflow(struct io_ring_ctx *ctx,
					struct io_uring_cqe **ret,
					bool overflow)
{
	io_lockdep_assert_cq_locked(ctx);

	if (unlikely(ctx->cqe_cached >= ctx->cqe_sentinel)) {
		if (unlikely(!io_cqe_cache_refill(ctx, overflow)))
			return false;
	}
	*ret = __io_get_ith_cqe(ctx, ctx->cqe_cached);
	ctx->cached_cq_tail++;
	ctx->cqe_cached++;
	if (ctx->flags & IORING_SETUP_CQE32)
		ctx->cqe_cached++;
	return true;
}

static inline bool io_get_cqe(struct io_ring_ctx *ctx, struct io_uring_cqe **ret)
{
	return io_get_cqe_overflow(ctx, ret, false);
}

static inline void __io_fill_cqe(struct io_ring_ctx *ctx, struct io_uring_cqe *cqe,
				 __kernel_uintptr_t user_data, s32 res, u32 cflags,
				 u64 extra1, u64 extra2)
{
	if (io_in_compat64(ctx)) {
		struct compat_io_uring_cqe *compat_cqe = (struct compat_io_uring_cqe *)cqe;

		WRITE_ONCE(compat_cqe->user_data, (__u64)user_data);
		WRITE_ONCE(compat_cqe->res, res);
		WRITE_ONCE(compat_cqe->flags, cflags);

		if (ctx->flags & IORING_SETUP_CQE32) {
			WRITE_ONCE(compat_cqe->big_cqe[0], extra1);
			WRITE_ONCE(compat_cqe->big_cqe[1], extra2);
		}
		return;
	}

	WRITE_ONCE(cqe->user_data, user_data);
	WRITE_ONCE(cqe->res, res);
	WRITE_ONCE(cqe->flags, cflags);

	if (ctx->flags & IORING_SETUP_CQE32) {
		WRITE_ONCE(cqe->big_cqe[0], extra1);
		WRITE_ONCE(cqe->big_cqe[1], extra2);
	}
}

static __always_inline bool io_fill_cqe_req(struct io_ring_ctx *ctx,
					    struct io_kiocb *req)
{
	struct io_uring_cqe *cqe;

	/*
	 * If we can't get a cq entry, userspace overflowed the
	 * submission (by quite a lot). Increment the overflow count in
	 * the ring.
	 */
	if (unlikely(!io_get_cqe(ctx, &cqe)))
		return false;

	if (trace_io_uring_complete_enabled())
		trace_io_uring_complete(req->ctx, req, req->cqe.user_data,
					req->cqe.res, req->cqe.flags,
					req->big_cqe.extra1, req->big_cqe.extra2);

	__io_fill_cqe(ctx, cqe, req->cqe.user_data, req->cqe.res,
		      req->cqe.flags, req->big_cqe.extra1, req->big_cqe.extra2);
	if (ctx->flags & IORING_SETUP_CQE32) {
		memset(&req->big_cqe, 0, sizeof(req->big_cqe));
	}
	return true;
}

static inline void req_set_fail(struct io_kiocb *req)
{
	req->flags |= REQ_F_FAIL;
	if (req->flags & REQ_F_CQE_SKIP) {
		req->flags &= ~REQ_F_CQE_SKIP;
		req->flags |= REQ_F_SKIP_LINK_CQES;
	}
}

static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)
{
	req->cqe.res = res;
	req->cqe.flags = cflags;
}

static inline bool req_has_async_data(struct io_kiocb *req)
{
	return req->flags & REQ_F_ASYNC_DATA;
}

static inline void io_put_file(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_FIXED_FILE) && req->file)
		fput(req->file);
}

static inline void io_ring_submit_unlock(struct io_ring_ctx *ctx,
					 unsigned issue_flags)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (issue_flags & IO_URING_F_UNLOCKED)
		mutex_unlock(&ctx->uring_lock);
}

static inline void io_ring_submit_lock(struct io_ring_ctx *ctx,
				       unsigned issue_flags)
{
	/*
	 * "Normal" inline submissions always hold the uring_lock, since we
	 * grab it from the system call. Same is true for the SQPOLL offload.
	 * The only exception is when we've detached the request and issue it
	 * from an async worker thread, grab the lock for that case.
	 */
	if (issue_flags & IO_URING_F_UNLOCKED)
		mutex_lock(&ctx->uring_lock);
	lockdep_assert_held(&ctx->uring_lock);
}

static inline void io_commit_cqring(struct io_ring_ctx *ctx)
{
	/* order cqe stores with ring update */
	smp_store_release(&ctx->rings->cq.tail, ctx->cached_cq_tail);
}

static inline void io_poll_wq_wake(struct io_ring_ctx *ctx)
{
	if (wq_has_sleeper(&ctx->poll_wq))
		__wake_up(&ctx->poll_wq, TASK_NORMAL, 0,
				poll_to_key(EPOLL_URING_WAKE | EPOLLIN));
}

static inline void io_cqring_wake(struct io_ring_ctx *ctx)
{
	/*
	 * Trigger waitqueue handler on all waiters on our waitqueue. This
	 * won't necessarily wake up all the tasks, io_should_wake() will make
	 * that decision.
	 *
	 * Pass in EPOLLIN|EPOLL_URING_WAKE as the poll wakeup key. The latter
	 * set in the mask so that if we recurse back into our own poll
	 * waitqueue handlers, we know we have a dependency between eventfd or
	 * epoll and should terminate multishot poll at that point.
	 */
	if (wq_has_sleeper(&ctx->cq_wait))
		__wake_up(&ctx->cq_wait, TASK_NORMAL, 0,
				poll_to_key(EPOLL_URING_WAKE | EPOLLIN));
}

static inline bool io_sqring_full(struct io_ring_ctx *ctx)
{
	struct io_rings *r = ctx->rings;

	return READ_ONCE(r->sq.tail) - ctx->cached_sq_head == ctx->sq_entries;
}

static inline unsigned int io_sqring_entries(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;
	unsigned int entries;

	/* make sure SQ entry isn't read before tail */
	entries = smp_load_acquire(&rings->sq.tail) - ctx->cached_sq_head;
	return min(entries, ctx->sq_entries);
}

static inline int io_run_task_work(void)
{
	/*
	 * Always check-and-clear the task_work notification signal. With how
	 * signaling works for task_work, we can find it set with nothing to
	 * run. We need to clear it for that case, like get_signal() does.
	 */
	if (test_thread_flag(TIF_NOTIFY_SIGNAL))
		clear_notify_signal();
	/*
	 * PF_IO_WORKER never returns to userspace, so check here if we have
	 * notify work that needs processing.
	 */
	if (current->flags & PF_IO_WORKER &&
	    test_thread_flag(TIF_NOTIFY_RESUME)) {
		__set_current_state(TASK_RUNNING);
		resume_user_mode_work(NULL);
	}
	if (task_work_pending(current)) {
		__set_current_state(TASK_RUNNING);
		task_work_run();
		return 1;
	}

	return 0;
}

static inline bool io_task_work_pending(struct io_ring_ctx *ctx)
{
	return task_work_pending(current) || !wq_list_empty(&ctx->work_llist);
}

static inline void io_tw_lock(struct io_ring_ctx *ctx, struct io_tw_state *ts)
{
	if (!ts->locked) {
		mutex_lock(&ctx->uring_lock);
		ts->locked = true;
	}
}

/*
 * Don't complete immediately but use deferred completion infrastructure.
 * Protected by ->uring_lock and can only be used either with
 * IO_URING_F_COMPLETE_DEFER or inside a tw handler holding the mutex.
 */
static inline void io_req_complete_defer(struct io_kiocb *req)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_submit_state *state = &req->ctx->submit_state;

	lockdep_assert_held(&req->ctx->uring_lock);

	wq_list_add_tail(&req->comp_list, &state->compl_reqs);
}

static inline void io_commit_cqring_flush(struct io_ring_ctx *ctx)
{
	if (unlikely(ctx->off_timeout_used || ctx->drain_active ||
		     ctx->has_evfd || ctx->poll_activated))
		__io_commit_cqring_flush(ctx);
}

static inline void io_get_task_refs(int nr)
{
	struct io_uring_task *tctx = current->io_uring;

	tctx->cached_refs -= nr;
	if (unlikely(tctx->cached_refs < 0))
		io_task_refs_refill(tctx);
}

static inline bool io_req_cache_empty(struct io_ring_ctx *ctx)
{
	return !ctx->submit_state.free_list.next;
}

extern struct kmem_cache *req_cachep;
extern struct kmem_cache *io_buf_cachep;

static inline struct io_kiocb *io_extract_req(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	req = container_of(ctx->submit_state.free_list.next, struct io_kiocb, comp_list);
	wq_stack_extract(&ctx->submit_state.free_list);
	return req;
}

static inline bool io_alloc_req(struct io_ring_ctx *ctx, struct io_kiocb **req)
{
	if (unlikely(io_req_cache_empty(ctx))) {
		if (!__io_alloc_req_refill(ctx))
			return false;
	}
	*req = io_extract_req(ctx);
	return true;
}

static inline bool io_allowed_defer_tw_run(struct io_ring_ctx *ctx)
{
	return likely(ctx->submitter_task == current);
}

static inline bool io_allowed_run_tw(struct io_ring_ctx *ctx)
{
	return likely(!(ctx->flags & IORING_SETUP_DEFER_TASKRUN) ||
		      ctx->submitter_task == current);
}

static inline void io_req_queue_tw_complete(struct io_kiocb *req, s32 res)
{
	io_req_set_res(req, res, 0);
	req->io_task_work.func = io_req_task_complete;
	io_req_task_work_add(req);
}

/*
 * IORING_SETUP_SQE128 contexts allocate twice the normal SQE size for each
 * slot.
 */
static inline size_t uring_sqe_size(struct io_ring_ctx *ctx)
{
	if (ctx->flags & IORING_SETUP_SQE128)
		return 2 * sizeof(struct io_uring_sqe);
	return sizeof(struct io_uring_sqe);
}
#endif
