/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */

#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile int ppid_targeting_ppid = 1;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dispatch_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could
 * just use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cct_task_ctx);
} controlled_task_ctxs SEC(".maps");


struct cct_task_ctx *lookup_create_controlled_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&controlled_task_ctxs, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
}


static __always_inline s32 calculate_control_match(struct task_struct *p)
{
	struct cct_task_ctx *taskc;
	struct task_struct *p2;
	enum cct_match flags = 0;
	int found_parent = 0;
	int ret = 0;
	int pid;

	if (!(taskc = lookup_create_controlled_task_ctx(p))) {
		scx_bpf_error("couldn't create task context");
		return -EINVAL;
	}

	// set one bit so we can check this step has been completed.
	taskc->match |= CONTROL_MATCH_COMPLETE;

	// no ppid targeting is covered by everything having CHAOS_MATCH_COMPLETE only
	if (ppid_targeting_ppid == -1)
		return 0;

	// no need for the path-to-root walk, this is the task
	if (ppid_targeting_ppid == p->pid) {
		taskc->match |= CONTROL_MATCH_NOT_CONTROLLED;
		return 0;
	}

	// we are matching on parent. if this task doesn't have one, exclude.
	if (!p->real_parent || !(pid = p->real_parent->pid)) {
		taskc->match |= CONTROL_MATCH_NOT_CONTROLLED;
		return 0;
	}

	// walk the real_parent path-to-root to check for the HAS_PARENT match
	bpf_repeat(CCT_NUM_PPIDS_CHECK) {
		p2 = bpf_task_from_pid(pid);
		if (!p2)
			break;

		if (!(taskc = lookup_create_chaos_task_ctx(p2))) {
			bpf_task_release(p2);
			scx_bpf_error("couldn't create task context");
			ret = -EINVAL;
			goto out;
		}

		// parent is matched and is in the parent path
		if (taskc->match & CHAOS_MATCH_HAS_PARENT) {
			flags |= CHAOS_MATCH_HAS_PARENT;
			found_parent = pid;
			bpf_task_release(p2);
			break;
		}

		// found the parent
		if (p2->pid == ppid_targeting_ppid) {
			flags |= CHAOS_MATCH_HAS_PARENT;
			found_parent = pid;
			bpf_task_release(p2);
			break;
		}

		// parent is matched and is not in the parent path
		if (taskc->match) {
			found_parent = pid;
			bpf_task_release(p2);
			break;
		}

		if (!p2->real_parent || !(pid = p2->real_parent->pid)) {
			bpf_task_release(p2);
			break;
		}

		bpf_task_release(p2);
	}

	if (!(flags & CHAOS_MATCH_HAS_PARENT))
		flags |= CHAOS_MATCH_EXCLUDED;

	if (!(taskc = lookup_create_chaos_task_ctx(p))) {
		scx_bpf_error("couldn't create task context");
		return -EINVAL;
	}
	taskc->match |= flags;

	if (!p->real_parent || !(pid = p->real_parent->pid))
		return 0;

	bpf_repeat(CHAOS_NUM_PPIDS_CHECK) {
		p2 = bpf_task_from_pid(pid);
		if (!p2)
			break;

		if (!(taskc = lookup_create_chaos_task_ctx(p2))) {
			bpf_task_release(p2);
			scx_bpf_error("couldn't create task context");
			ret = -EINVAL;
			goto out;
		}

		if (pid == found_parent) {
			bpf_task_release(p2);
			break;
		}

		taskc->match |= flags;

		if (!p2->real_parent || !(pid = p2->real_parent->pid)) {
			bpf_task_release(p2);
			break;
		}

		bpf_task_release(p2);
	}

out:
	return ret;
}




static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cct_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "cct");