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

#include "intf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

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
#define CCT_DSQ 1

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u64));
  __uint(max_entries, 2); /* [local, global] */
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct cct_task_ctx);
} controlled_task_ctxs SEC(".maps");

struct cct_task_ctx *lookup_create_cct_task_ctx(struct task_struct *p) {
  return bpf_task_storage_get(&controlled_task_ctxs, p, NULL,
                              BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline s32 calculate_cct_match(struct task_struct *p) {
  struct cct_task_ctx *taskc;
  struct task_struct *p2;
  enum cct_match flags = 0;
  int found_parent = 0;
  int ret = 0;
  int pid;

  if (!(taskc = lookup_create_cct_task_ctx(p))) {
    scx_bpf_error("couldn't create task context");
    return -EINVAL;
  }

  taskc->match |= CCT_MATCH_COMPLETE;
  taskc->priority = bpf_get_prandom_u32();

  if (ppid_targeting_ppid == -1)
    return 0;

  if (ppid_targeting_ppid == p->pid) {
    taskc->match |= CCT_MATCH_NOT_CONTROLLED;
    return 0;
  }

  // we are matching on parent. if this task doesn't have one, exclude.
  if (!p->real_parent || !(pid = p->real_parent->pid)) {
    taskc->match |= CCT_MATCH_NOT_CONTROLLED;
    return 0;
  }

  // walk the real_parent path-to-root to check for the HAS_PARENT match
  bpf_repeat(CCT_NUM_PPIDS_CHECK) {
    p2 = bpf_task_from_pid(pid);
    if (!p2)
      break;

    if (!(taskc = lookup_create_cct_task_ctx(p2))) {
      bpf_task_release(p2);
      scx_bpf_error("couldn't create task context");
      ret = -EINVAL;
      goto out;
    }

    // parent is matched and is in the parent path
    if (taskc->match & CCT_MATCH_HAS_PARENT) {
      flags |= CCT_MATCH_HAS_PARENT;
      found_parent = pid;
      bpf_task_release(p2);
      break;
    }

    // found the parent
    if (p2->pid == ppid_targeting_ppid) {
      flags |= CCT_MATCH_HAS_PARENT;
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

  if (!(flags & CCT_MATCH_HAS_PARENT))
    flags |= CCT_MATCH_NOT_CONTROLLED;

  if (!(taskc = lookup_create_cct_task_ctx(p))) {
    scx_bpf_error("couldn't create task context");
    return -EINVAL;
  }
  taskc->match |= flags;

  if (!p->real_parent || !(pid = p->real_parent->pid))
    return 0;

  bpf_repeat(CCT_NUM_PPIDS_CHECK) {
    p2 = bpf_task_from_pid(pid);
    if (!p2)
      break;

    if (!(taskc = lookup_create_cct_task_ctx(p2))) {
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

  // if (flags & CCT_MATCH_HAS_PARENT) {
  // 	bpf_printk("task(%s) %d matched CCT with flags %x\n",
  // 		   p->comm, p->pid, flags);
  // } else {
  // 	// bpf_printk("task(%s) %d did not match CCT with flags %x\n",
  // 	// 	   p->comm, p->pid, flags);
  // }

out:
  return ret;
}

static inline bool vtime_before(u64 a, u64 b) { return (s64)(a - b) < 0; }

// s32 BPF_STRUCT_OPS(cct_select_cpu, struct task_struct *p, s32 prev_cpu, u64
// wake_flags)
// {
// 	bool is_idle = false;
// 	s32 cpu;
// 	struct cct_task_ctx *taskc;

// 	taskc = lookup_create_cct_task_ctx(p);
// 	if (!(taskc = lookup_create_cct_task_ctx(p)))
// 		goto out;

// 	if (taskc->match & CCT_MATCH_HAS_PARENT) {
// 		bpf_printk("task(%s) %d is being scheduled on CPU %d\n",
// 			   p->comm, p->pid, prev_cpu);
// 		return prev_cpu;
// 	}

// out:
// 	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
// 	if (is_idle) {
// 		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
// 	}

// 	return cpu;
// }

void BPF_STRUCT_OPS(cct_task_running, struct task_struct *p) {
  if (!p)
    return;
  struct cct_task_ctx *taskc;
  if (!(taskc = lookup_create_cct_task_ctx(p))) {
    scx_bpf_error("couldn't create task context");
    return;
  }
  if (taskc->match & CCT_MATCH_HAS_PARENT) {
    bpf_printk("task(%s) %d is running in CCT\n", p->comm, p->pid);
  }
}

void BPF_STRUCT_OPS(cct_task_stopping, struct task_struct *p) {
  if (!p)
	return;
  struct cct_task_ctx *taskc;
  if (!(taskc = lookup_create_cct_task_ctx(p))) {
	scx_bpf_error("couldn't create task context");
	return;
  }
  if (taskc->match & CCT_MATCH_HAS_PARENT) {
	bpf_printk("task(%s) %d is stopping in CCT\n", p->comm, p->pid);
  }
}

void BPF_STRUCT_OPS(cct_task_quiescent, struct task_struct *p) {
  if (!p)
	return;
  struct cct_task_ctx *taskc;
  if (!(taskc = lookup_create_cct_task_ctx(p))) {
	scx_bpf_error("couldn't create task context");
	return;
  }
  if (taskc->match & CCT_MATCH_HAS_PARENT) {
	bpf_printk("task(%s) %d is quiescing in CCT\n", p->comm, p->pid);
	// scx_bpf_dsq_insert(p, CCT_DSQ, SCX_SLICE_DFL, SCX_ENQ_PREEMPT);
  }
}

void BPF_STRUCT_OPS(cct_enqueue, struct task_struct *p, u64 enq_flags) {

  struct cct_task_ctx *taskc;
  if (!(taskc = lookup_create_cct_task_ctx(p))) {
    scx_bpf_error("couldn't create task context");
    return;
  }

  if (taskc->match & CCT_MATCH_HAS_PARENT) {
	bpf_printk("task(%s) %d is being enqueued in CCT\n", p->comm, p->pid);
    scx_bpf_dsq_insert(p, CCT_DSQ, 1000, enq_flags);
  } else {
    u64 vtime = p->scx.dsq_vtime;
    if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
      vtime = vtime_now - SCX_SLICE_DFL;

    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
  }
}

void BPF_STRUCT_OPS(cct_task_tick, struct task_struct *p) {
  if (p) {
    struct cct_task_ctx *prev_taskc = lookup_create_cct_task_ctx(p);
    if (prev_taskc && (prev_taskc->match & CCT_MATCH_HAS_PARENT) &&
        bpf_get_prandom_u32() % 10 < 10) {
    //   scx_bpf_dsq_insert(p, CCT_DSQ, SCX_SLICE_DFL, SCX_ENQ_PREEMPT);
      //   scx_bpf_dispatch(p, CCT_DSQ, SCX_SLICE_DFL, SCX_ENQ_PREEMPT);

      scx_bpf_kick_cpu(8, SCX_KICK_PREEMPT);
    //   bpf_printk("Task %s (%d) kicked to CCT_DSQ\n", p->comm, p->pid);
    }
  }
}

void BPF_STRUCT_OPS(cct_dispatch, s32 cpu, struct task_struct *prev) {

  if (cpu == 8) {
    u32 cct_dsq_length = scx_bpf_dsq_nr_queued(CCT_DSQ);
    if (cct_dsq_length > 1) {
      bpf_printk("CCT_DSQ length: %u\n", cct_dsq_length);
    }

    struct cct_task_ctx *taskc;
    struct task_struct *p;
    u64 initial_dsq = CCT_DSQ;
    u32 highest_priority = 0;
    s32 highest_task_pid = 0;
    bpf_for_each(scx_dsq, p, initial_dsq, 0) {
      if (!(taskc = lookup_create_cct_task_ctx(p))) {
        scx_bpf_error("couldn't find task context");
        break;
      }
      u32 priority = bpf_get_prandom_u32();
      if (priority > highest_priority) {
        highest_priority = priority;
        highest_task_pid = p->pid;
      }
    }
    bpf_for_each(scx_dsq, p, initial_dsq, 0) {
      struct bpf_iter_scx_dsq *iter = BPF_FOR_EACH_ITER;
      if (p->pid == highest_task_pid) {
        scx_bpf_dsq_move(iter, p, SCX_DSQ_LOCAL_ON | cpu, SCX_ENQ_PREEMPT);
		bpf_printk("Task %s (%d) moved to CCT_DSQ\n", p->comm, p->pid);
      }
    }
  }
  scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cct_init) {
  int ret;
  ret = scx_bpf_create_dsq(CCT_DSQ, -1);
  if (ret < 0) {
    scx_bpf_error("failed to create CCT DSQ");
    return ret;
  }
  ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
  if (ret < 0) {
    scx_bpf_error("failed to create shared DSQ");
  }
  return ret;
}

void BPF_STRUCT_OPS(cct_exit, struct scx_exit_info *ei) { UEI_RECORD(uei, ei); }

s32 BPF_STRUCT_OPS_SLEEPABLE(cct_init_task, struct task_struct *p,
                             struct scx_init_task_args *args) {
  s32 ret = calculate_cct_match(p);
  if (ret)
    return ret;
  return 0;
}

SCX_OPS_DEFINE(cct_ops,
				// .select_cpu		= (void *)cct_select_cpu,
               .enqueue = (void *)cct_enqueue,
               .running = (void *)cct_task_running,
			   .stopping = (void *)cct_task_stopping,
			   .quiescent = (void *)cct_task_quiescent,
               .dispatch = (void *)cct_dispatch, 
			   .init = (void *)cct_init,
               .init_task = (void *)cct_init_task,
               .tick = (void *)cct_task_tick, 
			   .exit = (void *)cct_exit,
			   .flags = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
               .name = "cct");