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

#define P2DQ_CREATE_STRUCT_OPS 0
#include "scx_p2dq/main.bpf.c"
#include "intf.h"
#include "vmlinux.h"

const volatile int ppid_targeting_ppid = 1;

UEI_DEFINE(uei);

#define SHARED_DSQ 0

#define __COMPAT_chaos_scx_bpf_dsq_move_set_slice(it__iter, slice)             \
  (bpf_ksym_exists(scx_bpf_dsq_move_set_slice)                                 \
       ? scx_bpf_dsq_move_set_slice((it__iter), (slice))                       \
       : scx_bpf_dispatch_from_dsq_set_slice___compat((it__iter), (slice)))

#define __COMPAT_chaos_scx_bpf_dsq_move(it__iter, p, dsq_id, enq_flags)        \
  (bpf_ksym_exists(scx_bpf_dsq_move)                                           \
       ? scx_bpf_dsq_move((it__iter), (p), (dsq_id), (enq_flags))              \
       : scx_bpf_dispatch_from_dsq___compat((it__iter), (p), (dsq_id),         \
                                            (enq_flags)))

#define __COMPAT_chaos_scx_bpf_dsq_move_set_vtime(it__iter, vtime)             \
  (bpf_ksym_exists(scx_bpf_dsq_move_set_vtime)                                 \
       ? scx_bpf_dsq_move_set_vtime((it__iter), (vtime))                       \
       : scx_bpf_dispatch_from_dsq_set_vtime___compat((it__iter), (vtime)))

#define __COMPAT_chaos_scx_bpf_dsq_move_vtime(it__iter, p, dsq_id, enq_flags)  \
  (bpf_ksym_exists(scx_bpf_dsq_move_vtime)                                     \
       ? scx_bpf_dsq_move_vtime((it__iter), (p), (dsq_id), (enq_flags))        \
       : scx_bpf_dispatch_vtime_from_dsq___compat((it__iter), (p), (dsq_id),   \
                                                  (enq_flags)))

static __always_inline void
complete_p2dq_enqueue_move(struct enqueue_promise *pro,
                           struct bpf_iter_scx_dsq *it__iter,
                           struct task_struct *p) {
  switch (pro->kind) {
  case P2DQ_ENQUEUE_PROMISE_COMPLETE:
    scx_bpf_error("chaos: delayed async_p2dq_enqueue returned COMPLETE"
                  " after a task was placed in the delay dsq!");
    break;
  case P2DQ_ENQUEUE_PROMISE_FIFO:
    __COMPAT_chaos_scx_bpf_dsq_move_set_slice(
        it__iter, *MEMBER_VPTR(pro->fifo, .slice_ns));
    __COMPAT_chaos_scx_bpf_dsq_move(it__iter, p, pro->fifo.dsq_id,
                                    pro->fifo.enq_flags);
    break;
  case P2DQ_ENQUEUE_PROMISE_VTIME:
    __COMPAT_chaos_scx_bpf_dsq_move_set_slice(it__iter, pro->vtime.slice_ns);
    __COMPAT_chaos_scx_bpf_dsq_move_set_vtime(it__iter, pro->vtime.vtime);
    __COMPAT_chaos_scx_bpf_dsq_move_vtime(it__iter, p, pro->vtime.dsq_id,
                                          pro->vtime.enq_flags);
    break;
  case P2DQ_ENQUEUE_PROMISE_ATQ_FIFO:
  case P2DQ_ENQUEUE_PROMISE_ATQ_VTIME:
    scx_bpf_error("chaos: ATQs not supported");
    break;
  case P2DQ_ENQUEUE_PROMISE_FAILED:
    scx_bpf_error("chaos: delayed async_p2dq_enqueue failed");
    break;
  }

  if (pro->kick_idle)
    scx_bpf_kick_cpu(pro->cpu, SCX_KICK_IDLE);

  pro->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
}

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

static __always_inline void
destroy_p2dq_enqueue_promise(struct enqueue_promise *pro) {
  // If the idle bit of a CPU has already been cleared but we don't plan
  // to execute a task on it we should kick the CPU. If the CPU goes to
  // sleep again it will reset the kernel managed idle state.
  if (pro->has_cleared_idle)
    scx_bpf_kick_cpu(pro->cpu, SCX_KICK_IDLE);
}

__weak int async_p2dq_enqueue_weak(struct enqueue_promise *ret __arg_nonnull,
                                   struct task_struct *p __arg_trusted,
                                   u64 enq_flags) {
  async_p2dq_enqueue(ret, p, enq_flags);
  return 0;
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

out:
  return ret;
}

static __always_inline u64 get_cpu_delay_dsq(int cpu_idx) {
  if (cpu_idx >= 0)
    return CCT_DSQ_BASE | cpu_idx;

  cpu_idx = bpf_get_smp_processor_id();
  return CCT_DSQ_BASE | cpu_idx;
}

void BPF_STRUCT_OPS(cct_enqueue, struct task_struct *p, u64 enq_flags) {
  struct enqueue_promise promise;
  struct cct_task_ctx *taskc;

  if (!(taskc = lookup_create_cct_task_ctx(p))) {
    scx_bpf_error("failed to lookup task context in enqueue");
    return;
  }

  // capture vtime before the potentially discarded enqueue
  taskc->p2dq_vtime = p->scx.dsq_vtime;

  async_p2dq_enqueue(&promise, p, enq_flags);
  if (promise.kind == P2DQ_ENQUEUE_PROMISE_COMPLETE)
    return;
  if (promise.kind == P2DQ_ENQUEUE_PROMISE_FAILED)
    goto cleanup;

  complete_p2dq_enqueue(&promise, p);
  return;
cleanup:
  destroy_p2dq_enqueue_promise(&promise);
}

void BPF_STRUCT_OPS(cct_task_tick, struct task_struct *p) {}

void BPF_STRUCT_OPS(cct_dispatch, s32 cpu, struct task_struct *prev) {
  struct enqueue_promise promise;
  struct cct_task_ctx *taskc;
  struct task_struct *p;
  u64 now = bpf_ktime_get_ns();

  bpf_for_each(scx_dsq, p, get_cpu_delay_dsq(-1), 0) {
    p = bpf_task_from_pid(p->pid);
    if (!p)
      continue;

    if (!(taskc = lookup_create_cct_task_ctx(p))) {
      scx_bpf_error("couldn't find task context");
      bpf_task_release(p);
      break;
    }

    if (p->scx.dsq_vtime > now) {
      bpf_task_release(p);
      break; // this is the DSQ's key so we're done
    }

    // restore vtime to p2dq's timeline
    p->scx.dsq_vtime = taskc->p2dq_vtime;

    async_p2dq_enqueue_weak(&promise, p, SCX_ENQ_PREEMPT);
    complete_p2dq_enqueue_move(&promise, BPF_FOR_EACH_ITER, p);
    bpf_task_release(p);
  }

  return p2dq_dispatch_impl(cpu, prev);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cct_init) {
  struct timer_wrapper *timerw;
  struct llc_ctx *llcx;
  struct cpu_ctx *cpuc;
  int timer_id, ret, i;

  bpf_for(i, 0, topo_config.nr_cpus) {
    if (!(cpuc = lookup_cpu_ctx(i)) || !(llcx = lookup_llc_ctx(cpuc->llc_id)))
      return -EINVAL;

    ret = scx_bpf_create_dsq(CCT_DSQ_BASE | i, llcx->node_id);
    if (ret < 0)
      return ret;
  }
  return p2dq_init_impl();
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cct_init_task, struct task_struct *p,
                             struct scx_init_task_args *args) {
  s32 ret = calculate_cct_match(p);
  if (ret)
    return ret;
  return 0;
}

void BPF_STRUCT_OPS(cct_running, struct task_struct *p) {
  p2dq_running_impl(p);
}

SEC("uprobe//nix/store/g2jzxk3s7cnkhh8yq55l4fbvf639zy37-glibc-2.40-66/lib/"
    "libc.so.6:pthread_mutex_lock")
int mutex_lock_entry(struct pt_regs *ctx) {
  struct task_struct *p = (struct task_struct *)bpf_get_current_task_btf();
  struct cct_task_ctx *taskc;
  if (!(taskc = lookup_create_cct_task_ctx(p))) {
    bpf_printk("couldn't find task context for task %d\n", p->pid);
    return 0;
  }
  if (taskc->match & CCT_MATCH_HAS_PARENT) {
    bpf_printk("task(%s) %d is controlled by CCT, requesting yield\n", p->comm,
               p->pid);
    taskc->should_yield = 1;
    return 0;
  }

  return 0;
}

SCX_OPS_DEFINE(cct_ops, .tick = (void *)cct_task_tick,
               .enqueue = (void *)cct_enqueue, .running = (void *)cct_running,
               .stopping = (void *)p2dq_stopping,
               .dispatch = (void *)cct_dispatch, .init = (void *)cct_init,
               .init_task = (void *)cct_init_task, .exit = (void *)p2dq_exit,
               .exit_task = (void *)p2dq_exit_task,
               .set_cpumask = (void *)p2dq_set_cpumask,
               .update_idle = (void *)p2dq_update_idle,
               .flags = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
               .name = "cct");