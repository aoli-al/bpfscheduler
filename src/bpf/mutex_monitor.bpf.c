/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pthread_mutex_lock monitor with random delay injection
 * 
 * This eBPF program intercepts pthread_mutex_lock calls and injects
 * random delays before the actual lock operation.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

const volatile __u64 max_delay_us = 1000;
const volatile __u8 enable_monitoring = 1;

struct mutex_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u64 delay_us;
    __u64 mutex_addr;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct mutex_stats {
    __u64 total_locks;
    __u64 total_unlocks;
    __u64 total_delay_us;
    __u64 max_delay_us;
    __u64 min_delay_us;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct mutex_stats));
    __uint(max_entries, 1);
} stats SEC(".maps");

static __always_inline void update_stats(__u64 delay_us)
{
    __u32 key = 0;
    struct mutex_stats *stat = bpf_map_lookup_elem(&stats, &key);
    if (!stat)
        return;

    __sync_fetch_and_add(&stat->total_locks, 1);
    __sync_fetch_and_add(&stat->total_delay_us, delay_us);
    
    if (delay_us > stat->max_delay_us)
        stat->max_delay_us = delay_us;
    
    if (stat->min_delay_us == 0 || delay_us < stat->min_delay_us)
        stat->min_delay_us = delay_us;
}

static __always_inline __u64 generate_random_delay(void)
{
    __u32 random = bpf_get_prandom_u32();
    return (random % max_delay_us) + 1;
}

static __always_inline void busy_wait_delay(__u64 delay_us)
{
    __u64 start = bpf_ktime_get_ns();
    __u64 end = start + (delay_us * 1000);
    
    volatile __u64 current;
    do {
        current = bpf_ktime_get_ns();
    } while (current < end);
}

SEC("uprobe/pthread_mutex_lock")
int mutex_lock_entry(struct pt_regs *ctx)
{
    if (!enable_monitoring)
        return 0;

    void *mutex = (void *)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    
    __u64 delay_us = generate_random_delay();
    
    struct mutex_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.delay_us = delay_us;
    event.mutex_addr = (__u64)mutex;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    busy_wait_delay(delay_us);
    
    update_stats(delay_us);
    
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int mutex_unlock_entry(struct pt_regs *ctx)
{
    if (!enable_monitoring)
        return 0;

    __u32 key = 0;
    struct mutex_stats *stat = bpf_map_lookup_elem(&stats, &key);
    if (stat)
        __sync_fetch_and_add(&stat->total_unlocks, 1);
    
    return 0;
}