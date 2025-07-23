#ifndef __MUTEX_INTF_H
#define __MUTEX_INTF_H

#ifndef __KERNEL__
typedef unsigned long long u64;
typedef unsigned int u32;
#endif

struct mutex_stats {
    u64 total_locks;
    u64 total_unlocks;
    u64 total_delay_us;
    u64 max_delay_us;
    u64 min_delay_us;
};

struct mutex_config {
    u64 max_delay_us;
    _Bool enable_monitoring;
};

#endif /* __MUTEX_INTF_H */