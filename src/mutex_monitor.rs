use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::{PerfBufferBuilder, UprobeOpts, MapCore, OpenObject};
use libbpf_rs::skel::{SkelBuilder, OpenSkel};
use log::{info, warn};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod mutex_bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/mutex_monitor.skel.rs"));
}
use mutex_bpf_skel::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MutexEvent {
    pid: u32,
    tid: u32,
    timestamp: u64,
    delay_us: u64,
    mutex_addr: u64,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MutexStats {
    total_locks: u64,
    total_unlocks: u64,
    total_delay_us: u64,
    max_delay_us: u64,
    min_delay_us: u64,
}

#[derive(Debug, Parser)]
#[command(
    name = "mutex_monitor",
    version,
    about = "Monitor pthread_mutex_lock calls with random delay injection"
)]
struct Opts {
    #[arg(
        short,
        long,
        default_value = "1000",
        help = "Maximum delay in microseconds"
    )]
    max_delay: u64,

    #[arg(
        short,
        long,
        help = "Target binary to monitor"
    )]
    target: String,

    #[arg(
        short,
        long,
        default_value = "5",
        help = "Statistics reporting interval in seconds"
    )]
    stats_interval: u64,

    #[arg(
        long,
        help = "Disable delay injection (monitoring only)"
    )]
    no_delay: bool,
}

struct MutexMonitor<'a> {
    skel: MutexMonitorSkel<'a>,
    opts: Opts,
}

impl<'a> MutexMonitor<'a> {
    fn init(opts: Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let mut skel_builder = MutexMonitorSkelBuilder::default();
        skel_builder.obj_builder.debug(true);
        
        let open_skel = skel_builder.open(open_object)?;
        
        // Set configuration
        open_skel.maps.rodata_data.max_delay_us = opts.max_delay;
        open_skel.maps.rodata_data.enable_monitoring = if opts.no_delay { 0 } else { 1 };
        
        let skel = open_skel.load()?;
        
        // Attach uprobes to the target binary  
        let uprobe_opts = UprobeOpts {
            ref_ctr_offset: 0,
            cookie: 0,
            retprobe: false,
            func_name: "pthread_mutex_lock".to_string(),
            ..Default::default()
        };

        let _lock_link = skel.progs
            .mutex_lock_entry
            .attach_uprobe_with_opts(-1, &opts.target, 0, uprobe_opts)
            .context("Failed to attach pthread_mutex_lock uprobe")?;

        let uprobe_opts_unlock = UprobeOpts {
            ref_ctr_offset: 0,
            cookie: 0,
            retprobe: false,
            func_name: "pthread_mutex_unlock".to_string(),
            ..Default::default()
        };

        let _unlock_link = skel.progs
            .mutex_unlock_entry
            .attach_uprobe_with_opts(-1, &opts.target, 0, uprobe_opts_unlock)
            .context("Failed to attach pthread_mutex_unlock uprobe")?;

        Ok(Self { skel, opts })
    }

    fn handle_event(_cpu: i32, data: &[u8]) {
        if data.len() != std::mem::size_of::<MutexEvent>() {
            warn!("Invalid event size: {}", data.len());
            return;
        }

        let event = unsafe { &*(data.as_ptr() as *const MutexEvent) };
        let comm = String::from_utf8_lossy(&event.comm)
            .trim_end_matches('\0')
            .to_string();

        info!(
            "Mutex lock: PID={}, TID={}, comm={}, delay={}μs, mutex=0x{:x}",
            event.pid, event.tid, comm, event.delay_us, event.mutex_addr
        );
    }

    fn print_stats(&self) -> Result<()> {
        let stats_map = &self.skel.maps.stats;
        let key = 0u32;
        
        match stats_map.lookup(&key.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            Ok(Some(value)) => {
                if value.len() == std::mem::size_of::<MutexStats>() {
                    let stats = unsafe { &*(value.as_ptr() as *const MutexStats) };
                    
                    let avg_delay = if stats.total_locks > 0 {
                        stats.total_delay_us / stats.total_locks
                    } else {
                        0
                    };

                    info!("=== Mutex Monitor Statistics ===");
                    info!("Total locks: {}", stats.total_locks);
                    info!("Total unlocks: {}", stats.total_unlocks);
                    info!("Total delay: {}μs", stats.total_delay_us);
                    info!("Average delay: {}μs", avg_delay);
                    info!("Min delay: {}μs", stats.min_delay_us);
                    info!("Max delay: {}μs", stats.max_delay_us);
                    info!("================================");
                }
            }
            Ok(None) => {
                info!("No statistics available yet");
            }
            Err(e) => {
                warn!("Failed to read statistics: {}", e);
            }
        }
        
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .context("Error setting Ctrl-C handler")?;

        info!("Starting mutex monitor for target: {}", self.opts.target);
        info!("Max delay: {}μs", self.opts.max_delay);
        info!("Delay injection: {}", !self.opts.no_delay);

        let perf_buffer = PerfBufferBuilder::new(&self.skel.maps.events)
            .sample_cb(Self::handle_event)
            .lost_cb(|cpu, count| {
                warn!("Lost {} events on CPU {}", count, cpu);
            })
            .build()?;

        let mut last_stats = Instant::now();
        let stats_interval = Duration::from_secs(self.opts.stats_interval);

        while running.load(Ordering::SeqCst) {
            if let Err(e) = perf_buffer.poll(Duration::from_millis(100)) {
                warn!("Error polling perf buffer: {}", e);
                break;
            }

            if last_stats.elapsed() >= stats_interval {
                if let Err(e) = self.print_stats() {
                    warn!("Error printing stats: {}", e);
                }
                last_stats = Instant::now();
            }
        }

        info!("Final statistics:");
        let _ = self.print_stats();
        info!("Mutex monitor stopped");

        Ok(())
    }
}

fn main() -> Result<()> {
    env_logger::init();
    
    let opts = Opts::parse();
    let mut open_object = MaybeUninit::uninit();
    let mut monitor = MutexMonitor::init(opts, &mut open_object)?;
    monitor.run()
}