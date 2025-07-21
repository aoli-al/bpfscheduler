mod bpf_skel;
use std::mem::MaybeUninit;
use std::process::Command;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

mod stats;
use anyhow::Context;
pub use bpf_skel::*;
use anyhow::Result;
use clap::Parser;
use log::info;
use nix::unistd::Pid;
use scx_stats::StatsServer;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use libbpf_rs::OpenObject;
use stats::Metrics;


#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_cosmos",
    version,
    disable_version_flag = true,
    about = "Lightweight scheduler optimized for preserving task-to-CPU locality."
)]
struct Opts {
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help_heading = "Test Command"
    )]
    pub args: Vec<String>,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    opts: &'a Opts,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(true);
        let mut skel = scx_ops_open!(skel_builder, open_object, cct_ops)?;
        skel.struct_ops.cct_ops_mut().exit_dump_len = 0;
        skel.maps.rodata_data.ppid_targeting_ppid = Pid::this().as_raw();

        let mut skel = scx_ops_load!(skel, cct_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, cct_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self { 
            skel, 
            opts, 
            struct_ops,
            stats_server
        })
    }

    pub fn observe(
        &self,
        shutdown: &(Mutex<bool>, Condvar),
    ) -> Result<()> {
        let (lock, cvar) = shutdown;
        let mut guard = lock.lock().unwrap();
        while !*guard {
            guard = cvar
                .wait_timeout(guard, Duration::from_millis(100))
                .unwrap()
                .0;
        }
        Ok(())
    }
}


fn main() -> Result<()> {
    let opts = Arc::new(Opts::parse());
    let shutdown = Arc::new((Mutex::new(false), Condvar::new()));

    ctrlc::set_handler({
        let shutdown = shutdown.clone();
        move || {
            let (lock, cvar) = &*shutdown;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
    })
    .context("Error setting Ctrl-C handler")?;

    let scheduler_thread = thread::spawn({
        let opts = opts.clone();
        let shutdown = shutdown.clone();
        move || -> Result<()> {
            let mut open_object = MaybeUninit::uninit();
            let sched= Scheduler::init(&opts, &mut open_object)?;
            sched.observe(&shutdown)?;
            Ok(())
        }
    });

    let (cmd, vargs) = opts.args.split_first().unwrap();

    let mut should_run_app = true;
        while should_run_app {

        let mut child = Command::new(cmd).args(vargs).spawn()?;
        loop {
            should_run_app &= !*shutdown.0.lock().unwrap();
            if scheduler_thread.is_finished() {
                child.kill()?;
                break;
            }
            if let Some(s) = child.try_wait()? {
                if s.success() {
                    should_run_app &= !*shutdown.0.lock().unwrap();
                    if should_run_app {
                        info!("app under test terminated successfully, restarting...");
                    };
                } else {
                    info!("TODO: report what the scheduler was doing when it crashed");
                    should_run_app = false;
                };
                break;
            };

            thread::sleep(Duration::from_millis(100));
        }
    }

    Ok(())
}
