use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();

    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("mutex_monitor.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/mutex_monitor.bpf.c")
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed=src/bpf/mutex_monitor.bpf.c");
}
