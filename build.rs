use std::io::Write;
use scx_p2dq;


fn main() {
    let include_path = std::env::var("OUT_DIR").unwrap() + "/include";
    std::fs::create_dir_all(include_path.clone() + "/scx_p2dq").unwrap();
    let mut file = std::fs::File::create(include_path.clone() + "/scx_p2dq/main.bpf.c").unwrap();
    file.write_all(scx_p2dq::bpf_srcs::main_bpf_c()).unwrap();
    let mut file = std::fs::File::create(include_path.clone() + "/scx_p2dq/intf.h").unwrap();
    file.write_all(scx_p2dq::bpf_srcs::intf_h()).unwrap();
    let mut file = std::fs::File::create(include_path.clone() + "/scx_p2dq/types.h").unwrap();
    file.write_all(scx_p2dq::bpf_srcs::types_h()).unwrap();

    let mut extra_flags = vec!["-I".to_string() + &include_path];
    if let Ok(e) = std::env::var("BPF_EXTRA_CFLAGS_POST_INCL") {
        extra_flags.push(e);
    }
    unsafe {
        std::env::set_var("BPF_EXTRA_CFLAGS_POST_INCL", extra_flags.join(" "));
    }


    let scx_source = std::env::var("SCX_SRC").expect("SCX_SRC environment variable not set").to_string();
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source(&format!("{}/lib/arena.bpf.c", scx_source))
        .add_source(&format!("{}/lib/atq.bpf.c", scx_source))
        .add_source(&format!("{}/lib/bitmap.bpf.c", scx_source))
        .add_source(&format!("{}/lib/minheap.bpf.c", scx_source))
        .add_source(&format!("{}/lib/sdt_alloc.bpf.c", scx_source))
        .add_source(&format!("{}/lib/sdt_task.bpf.c", scx_source))
        .add_source(&format!("{}/lib/topology.bpf.c", scx_source))
        .compile_link_gen()
        .unwrap();
}
