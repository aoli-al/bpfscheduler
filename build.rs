fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
}
