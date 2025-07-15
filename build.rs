use std::env;
use std::path::PathBuf;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/runqslower.bpf.c";
const HEADER: &str = "src/bpf/runqslower.h";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("runqslower.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={HEADER}");
}
