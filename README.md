To use the bpfscheduler, you need to make sure the libc matches the libc linked by the binary.

To get the right libc, you can use the following command:

```bash
❯ ldd a.out
        linux-vdso.so.1 (0x00007f40ca15d000)
        libstdc++.so.6 => /nix/store/fkw48vh7ivlvlmhp4j30hy2gvg00jgin-gcc-14.3.0-lib/lib/libstdc++.so.6 (0x00007f40c9edb000)
        libm.so.6 => /nix/store/lmn7lwydprqibdkghw7wgcn21yhllz13-glibc-2.40-66/lib/libm.so.6 (0x00007f40c9df3000)
        libgcc_s.so.1 => /nix/store/fkw48vh7ivlvlmhp4j30hy2gvg00jgin-gcc-14.3.0-lib/lib/libgcc_s.so.1 (0x00007f40c9dc5000)
        libc.so.6 => /nix/store/lmn7lwydprqibdkghw7wgcn21yhllz13-glibc-2.40-66/lib/libc.so.6 (0x00007f40c9bbc000)
        /nix/store/lmn7lwydprqibdkghw7wgcn21yhllz13-glibc-2.40-66/lib/ld-linux-x86-64.so.2 => /nix/store/lmn7lwydprqibdkghw7wgcn21yhllz13-glibc-2.40-66/lib64/ld-linux-x86-64.so.2 (0x00007f40ca15f000)
```


Next copy the `libc.so.6` path to the `src/bpf/main.bpf.c` file and `src/lib.rs` file.


Run `cargo build --release` to compile the project.

Next run the SUT with the following command:

```bash

```