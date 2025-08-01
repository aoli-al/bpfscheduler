{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    scx-src = {
      url = "github:sched-ext/scx/89a7736c71370335660980aa31a62482f1cd32d1";
      flake = false;
    };
  };

  outputs = { self, rust-overlay, flake-utils, nixpkgs, scx-src }:
    flake-utils.lib.eachDefaultSystem (system: 
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          name = "bpfscheduler";
          version = "0.1.0";
          cargoHash = "sha256-utEBWyHlvlSztjyQjZ9ga842lJsUOQIFB3P0EPV7sao=";
          hardeningDisable = [ "all" ];
          buildInputs = with pkgs; [
            zlib
            elfutils.dev
            elfutils.out
            libbpf
            bear
            rustfmt
            llvmPackages_20.clang-tools  
            llvmPackages_20.libcxx
            llvmPackages_20.clang
          ];

          nativeBuildInputs = with pkgs; [
            rustPlatform.bindgenHook
            pkg-config
            # llvmPackages_20.clang.lib
            linuxHeaders
          ];

          preConfigure = ''
            export SCX_SRC="${scx-src}";
            '';
          src = ./.;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          shellHook = ''
            unset NIX_HARDENING_ENABLE
            export LD_LIBRARY_PATH=${pkgs.elfutils.out}/lib
            export RUST_SRC_PATH="${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
            export SCX_SRC="${scx-src}";
          '';
        };
      });
}

