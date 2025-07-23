{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, rust-overlay, flake-utils, nixpkgs }:
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
          cargoHash = "sha256-Dapq2pu1ojD78E8MlATXzVuwhpTLHNpW4u78L/rnP34=";
          hardeningDisable = [ "all" ];
          buildInputs = with pkgs; [
            zlib
            elfutils.dev
            elfutils.out
            libbpf
            bear
            (rust-bin.stable.latest.default.override {
              extensions = ["rust-src" "rust-analyzer"];
            })
          ];

          nativeBuildInputs = with pkgs; [
            rustPlatform.bindgenHook
            pkg-config
            llvmPackages_20.clang-tools  
            llvmPackages_20.clang
            llvmPackages_20.libcxx
            # llvmPackages_20.clang.lib
            linuxHeaders
          ];
          src = ./.;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          shellHook = ''
            unset NIX_HARDENING_ENABLE
            export LD_LIBRARY_PATH=${pkgs.elfutils.out}/lib
            export RUST_SRC_PATH="${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
          '';
        };
      });
}

