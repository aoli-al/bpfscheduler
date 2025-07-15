{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, fenix, flake-utils, naersk, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system: 
      let
        pkgs = nixpkgs.legacyPackages.${system};
        toolchain = with fenix.packages.${system}; combine [
          minimal.cargo
          minimal.rustc
        ];
      in
      {
        # packages.default = (naersk.lib.${system}.override {
        #   cargo = toolchain;
        #   rustc = toolchain;
        # }).buildPackage
        packages.default = pkgs.rustPlatform.buildRustPackage {
          name = "bpfscheduler";
          version = "0.1.0";
          cargoHash = "sha256-aR2C+ftiRLb9tfiYkblT05EwKV3SjLUiHtlvA8LrV/M=";
          hardeningDisable = [ "all" ];
          buildInputs = with pkgs; [
            zlib
            elfutils.dev
            elfutils.out
            libbpf
          ];

          nativeBuildInputs = with pkgs; [
            rustPlatform.bindgenHook
            pkg-config
            llvmPackages_20.clang-unwrapped
          ];
          preBuild = ''
            export LD_LIBRARY_PATH=${pkgs.elfutils.out}/lib
          '';
          src = ./.;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            toolchain
            llvmPackages_20.clang-unwrapped
            zlib
            libbpf
            elfutils
            pkg-config
          ];
        };
      });
}

