{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, fenix, flake-utils, nixpkgs }:
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
          cargoHash = "sha256-Dapq2pu1ojD78E8MlATXzVuwhpTLHNpW4u78L/rnP34=";
          hardeningDisable = [ "all" ];
          buildInputs = with pkgs; [
            zlib
            elfutils.dev
            elfutils.out
            libbpf
            bear
          ];

          nativeBuildInputs = with pkgs; [
            rustPlatform.bindgenHook
            pkg-config
            llvmPackages_20.clang
            # llvmPackages_20.clang.lib
            llvmPackages_20.clang-tools  
            linuxHeaders
          ];
          src = ./.;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          shellHook = ''
            unset NIX_HARDENING_ENABLE
            export LD_LIBRARY_PATH=${pkgs.elfutils.out}/lib
          '';
        };
      });
}

