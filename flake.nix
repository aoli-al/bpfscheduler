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
        packages.default = (naersk.lib.${system}.override {
          cargo = toolchain;
          rustc = toolchain;
        }).buildPackage {
          hardeningDisable = [ "all" ];
          buildInputs = with pkgs; [
            llvmPackages_20.clang-unwrapped
            zlib
            elfutils.out
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
            patchelf
          ];
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
          shellHook = ''
            export LD_LIBRARY_PATH=${pkgs.elfutils.out}/lib:${pkgs.zlib}/lib:${pkgs.libbpf}/lib:$LD_LIBRARY_PATH
          '';
        };
      });
}

