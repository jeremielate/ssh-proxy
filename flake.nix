{
  description = "SSH proxy interface";

  inputs.nixpkgs = {
    type = "github";
    owner = "NixOS";
    repo = "nixpkgs";
  };

  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    all@{
      self,
      nixpkgs,
      rust-overlay,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEachSupportedSystem =
        f:
        nixpkgs.lib.genAttrs supportedSystems (
          system:
          f rec {
            overlays = [ (import rust-overlay) ];
            pkgs = import nixpkgs {
              inherit system overlays;
            };
          }
        );
    in
    rec {
      packages = forEachSupportedSystem (
        { pkgs, ... }:
        {
          default = pkgs.rustPlatform.buildRustPackage {
            name = "ssh-proxy";
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            src = self;
            postUnpack = ''
              export CARGO_HOME=$PWD/.cargo
            '';
          };
        }
      );

      devShells = forEachSupportedSystem (
        { pkgs, ... }:
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rust-bin.stable.latest.complete
            ];
          };
        }
      );
      defaultPackage = (nixpkgs.lib.genAttrs supportedSystems (system: packages.${system}.default));
    };
}
