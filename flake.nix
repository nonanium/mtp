{
  description = "MTP - Methanium Transport Protocol";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
          ];
          targets = [ "wasm32-unknown-unknown" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "mtp-dev";

          buildInputs = with pkgs; [
            rustToolchain
            wasm-pack
            pkg-config
            openssl
          ];

          MTP_TYPE_MAPS = "${toString ./example-usage/type-maps.yaml}";

          shellHook = ''
            echo "MTP dev shell"
            echo "  rustc  : $(rustc --version)"
            echo "  cargo  : $(cargo --version)"
            echo "  wasm-pack : $(wasm-pack --version 2>/dev/null || echo 'not found')"
            echo "  targets: $(rustc --print target-list | grep wasm32 | tr '\n' ' ')"
            echo "  MTP_TYPE_MAPS = $MTP_TYPE_MAPS"
          '';
        };

        # Ad-hoc WASM build using wasm-pack
        apps.wasm-build = {
          type = "app";
          program = "${pkgs.wasm-pack}/bin/wasm-pack";
          args = [
            "build"
            "wasm"
            "--target"
            "web"
          ];
        };
      }
    );
}
