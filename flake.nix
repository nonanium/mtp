{
  description = "MTP - Methanium Transport Protocol";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      eachSystem =
        f:
        nixpkgs.lib.foldl' nixpkgs.lib.recursiveUpdate { } (
          map (system: nixpkgs.lib.mapAttrs (_: value: { ${system} = value; }) (f system)) systems
        );
    in
    eachSystem (
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

        # Cargo build scripts are native executables.  Keeping their artifacts
        # separate from builds made with another Nix toolchain prevents Cargo
        # from trying to execute a script whose dynamic linker was garbage
        # collected after a nixpkgs update.
        cargoTargetDir = ".cargo-target/${builtins.baseNameOf (toString rustToolchain)}-${builtins.baseNameOf (toString pkgs.stdenv.cc)}";

        clippyCheck = pkgs.writeShellApplication {
          name = "mtp-clippy";
          runtimeInputs = [ rustToolchain ];
          text = ''
            export MTP_TYPE_MAPS="''${MTP_TYPE_MAPS:-$PWD/tests/fixtures/example/type-maps.yaml}"
            export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-$PWD/${cargoTargetDir}}"
            cargo clippy --workspace --exclude mtp-wasm --exclude client --exclude server --exclude keygen --all-targets --all-features -- -D warnings -W unreachable-pub
          '';
        };

        macheteCheck = pkgs.writeShellApplication {
          name = "mtp-machete";
          runtimeInputs = [ pkgs.cargo-machete ];
          text = ''
            cargo machete "$@"
          '';
        };

        buildAll = pkgs.writeShellApplication {
          name = "mtp-build-all";
          runtimeInputs = [
            rustToolchain
            pkgs.cargo-deny
            pkgs.wasm-pack
            pkgs.pnpm
            pkgs.nodejs
            pkgs.coreutils
            pkgs.stdenv.cc
            pkgs.pkg-config
            pkgs.openssl
            clippyCheck
            macheteCheck
          ];
          text = ''
            export MTP_TYPE_MAPS="''${MTP_TYPE_MAPS:-$PWD/tests/fixtures/example/type-maps.yaml}"
            export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-$PWD/${cargoTargetDir}}"

            export PKG_CONFIG_PATH="${
              let
                libraries = pkgs.lib.closePropagation (map pkgs.lib.getDev [
                  pkgs.openssl
                  pkgs.glib
                  pkgs.gtk3
                  pkgs.webkitgtk_4_1
                  pkgs.libsoup_3
                ]);
              in
              pkgs.lib.makeSearchPath "lib/pkgconfig" libraries
              + ":"
              + pkgs.lib.makeSearchPath "share/pkgconfig" libraries
            }''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

            timeout 60s pnpm install --frozen-lockfile
            cargo build
            cargo test --workspace --exclude mtp-wasm --all-features
            cargo check -p client -p server -p keygen --all-targets --all-features
            mtp-clippy
            mtp-machete
            pnpm run build
            RUSTFLAGS="--cfg web_sys_unstable_apis" wasm-pack test --node bindings/wasm
            pnpm --dir sdk run test:e2e
            pnpm --dir sdk run test:secrets
            pnpm --dir sdk run test:wasm-init
            pnpm --dir sdk run test:types
            pnpm --dir sdk run test:vite
            pnpm --dir sdk run test:boundary
            pnpm --dir sdk pack
            pnpm --filter mtp-web-client run build
          '';
        };

        healthCheck = pkgs.writeShellApplication {
          name = "mtp-health";
          runtimeInputs = [
            clippyCheck
            macheteCheck
          ];
          text = ''
            mtp-clippy
            mtp-machete
          '';
        };
      in
      {
        devShells = {
          default = pkgs.mkShell {
            name = "mtp-dev";

            buildInputs = with pkgs; [
              rustToolchain
              cargo-deny
              cargo-machete
              wasm-pack
              pnpm
              pkg-config
              openssl
              glib
              gtk3
              webkitgtk_4_1
              libsoup_3
            ];

            MTP_TYPE_MAPS = "${toString ./tests/fixtures/example/type-maps.yaml}";

            shellHook = ''
              repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
              export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-$repo_root/${cargoTargetDir}}"
              cert_dir="$repo_root/tests/fixtures/example/dev-cert"
              public_dir="$repo_root/tests/fixtures/example/web-client/public"
              cert_key="$cert_dir/key.pem"
              cert_pem="$cert_dir/cert.pem"
              cert_hash="$cert_dir/sha256.txt"

              mkdir -p "$cert_dir"
              mkdir -p "$public_dir"

              if [ ! -f "$cert_key" ] || [ ! -f "$cert_pem" ]; then
                openssl ecparam -name prime256v1 -genkey -noout -out "$cert_key"
                openssl req -new -x509 \
                  -sha256 \
                  -key "$cert_key" \
                  -out "$cert_pem" \
                  -days 13 \
                  -subj "/CN=localhost" \
                  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
                  -addext "basicConstraints=critical,CA:FALSE" \
                  -addext "keyUsage=critical,digitalSignature" \
                  -addext "extendedKeyUsage=serverAuth"
                cert_status="generated"
              else
                cert_status="cached"
              fi

              openssl x509 -in "$cert_pem" -outform der \
                | openssl dgst -sha256 -binary \
                | od -An -tx1 -v \
                | tr -d ' \n' > "$cert_hash"
              cp "$cert_hash" "$public_dir/mtp_dev_cert_hash.txt"

              export MTP_DEV_CERT="$cert_pem"
              export MTP_DEV_KEY="$cert_key"
              export MTP_DEV_CERT_HASH="$(cat "$cert_hash")"
            '';
          };
          autoStart = pkgs.mkShell {
            name = "autoStart";
            buildInputs = with pkgs; [
              mprocs
              pnpm
            ];
            shellHook = ''
              nix develop --command bash -c "mprocs 'pnpm --dir sdk build:wasm && pnpm --dir tests/fixtures/example/web-client dev' 'cargo run -p server' 'cargo run -p client'"
              exit
            '';
          };
        };

        # Ad-hoc WASM build using wasm-pack
        apps = {
          clippy = {
            type = "app";
            program = "${clippyCheck}/bin/mtp-clippy";
          };
          machete = {
            type = "app";
            program = "${macheteCheck}/bin/mtp-machete";
          };
          build-all = {
            type = "app";
            program = "${buildAll}/bin/mtp-build-all";
          };
          health = {
            type = "app";
            program = "${healthCheck}/bin/mtp-health";
          };
          wasm-build = {
            type = "app";
            program = "${pkgs.wasm-pack}/bin/wasm-pack";
            args = [
              "build"
              "bindings/wasm"
              "--target"
              "web"
            ];
          };
        };
      }
    );
}
