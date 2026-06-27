{
  description = "MTP - Methanium Transport Protocol";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [rust-overlay.overlays.default];
        pkgs = import nixpkgs {inherit system overlays;};

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
          ];
          targets = ["wasm32-unknown-unknown"];
        };

        clippyCheck = pkgs.writeShellApplication {
          name = "mtp-clippy";
          runtimeInputs = [rustToolchain];
          text = ''
            export MTP_TYPE_MAPS="''${MTP_TYPE_MAPS:-$PWD/example-usage/type-maps.yaml}"
            cargo clippy --workspace --exclude mtp-wasm --all-targets --all-features -- -D warnings -W unreachable-pub
          '';
        };

        macheteCheck = pkgs.writeShellApplication {
          name = "mtp-machete";
          runtimeInputs = [pkgs.cargo-machete];
          text = ''
            cargo machete "$@"
          '';
        };

        buildAll = pkgs.writeShellApplication {
          name = "mtp-build-all";
          runtimeInputs = [rustToolchain pkgs.wasm-pack pkgs.bun clippyCheck macheteCheck];
          text = ''
            export MTP_TYPE_MAPS="''${MTP_TYPE_MAPS:-$PWD/example-usage/type-maps.yaml}"

            bun install --frozen-lockfile
            cargo fmt --all --check
            cargo b
            cargo test --workspace --exclude mtp-wasm --all-features
            cargo check --manifest-path example-usage/Cargo.toml --workspace --all-targets --all-features
            mtp-clippy
            mtp-machete
            bun run dup
            RUSTFLAGS='--cfg web_sys_unstable_apis' wasm-pack build wasm --target web --out-dir pkg --release
            bun --cwd example-usage/web-client install --frozen-lockfile
            bun --cwd example-usage/web-client run build
          '';
        };

        healthCheck = pkgs.writeShellApplication {
          name = "mtp-health";
          runtimeInputs = [clippyCheck macheteCheck];
          text = ''
            mtp-clippy
            mtp-machete
          '';
        };
      in {
        devShells = {
          default = pkgs.mkShell {
            name = "mtp-dev";

            buildInputs = with pkgs; [
              rustToolchain
              cargo-machete
              wasm-pack
              pkg-config
              openssl
            ];

            MTP_TYPE_MAPS = "${toString ./example-usage/type-maps.yaml}";

            shellHook = ''
              repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
              cert_dir="$repo_root/example-usage/dev-cert"
              public_dir="$repo_root/example-usage/web-client/public"
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
            ];
            shellHook = ''
              nix develop --command bash -c "mprocs 'cd wasm && wasm-pack build --target web --out-dir pkg && cd ../example-usage/web-client && bun dev' 'cargo b && cd example-usage && cargo r --bin server' 'cd example-usage && cargo r --bin client'"
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
              "wasm"
              "--target"
              "web"
            ];
          };
        };
      }
    );
}
