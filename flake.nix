# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

{
  description = "RS-Key (RSK) — an open security-key firmware for the RP2350: FIDO2, OpenPGP, PIV, OATH, OTP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, fenix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        fx = fenix.packages.${system};

        # RP2350 = dual Cortex-M33 -> thumbv8m.main-none-eabihf (hardware float).
        # (RP2350 also has RISC-V Hazard3 cores; we target the ARM cores, which embassy-rp supports.)
        target = "thumbv8m.main-none-eabihf";

        toolchain = fx.combine [
          fx.stable.toolchain
          fx.targets.${target}.stable.rust-std
        ];

        # cargo-fuzz needs nightly (libfuzzer + -Zsanitizer); host target only.
        fuzzToolchain = fx.complete.toolchain;

        # ML-DSA (FIPS 204) reference implementation in pure Python — not in
        # nixpkgs; used by the PQC device test to verify signatures.
        dilithiumPy = pkgs.python3Packages.buildPythonPackage rec {
          pname = "dilithium_py";
          version = "1.4.0";
          pyproject = true;
          src = pkgs.fetchPypi {
            inherit pname version;
            sha256 = "0ai54hjqniwcyqw4kibxnd3by0vqc78nm45gl1i2009lmz35bm5n";
          };
          build-system = [ pkgs.python3Packages.hatchling ];
          # the 'pkcs' extra (ecdsa) is not needed; no runtime deps
          doCheck = false;
        };

        # Tiny prompt-with-timeout helper the vendored pico-fido suite imports —
        # not in nixpkgs.
        inputimeoutPy = pkgs.python3Packages.buildPythonPackage rec {
          pname = "inputimeout";
          version = "1.0.4";
          format = "wheel";
          src = pkgs.fetchPypi {
            inherit pname version;
            format = "wheel";
            python = "py3";
            dist = "py3";
            sha256 = "0hss8wij922igihjdliiv052hinw7qmdbj7giqk2bz1wflkkvqpl";
          };
          doCheck = false;
        };

        # The host-side Python for the `rsk` CLI (tools/rsk) + the device tests.
        rskPython = pkgs.python3.withPackages (ps: [
          ps.hidapi          # FIDO CTAPHID transport
          ps.cryptography    # P-256 ECDH / AES-CBC / HMAC (clientPIN + MSE backup)
          ps.pyscard         # PC/SC for the CCID applets
          ps.mnemonic        # BIP-39 seed rendering
          ps.shamir-mnemonic # SLIP-39 Shamir shares
          ps.fido2           # `rsk fido` set-pin / list-passkeys
          ps.pytest          # third_party/ conformance suites
          inputimeoutPy      # prompt helper used by the vendored FIDO suite
          dilithiumPy        # ML-DSA-44 verification (PQC device test)
          # ykman as an importable module (keyboard-OTP test drives its OtpConnection)
          (ps.toPythonModule pkgs.yubikey-manager)
        ]);

        # `rsk` as a first-class dev-shell command: finds the repo root, puts
        # tools/ on PYTHONPATH, and runs the package. Works from any subdir and
        # under `nix develop -c rsk ...`.
        rskBin = pkgs.writeShellScriptBin "rsk" ''
          root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"
          export PYTHONPATH="$root/tools''${PYTHONPATH:+:$PYTHONPATH}"
          exec ${rskPython}/bin/python -m rsk "$@"
        '';

        # `rsk-tui` — the Rust ratatui dashboard (tools/tui, its own workspace).
        # cargo-runs it for the host target (overriding the repo's thumbv8m
        # default); first run compiles, then it is instant. Reads device state natively.
        rskTui = pkgs.writeShellScriptBin "rsk-tui" ''
          root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"
          host="$(rustc -vV | sed -n 's/host: //p')"
          exec cargo run --release --quiet --target "$host" \
            --manifest-path "$root/tools/tui/Cargo.toml" -- "$@"
        '';
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            toolchain
            pkgs.flip-link        # stack-overflow-safe linker for embedded
            pkgs.probe-rs-tools   # flash/debug over SWD (optional; needs a probe)
            pkgs.picotool         # ELF -> UF2 + BOOTSEL flashing, no probe needed
            pkgs.pkg-config
            pkgs.gcc-arm-embedded # arm-none-eabi-gcc — builds rsk-rsa-asm's C+ARM-asm
                                  # fast RSA modexp. `cc` auto-detects it.

            pkgs.yubikey-manager  # ykman CLI (device management, guides)
            pkgs.libgcrypt        # the vendored OpenPGP card suite loads it via ctypes

            # Security tooling (see scripts/check.sh).
            pkgs.gitleaks         # secret detection (pre-commit hook over staged diff)
            pkgs.cargo-audit      # SCA: RustSec advisory scan of Cargo.lock
            pkgs.cargo-deny       # SCA: advisories + licenses + source/ban policy

            # Host-side tooling: the `rsk` CLI (tools/rsk) + the `rsk-tui` dashboard
            # (tools/tui) + the CTAPHID/FIDO device tests (tests/). See rskPython
            # above for the Python deps.
            rskPython
            rskBin
            rskTui
          ];

          shellHook = ''
            # the Gnuk-derived OpenPGP card suite (third_party/) dlopens libgcrypt
            export DYLD_FALLBACK_LIBRARY_PATH="${pkgs.lib.getLib pkgs.libgcrypt}/lib''${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
            export LD_LIBRARY_PATH="${pkgs.lib.getLib pkgs.libgcrypt}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

            # Install repo git hooks (idempotent; symlinked so edits take effect).
            if [ -d .git ] && [ -f scripts/hooks/pre-commit ]; then
              ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
            fi

            echo "rs-key devshell"
            echo "  rustc:    $(rustc --version 2>/dev/null)"
            echo "  target:   ${target}"
            echo "  picotool: $(picotool version 2>/dev/null | head -1 || echo 'n/a')"
            echo
            echo "Build:  cargo build --release -p firmware   # pick the target crate"
            echo "UF2:    picotool uf2 convert target/${target}/release/firmware -t elf firmware.uf2"
            echo "Flash:  hold BOOTSEL, plug in the RP2350, drag firmware.uf2 to the RP2350 drive"
            echo "Check:  ./scripts/check.sh        # fmt + clippy + test + audit + deny + gitleaks"
            echo "Fuzz:   nix develop .#fuzz -c cargo fuzz run <target>"
            echo "CLI:    rsk status | rsk backup … | rsk secure-boot … | rsk otp … (rsk --help)"
            echo "TUI:    rsk-tui                    # live device dashboard"
          '';
        };

        # Nightly shell for cargo-fuzz: `nix develop .#fuzz -c cargo fuzz run apdu`.
        devShells.fuzz = pkgs.mkShell {
          packages = [ fuzzToolchain pkgs.cargo-fuzz ];
          shellHook = ''
            echo "rs-key fuzz devshell (nightly)"
            echo "  rustc: $(rustc --version 2>/dev/null)"
            echo "List:   cargo fuzz list"
            echo "Run:    cargo fuzz run <target> -- -max_total_time=30"
          '';
        };
      });
}
