#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Full quality + security suite: formatting, lint, tests, no_std build, SCA, secrets.
# Run locally or in CI. Host target defaults to macOS arm64 (override with HOST_TARGET).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST_TARGET:-aarch64-apple-darwin}"

run() { echo; echo "== $1 =="; shift; "$@"; }

run "fmt"                      cargo fmt --all --check
run "clippy (embedded)"        cargo clippy --workspace -- -D warnings
run "clippy (host tests)"      cargo clippy -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-mgmt -p rsk-oath -p rsk-otp -p rsk-piv -p rsk-rescue --target "$HOST" --all-targets -- -D warnings
run "test (host)"              cargo test -p rsk-sdk -p rsk-fs -p rsk-usb -p rsk-crypto -p rsk-fido -p rsk-openpgp -p rsk-rsa-asm -p rsk-mgmt -p rsk-oath -p rsk-otp -p rsk-piv -p rsk-rescue --target "$HOST"
# The PQC-advertisement opt-in changes the getInfo shape — test both forms.
run "test (advertise-pqc)"     cargo test -p rsk-fido --features advertise-pqc --target "$HOST" getinfo
run "build firmware (release)" cargo build --release -p firmware
# The test build: no BOOTSEL presence, so the automated suites don't hang on a touch.
run "build firmware (test, --no-default-features)" cargo build --release -p firmware --no-default-features
run "build rsk-wipe (release)" cargo build --release -p rsk-wipe
# RUSTSEC-2023-0071: rsa Marvin timing side-channel — no fixed release; it is the
# OpenPGP RSA backend, mitigated by blinding. Justification in deny.toml.
run "cargo-audit (SCA)"        cargo audit --ignore RUSTSEC-2023-0071
run "cargo-deny"               cargo deny check
run "gitleaks (tree)"          gitleaks detect --redact --no-banner

echo
echo "ALL CHECKS PASSED"
