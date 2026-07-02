#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# Refactor reconnaissance — advisory metrics, NOT a gate. Run it when deciding
# *where* to refactor; nothing here gates a commit (that stays scripts/check.sh).
# The signals: function complexity (rust-code-analysis), firmware size by
# crate/function (cargo-bloat), and generic monomorphization (cargo-llvm-lines).
#
# The three tools are pulled ad-hoc via `nix shell nixpkgs#…` so they do NOT
# join the pinned dev shell / SBOM trust base — they never touch a shipping
# build. Run inside the dev shell (for cargo + the cross target):
#   nix develop -c ./scripts/metrics.sh [crate-src-dir ...]
# With no args it profiles the applet command handlers (the long INS/CBOR
# dispatchers); pass paths to scope the complexity pass elsewhere.
set -euo pipefail
cd "$(dirname "$0")/.."

crates=("$@")
if [ "${#crates[@]}" -eq 0 ]; then
  crates=(
    crates/rsk-fido/src
    crates/rsk-piv/src
    crates/rsk-openpgp/src
    crates/rsk-oath/src
    crates/rsk-mgmt/src
  )
fi

echo "== complexity — heaviest functions (rust-code-analysis) =="
echo "   scope: ${crates[*]}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rca_args=()
for c in "${crates[@]}"; do rca_args+=(-p "$c"); done
nix shell nixpkgs#rust-code-analysis -c rust-code-analysis-cli -m -O json -o "$tmp" "${rca_args[@]}"
python3 scripts/metrics_complexity.py "$tmp"

echo
echo "== firmware size by crate (cargo-bloat, release) =="
nix shell nixpkgs#cargo-bloat -c cargo bloat --release -p firmware --crates -n 20

echo
echo "== firmware size by function (cargo-bloat, release) =="
nix shell nixpkgs#cargo-bloat -c cargo bloat --release -p firmware -n 20

echo
echo "== generic monomorphization (cargo-llvm-lines, release) =="
nix shell nixpkgs#cargo-llvm-lines -c cargo llvm-lines --release -p firmware | head -25
