#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Device test: wallet-style seed backup over the vendor (0x41) MSE channel.

Non-destructive and idempotent — it exports the seed, checks BIP-39 and SLIP-39
encode the SAME 32 bytes, restores that same seed back (so the live FIDO identity
is unchanged), then re-exports to confirm it round-tripped. The raw seed is never
printed; only a short SHA-256 fingerprint is shown.

Needs the NO-TOUCH firmware build (the export/restore touch gate auto-confirms
there). Run it from the dev shell (the flake provides the deps):

  nix develop -c python tests/75_seed_backup.py --pin <PIN>
"""
import hashlib
import os
import sys

# Exercises the `rsk backup` implementation directly (tests -> tools is fine).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from rsk import backup as b  # noqa: E402
from rsk.common import connect_fido  # noqa: E402


def main():
    pin = None
    if "--pin" in sys.argv:
        pin = sys.argv[sys.argv.index("--pin") + 1]

    dev, cid = connect_fido()

    st, m = b._vendor(dev, cid, {1: b.STATE})
    assert st == 0, f"status failed {st:#x}"
    sealed, has_seed = m[1], m[2]
    print(f"status: sealed={sealed} has_seed={has_seed}")
    assert has_seed, "device has no seed?!"
    if sealed:
        print("SKIP: export window already sealed — run an authenticatorReset to reopen")
        return

    seed = b.read_seed(dev, cid, pin)
    fp = hashlib.sha256(seed).hexdigest()[:8]

    words = b.to_bip39(seed)[0]
    shares = b.to_slip39(seed, 2, 3)
    assert b.from_bip39(words) == seed, "BIP-39 does not round-trip the exported seed"
    assert b.from_slip39(shares[:2]) == seed, "SLIP-39 2-of-3 does not round-trip"
    assert len(words.split()) == 24, "expected a 24-word BIP-39 phrase"
    assert len(shares) == 3, "expected 3 SLIP-39 shares"
    print(f"export: seed_fp={fp}  bip39=24 words  slip39=2-of-3 (both consistent)")

    # Restore the SAME seed (identity-preserving), then re-export to confirm.
    b.write_seed(dev, cid, pin, b.from_bip39(words))
    seed2 = b.read_seed(dev, cid, pin)
    assert seed2 == seed, "seed changed after restore — round-trip broken"

    print(f"PASS — export+restore round-trip clean, identity preserved (fp={fp})")


if __name__ == "__main__":
    main()
