#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Test: physical user presence via the BOOTSEL button.

    nix develop -c python tests/50_user_presence_button.py

Drives `authenticatorSelection` (CTAP 0x0B) — the canonical "touch this
authenticator" gesture — and watches the CTAPHID_KEEPALIVE stream. On firmware
built with `--features up-button` the device blocks until BOOTSEL is pressed,
streaming KEEPALIVE status `UPNEEDED` (0x02) meanwhile; on the default build
presence is satisfied instantly (status would be `PROCESSING`, never seen).

  1. selection (0x0B): press BOOTSEL within 30s -> CTAP2_OK (0x00)

The same button gates makeCredential / getAssertion / reset / U2F-register and
U2F-authenticate-enforce; selection is just the cleanest single-shot demo.

Requires the firmware flashed with `--features up-button` to exercise a real
touch:  cargo build -p firmware --release --features up-button
        picotool uf2 convert .../release/firmware -t elf firmware.uf2
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaphid import (  # noqa: E402
    CTAPHID_CBOR,
    CTAPHID_INIT,
    find,
    read,
    write,
)

KEEPALIVE = 0xBB
STATUS = {0x01: "PROCESSING", 0x02: "UPNEEDED"}
AUTHENTICATOR_SELECTION = 0x0B
USER_ACTION_TIMEOUT = 0x2F


def selection_with_touch(dev, cid):
    """Send authenticatorSelection and read its reply, surfacing each distinct
    KEEPALIVE status (so a UPNEEDED stream is visible). Returns the CBOR body."""
    write(dev, cid + bytes([CTAPHID_CBOR, 0x00, 0x01, AUTHENTICATOR_SELECTION]))
    last = None
    while True:
        r = read(dev)
        assert len(r) >= 5, "empty HID read (device timed out / dropped report)"
        if r[4] == KEEPALIVE:
            st = r[7] if len(r) > 7 else 0
            if st != last:
                print(f"   keepalive: {STATUS.get(st, hex(st))}")
                last = st
            continue
        assert r[4] == CTAPHID_CBOR, f"unexpected cmd {r[4]:#x}"
        bcnt = (r[5] << 8) | r[6]
        return bytes(r[7:7 + bcnt])


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    rel = info.get("release_number")
    if rel:
        print(f"device bcdDevice = {rel:#06x}")
    dev = __import__("hid").device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]

        print("\nauthenticatorSelection — 👉 press the BOOTSEL button now (within 30s)...")
        t0 = time.time()
        resp = selection_with_touch(dev, cid)
        dt = time.time() - t0

        assert len(resp) >= 1, "empty selection response"
        status = resp[0]
        if status == USER_ACTION_TIMEOUT:
            sys.exit(f"selection timed out (0x2f) after {dt:.1f}s — no touch detected")
        assert status == 0x00, f"selection status {status:#x} (want CTAP2_OK)"

        print(f"selection: CTAP2_OK after {dt:.1f}s")
        if dt < 0.5:
            print(
                "\n⚠ returned instantly — this firmware was built WITHOUT "
                "--features up-button (presence auto-confirmed, no touch required)."
            )
        else:
            print("\nPASS — BOOTSEL touch gated authenticatorSelection.")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
