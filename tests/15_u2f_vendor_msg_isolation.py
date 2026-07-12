#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Regression: a vendor-AID SELECT over CTAPHID_MSG must not hijack U2F routing.

    nix develop -c python tests/15_u2f_vendor_msg_isolation.py

U2F/CTAP1 has no SELECT — the firmware special-cases it only while no applet is
selected over the MSG transport. A vendor-AID SELECT (what 01_flash_persistence
does) set a sticky `disp.current` that nothing cleared, so a LATER U2F command in
the same boot session was dispatched to the vendor applet and returned SW 0x6D00
(INS_NOT_SUPPORTED). The fix drops that selection on every CTAPHID_INIT.

This reproduces it deterministically in one process: SELECT the vendor AID on one
channel, then INIT a fresh channel and ask U2F VERSION — which must answer
`U2F_V2`, not 0x6D00. Touch-free (no REGISTER/AUTHENTICATE), runs on any build.
"""
import sys

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

REPORT_LEN = 64
CTAPHID_INIT = 0x86
CTAPHID_MSG = 0x83
VENDOR_AID = bytes([0xF0, 0x00, 0x00, 0x00, 0x01])
SELECT_VENDOR = bytes([0x00, 0xA4, 0x04, 0x00, len(VENDOR_AID)]) + VENDOR_AID
U2F_VERSION = bytes([0x00, 0x03, 0x00, 0x00, 0x00])  # short Le (case 2)


FIDO_USAGE_PAGE_ITEM = b"\x06\xd0\xf1"  # Usage Page (0xF1D0) item in a HID report descriptor


def find():
    devices = hid.enumerate()
    for d in devices:
        if d.get("usage_page") == 0xF1D0:
            return d
    # hidapi may leave usage_page unset on Linux (libusb/older hidraw); confirm the
    # FIDO usage page from the report descriptor instead (mirrors tools/rsk/ctaphid.py).
    for d in devices:
        if not d.get("usage_page") and _declares_fido(d.get("path")):
            return d
    return None


def _declares_fido(path):
    if not path:
        return False
    dev = hid.device()
    try:
        dev.open_path(path)
        desc = bytes(dev.get_report_descriptor())
    except (OSError, ValueError, TypeError, AttributeError):
        return False
    finally:
        dev.close()
    return FIDO_USAGE_PAGE_ITEM in desc


def write(dev, payload):
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev):
    return bytes(dev.read(REPORT_LEN, 3000))


def init(dev):
    write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
    return read(dev)[15:19]


def msg(dev, cid, apdu):
    n = len(apdu)
    write(dev, cid + bytes([CTAPHID_MSG, n >> 8, n & 0xFF]) + apdu[:57])
    r = read(dev)
    while len(r) >= 5 and r[4] == 0xBB:  # KEEPALIVE
        r = read(dev)
    assert r[4] == CTAPHID_MSG, f"cmd {r[4]:#x}"
    bcnt = (r[5] << 8) | r[6]
    data = bytearray(r[7:7 + bcnt])
    while len(data) < bcnt:
        c = read(dev)
        data += c[5:5 + min(59, bcnt - len(data))]
    return bytes(data[:bcnt])


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        # 1. SELECT the vendor AID over MSG — sets the sticky selection.
        cid1 = init(dev)
        sel = msg(dev, cid1, SELECT_VENDOR)
        assert sel[-2:] == b"\x90\x00", f"vendor SELECT SW {sel[-2:].hex()} (want 9000)"
        print(f"vendor SELECT over MSG ok (cid {cid1.hex()})")

        # 2. Fresh INIT (must clear the selection), then U2F VERSION.
        cid2 = init(dev)
        ver = msg(dev, cid2, U2F_VERSION)
        print(f"U2F VERSION after a new INIT -> {ver!r}")
        if ver == b"\x6d\x00":
            sys.exit("FAIL: U2F VERSION returned 6D00 — vendor selection hijacked "
                     "U2F (the CTAPHID_INIT deselect did not fire)")
        assert ver == b"U2F_V2\x90\x00", f"FAIL: U2F VERSION = {ver!r} (want 'U2F_V2' 9000)"
        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    sys.exit(main())
