#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Smoke test: find the rs-key FIDO HID device and run CTAPHID INIT + PING.

    pip install hidapi      # or: uv pip install hidapi
    python tests/00_ctaphid_transport.py

Exercises channel allocation (INIT) and the PING echo.
"""
import sys

try:
    import hid
except ImportError:
    sys.exit("missing dependency: pip install hidapi")

FIDO_USAGE_PAGE = 0xF1D0
FIDO_USAGE_PAGE_ITEM = b"\x06\xd0\xf1"  # Usage Page (0xF1D0) item in a HID report descriptor
REPORT_LEN = 64


def find():
    devices = hid.enumerate()
    for d in devices:
        if d.get("usage_page") == FIDO_USAGE_PAGE:
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
    assert len(payload) <= REPORT_LEN
    # hidapi wants a leading report-id byte (0x00) for report-id-less devices.
    dev.write(b"\x00" + payload + b"\x00" * (REPORT_LEN - len(payload)))


def read(dev, timeout_ms=1000):
    return bytes(dev.read(REPORT_LEN, timeout_ms))


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device (usage page 0xF1D0) found — is the board plugged in?")
    print(
        f"found: vid={info['vendor_id']:#06x} pid={info['product_id']:#06x} "
        f"product={info.get('product_string')!r}"
    )

    dev = hid.device()
    dev.open_path(info["path"])
    try:
        # ---- CTAPHID_INIT on the broadcast channel ----
        nonce = bytes(range(8))
        write(dev, b"\xff\xff\xff\xff\x86\x00\x08" + nonce)
        r = read(dev)
        assert r[4] == 0x86, f"INIT cmd mismatch: {r[4]:#x}"
        assert r[7:15] == nonce, f"nonce mismatch: {r[7:15].hex()} != {nonce.hex()}"
        newcid = r[15:19]
        print(
            f"INIT ok: newcid={newcid.hex()} iface_ver={r[19]} "
            f"version={r[20]}.{r[21]}.{r[22]} caps={r[23]:#04x}"
        )

        # ---- CTAPHID_PING (single frame) ----
        payload = b"rs-key transport ping"
        write(dev, newcid + b"\x81" + bytes([len(payload) >> 8, len(payload) & 0xFF]) + payload)
        r = read(dev)
        bcnt = (r[5] << 8) | r[6]
        got = r[7 : 7 + bcnt]
        assert r[4] == 0x81, f"PING cmd mismatch: {r[4]:#x}"
        assert got == payload, f"PING echo mismatch: {got!r} != {payload!r}"
        print(f"PING ok: echoed {got!r}")

        print("\nPASS")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
