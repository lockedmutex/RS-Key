#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Crypto-parity control — prove RS-Key's OATH engine matches a real YubiKey's.

The `diff.py` snapshot compare is *structural*: it checks that the two keys agree
on counts, options and metadata. It deliberately never diffs OATH codes or
challenge-response outputs, because the fill's secrets are independent across the
two boards — equal codes would be a coincidence, unequal ones meaningless.

This instead provisions a **known-answer** credential (RFC 4226 appendix D, the
same vector `tests/71_oath.py` uses) on the device and reads it back: a fresh
counter-0 HOTP over the ASCII secret `12345678901234567890` must produce
**755224** on *any* correct implementation. Run it against both keys — both
printing 755224 proves the HMAC-SHA1 + dynamic-truncation engine is byte-identical.

Additive and restorable: it adds one credential (`RSKPARITY`), reads three codes,
and deletes it, leaving the existing OATH fill untouched.
"""
import argparse
import base64
import sys

from capture import _bin, resolve_serial, run  # reuse the scrubbed-env runner

# RFC 4226 App-B secret "12345678901234567890" (the same vector tests/71_oath.py
# uses); base32 it here rather than hardcode the encoded form, which reads as a
# high-entropy token. App-D gives the HOTP sequence below.
SECRET_B32 = base64.b32encode(b"12345678901234567890").decode()
NAME = "RSKPARITY"
URI = (f"otpauth://hotp/{NAME}:known-answer@rs-key"
       f"?secret={SECRET_B32}&issuer={NAME}&algorithm=SHA1&digits=6&counter=0")
EXPECT = ["755224", "287082", "359152"]  # RFC 4226 appendix D, counters 0/1/2


def _yk(serial, *args, **kw):
    return run([_bin("ykman"), "--device", serial, "oath", "accounts", *args], **kw)


def main():
    ap = argparse.ArgumentParser(description="OATH HOTP known-answer crypto-parity control")
    ap.add_argument("--serial", help="ykman serial (auto if a single device is plugged)")
    ap.add_argument("--password", help="OATH password, if the applet is protected")
    args = ap.parse_args()
    serial = resolve_serial(args.serial)
    pw = ["--password", args.password] if args.password else []

    print(f"OATH parity on serial {serial}: add {NAME} (RFC 4226 known-answer)…")
    _yk(serial, "delete", NAME, "-f", *pw)  # clear any leftover from a prior run
    rc, out = _yk(serial, "uri", URI, "-f", *pw)
    if rc != 0:
        sys.exit(f"  add failed: {out.strip().splitlines()[-1] if out.strip() else 'rc!=0'}")

    got = []
    try:
        for i, want in enumerate(EXPECT):
            rc, out = _yk(serial, "code", NAME, *pw)
            code = next((t for t in out.split() if t.isdigit() and len(t) == 6), None)
            got.append(code)
            ok = code == want
            print(f"  counter {i}: {code}  (want {want})  {'ok' if ok else 'MISMATCH'}")
    finally:
        _yk(serial, "delete", NAME, "-f", *pw)  # restore the fill

    if got == EXPECT:
        print("PASS — HMAC-SHA1 + dynamic-truncation engine matches the RFC 4226 vector.")
        return 0
    print(f"FAIL — got {got}, want {EXPECT}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
