# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk offboard — guided decommission of a returned (or lost-and-found) key.

Wipes every applet — OTP slots, OATH, PIV, OpenPGP, FIDO (seed, passkeys, PIN,
soft lock), org attestation — then signs a final audit checkpoint with the
DEVK-derived P-256 attestation key over the post-wipe journal window. The
saved JSON report is a cryptographic receipt: THIS device (fingerprint) was
factory-reset (the signed window contains the RESET event).

Deliberately PIN-free: every wipe path is reachable without knowing any
credential (block-then-reset for PIV/OpenPGP, the spec's resetting paths for
OATH/OTP, touch-gated reset for FIDO), so a key that comes back with unknown
PINs can still be offboarded. Needs the CCID interface, a typed confirmation,
and up to three touches.
"""
import json
import os
import sys
from datetime import datetime

from . import ccid, ctaphid, openpgp
from .audit import AUDIT_CHECKPOINT, CKPT_TAG, EVENTS, ENTRY_LEN, _fold, read_journal
from .backup import _gated, _vendor, mse_handshake
from .common import confirm, connect_fido, die
from .fido import ATT_CLEAR, ATT_STATE
from .status import RESCUE_AID

OTP_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
PIV_AID = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]

OTP_CONFIG_SIZE, OTP_ACC_CODE_SIZE = 52, 6
PIV_INS_VERIFY, PIV_INS_RESET_RETRY, PIV_INS_RESET = 0x20, 0x2C, 0xFB
CTAP_RESET = 0x07


def register(sub):
    p = sub.add_parser("offboard", help="guided full wipe + signed receipt (DESTRUCTIVE)")
    p.add_argument("--report", help="receipt path (default offboard-<serial>-<time>.json)")
    p.set_defaults(func=run)


def _serial():
    """The device serial (RP2350 OTP chip id) from the rescue applet."""
    conn = ccid.connect()
    d, s1, s2 = ccid.select(conn, RESCUE_AID)
    if (s1, s2) != (0x90, 0x00) or len(d) < 12:
        die("rescue applet did not answer — cannot identify the device")
    return d[4:12].hex(), conn


def _wipe_otp(conn):
    """Delete slots 1-4 (an all-zero config is the protocol's delete)."""
    _, s1, s2 = ccid.select(conn, OTP_AID)
    if (s1, s2) != (0x90, 0x00):
        return "applet absent"
    blocked = []
    for slot in range(1, 5):
        body = [0] * (OTP_CONFIG_SIZE + OTP_ACC_CODE_SIZE)
        _, s1, s2 = ccid.transmit(
            conn, [0x00, 0x01, 0x01, slot - 1, len(body)] + body)
        if (s1, s2) == (0x69, 0x82):
            blocked.append(slot)  # protected by an access code we don't have
        elif (s1, s2) != (0x90, 0x00):
            return f"slot {slot}: SW {s1:02X}{s2:02X}"
    return f"slots {blocked} protected by access codes — NOT wiped" if blocked else "ok"


def _wipe_oath(conn):
    _, s1, s2 = ccid.select(conn, OATH_AID)
    if (s1, s2) != (0x90, 0x00):
        return "applet absent"
    _, s1, s2 = ccid.transmit(conn, [0x00, 0x04, 0xDE, 0xAD])
    return "ok" if (s1, s2) == (0x90, 0x00) else f"RESET: SW {s1:02X}{s2:02X}"


def _wipe_piv(conn):
    """Block PIN and PUK (two distinct wrong values, so even a matching first
    guess cannot keep the retry counter alive), then factory RESET."""
    _, s1, s2 = ccid.select(conn, PIV_AID)
    if (s1, s2) != (0x90, 0x00):
        return "applet absent"
    for bad in (b"00000000", b"11111111"):
        for _ in range(8):
            ccid.transmit(conn, [0x00, PIV_INS_VERIFY, 0x00, 0x80, 8] + list(bad))
    for bad in (b"00000000" * 2, b"11111111" * 2):
        for _ in range(8):
            ccid.transmit(conn, [0x00, PIV_INS_RESET_RETRY, 0x00, 0x80, 16] + list(bad))
    _, s1, s2 = ccid.transmit(conn, [0x00, PIV_INS_RESET, 0x00, 0x00])
    return "ok" if (s1, s2) == (0x90, 0x00) else f"RESET: SW {s1:02X}{s2:02X}"


def _wipe_openpgp():
    try:
        openpgp.reset(None)
        return "ok"
    except SystemExit as e:
        return f"failed: {e}"


def _journal_entries(entries):
    out = []
    for off in range(0, len(entries), ENTRY_LEN):
        e = entries[off:off + ENTRY_LEN]
        out.append({"seq": int.from_bytes(e[0:4], "little"),
                    "uptime_ms": int.from_bytes(e[4:8], "little"),
                    "event": EVENTS.get(e[8], f"0x{e[8]:02x}"),
                    "aux": e[9], "detail": e[10:18].hex()})
    return out


def run(args):
    serial, conn = _serial()
    hid_info = ctaphid.find()
    if not hid_info:
        die("no FIDO HID device — offboard needs both interfaces")

    print(f"device serial : {serial}")
    print("\nThis wipes EVERYTHING on the key: OTP slots, OATH credentials, PIV")
    print("keys, OpenPGP keys, the FIDO seed and all passkeys, PINs, the org")
    print("attestation — and finishes with a signed wipe receipt.")
    confirm(f"OFFBOARD {serial}")

    steps = {}
    print("\nwiping OTP slots…", end=" ")
    steps["otp"] = _wipe_otp(conn)
    print(steps["otp"])
    print("wiping OATH…", end=" ")
    steps["oath"] = _wipe_oath(conn)
    print(steps["oath"])
    print("wiping PIV (block PIN+PUK, then factory reset)…", end=" ")
    steps["piv"] = _wipe_piv(conn)
    print(steps["piv"])
    conn.disconnect()  # openpgp.reset opens its own connection
    print("wiping OpenPGP…")
    steps["openpgp"] = _wipe_openpgp()

    dev, cid = connect_fido()
    print("\nFIDO factory reset — touch the device (BOOTSEL)…", file=sys.stderr)
    r = ctaphid.send_cbor(dev, cid, bytes([CTAP_RESET]))
    if r[0] != 0:
        die(f"FIDO reset failed: {r[0]:#x} — nothing signed; re-run rsk offboard"
            " (the CCID wipes are idempotent)")
    steps["fido_reset"] = "ok"

    st, m = _vendor(dev, cid, {1: ATT_STATE})
    if st == 0 and m.get(1):
        mse_handshake(dev, cid)
        print("removing the org attestation — touch the device (BOOTSEL)…", file=sys.stderr)
        st, _ = _vendor(dev, cid, _gated(ATT_CLEAR, None, dev, cid, None))
        steps["org_attestation"] = "cleared" if st == 0 else f"clear failed: {st:#x}"
    else:
        steps["org_attestation"] = "none"

    # The receipt: journal window (holds the RESET event), then a checkpoint
    # signing that window's head against a fresh challenge.
    start, seq_next, epoch, entries = read_journal(dev, cid, None)
    window = _journal_entries(entries)
    challenge = os.urandom(16)
    print("signing the wipe receipt — touch the device (BOOTSEL)…", file=sys.stderr)
    st, m = _vendor(dev, cid,
                    _gated(AUDIT_CHECKPOINT, {1: challenge}, dev, cid, None))
    report = {"device": serial,
              "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
              "steps": steps, "journal_window": window, "signed": False}
    if st == 0x30:
        print("warning: no OTP DEVK provisioned — receipt is UNSIGNED", file=sys.stderr)
    elif st != 0:
        print(f"warning: checkpoint failed ({st:#x}) — receipt is UNSIGNED", file=sys.stderr)
    else:
        import hashlib

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        # The device is untrusted: validate every field before use so a
        # malformed checkpoint fails closed instead of raising a traceback.
        if not all(k in m for k in (1, 2, 3, 4)):
            die("malformed checkpoint response — do not trust this device")
        head, seq, sig, pubkey = m[1], m[2], m[3], m[4]
        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
            msg = CKPT_TAG + head + int(seq).to_bytes(4, "little") + challenge
        except (ValueError, TypeError, OverflowError):
            die("malformed checkpoint fields — do not trust this device")
        try:
            vk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            die("receipt SIGNATURE INVALID — do not trust this device")
        # Bind the signature to the window the receipt shows: recompute the head
        # locally and require it match the signed head (as `rsk audit` does),
        # then require the RESET event actually be present in that bound window.
        if head != _fold(epoch, entries):
            die("signed head differs from the exported window — TAMPER")
        if not any(e["event"] == "RESET" for e in window):
            die("signed window does not contain the RESET event — refusing to certify")
        report.update({"signed": True, "challenge": challenge.hex(),
                       "signed_head": head.hex(), "seq": seq, "signature": sig.hex(),
                       "attestation_pubkey": pubkey.hex(),
                       "fingerprint": hashlib.sha256(pubkey).hexdigest()[:16]})

    path = args.report or f"offboard-{serial}-{datetime.now():%Y%m%d-%H%M%S}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nreceipt : {path}")
    if report["signed"]:
        print(f"identity: fingerprint {report['fingerprint']} — match it against"
              " your inventory record")
    failed = {k: v for k, v in steps.items()
              if v not in ("ok", "cleared", "none", "applet absent")}
    if failed:
        die(f"offboard finished WITH FAILURES: {failed} — receipt saved")
    print("device offboarded ✓ — all applets at factory state")
