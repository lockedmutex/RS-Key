#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Emulated-keyboard test — drive the OTP HID frame protocol.

The keyboard interface carries two things: typed tickets (button press →
keystrokes) and the legacy 8-byte feature-report frame protocol that `ykman`'s
OtpConnection speaks. This test exercises the *frame protocol* — the
auto-testable half — by driving the device through ykman's own reference
`OtpConnection`:

  * read the status record (firmware version, slot bits),
  * program slot 2 as an HMAC-SHA1 challenge-response slot (a frame write that
    bumps the program sequence),
  * run `calculate_hmac_sha1` (a frame write whose response is streamed back) and
    check it against a host-side HMAC-SHA1,
  * delete the slot again.

`ykman otp calculate` is the *only* path that forces OtpConnection (HID), so this
is the real-world exercise of code unreachable over CCID. It needs no touch (the
slot is not CHAL_BTN_TRIG), so it runs against either firmware build.

Run under ykman's bundled Python (it has yubikit + ykman):

    /opt/homebrew/Cellar/ykman/5.9.1/libexec/bin/python tests/73_otp_keyboard.py

Notes:
  * On macOS, opening the keyboard HID interface for feature reports may prompt
    for Input Monitoring permission for the Python process — grant it once.
  * If discovery fails with the CCID reader held, `gpgconf --kill scdaemon`.
  * The typed-ticket half (button types an OTP) can't be auto-verified; see
    `--typed` for a manual check.
"""
import hashlib
import hmac
import sys

try:
    from yubikit.core.otp import OtpConnection
    from yubikit.management import ManagementSession
    from yubikit.yubiotp import (
        HmacSha1SlotConfiguration,
        SLOT,
        StaticPasswordSlotConfiguration,
        YubiOtpSession,
    )
    from ykman.device import list_all_devices
except ImportError:
    sys.exit(
        "missing yubikit/ykman — run under ykman's python, e.g.\n"
        "  /opt/homebrew/Cellar/ykman/<ver>/libexec/bin/python tests/73_otp_keyboard.py"
    )

KEY20 = bytes(range(1, 21))  # 20-byte HMAC-SHA1 key
CHALLENGE = b"rs-key keyboard challenge"


def find_otp_device():
    """First device exposing an OTP (HID) connection."""
    for dev, info in list_all_devices():
        try:
            if dev.supports_connection(OtpConnection):
                return dev, info
        except Exception:
            continue
    return None, None


def run_frame_protocol():
    dev, info = find_otp_device()
    if dev is None:
        sys.exit("no OTP HID device found — flash current firmware and replug")
    print(f"device: serial={getattr(info, 'serial', '?')} version={info.version}")

    # DeviceInfo over OTP — the slot-0x13 management read ykman falls back to
    # when CCID is unavailable. Must answer (caps TLV matching the CCID
    # READ_CONFIG), or ykman blocks forever in yubikit's _read_frame.
    with dev.open_connection(OtpConnection) as conn:
        di = ManagementSession(conn).read_device_info()
        assert di.serial is not None, "no serial in DeviceInfo over OTP"
        caps = int(di.supported_capabilities.get(next(iter(di.supported_capabilities))))
        assert caps == 0x23B, f"USB caps {caps:#x} != 0x23B (must match CCID READ_CONFIG)"
        print(f"DeviceInfo over OTP OK: serial={di.serial} version={di.version} caps={caps:#x}")

    with dev.open_connection(OtpConnection) as conn:
        session = YubiOtpSession(conn)
        print(f"OTP applet version over HID: {session.version}")

        # Best-effort clean slate (no access code in this test).
        try:
            session.delete_slot(SLOT.TWO)
        except Exception:
            pass

        # Program slot 2 = HMAC-SHA1 challenge-response (frame write + seq bump).
        before = session.get_config_state()
        session.put_configuration(SLOT.TWO, HmacSha1SlotConfiguration(KEY20))
        after = session.get_config_state()
        assert after.is_configured(SLOT.TWO), "slot 2 not reported configured"
        print(f"slot 2 programmed (config state {before} -> {after})")

        # Calculate (frame write + streamed response) and verify host-side.
        resp = session.calculate_hmac_sha1(SLOT.TWO, CHALLENGE)
        want = hmac.new(KEY20, CHALLENGE, hashlib.sha1).digest()
        assert resp == want, f"HMAC mismatch:\n got {resp.hex()}\n want {want.hex()}"
        print(f"HMAC-SHA1 chal-resp over HID OK ({resp.hex()})")

        # Clean up.
        session.delete_slot(SLOT.TWO)
        assert not session.get_config_state().is_configured(SLOT.TWO)
        print("slot 2 deleted")

    print("PASS (frame protocol)")


def program_typed_static():
    """Manual-check helper: program slot 1 as a static password so a button press
    types it. The keyboard output can't be auto-verified."""
    dev, info = find_otp_device()
    if dev is None:
        sys.exit("no OTP HID device found")
    # "hello" in HID scancodes (h e l l o).
    scancodes = bytes([0x0B, 0x08, 0x0F, 0x0F, 0x12])
    with dev.open_connection(OtpConnection) as conn:
        session = YubiOtpSession(conn)
        try:
            session.delete_slot(SLOT.ONE)
        except Exception:
            pass
        session.put_configuration(
            SLOT.ONE, StaticPasswordSlotConfiguration(scancodes)
        )
    print("slot 1 = static password 'hello'.")
    print("Focus a text field, press BOOTSEL once, and confirm 'hello' is typed.")
    print("(Double-press would trigger slot 2.)")


if __name__ == "__main__":
    if "--typed" in sys.argv:
        program_typed_static()
    else:
        run_frame_protocol()
