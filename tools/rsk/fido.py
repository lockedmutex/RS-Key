# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk fido — ykman-free FIDO2 management over the HID interface (needs python-fido2).

set-pin:       set or change the FIDO2 clientPIN (no touch).
list-passkeys: list discoverable credentials via credentialManagement (needs PIN).
"""
import sys
from getpass import getpass

from .common import die

try:
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.ctap2.credman import CredentialManagement as CM
except ImportError:
    CtapHidDevice = None


def register(sub):
    p = sub.add_parser("fido", help="FIDO2 management (set PIN, list passkeys)")
    g = p.add_subparsers(dest="cmd", required=True)
    g.add_parser("set-pin", help="set or change the FIDO2 clientPIN").set_defaults(func=set_pin)
    g.add_parser("list-passkeys", help="list discoverable credentials").set_defaults(func=list_passkeys)


def _ctap():
    if CtapHidDevice is None:
        die("missing dependency: python-fido2 (run `rsk` from `nix develop`)")
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        die("no FIDO HID device found")
    ctap = Ctap2(dev)
    if "FIDO_2_0" not in ctap.info.versions:
        die("device does not advertise FIDO2")
    return ctap


def set_pin(args):
    ctap = _ctap()
    has_pin = ctap.info.options.get("clientPin")
    if has_pin is None:
        die("device does not support clientPin")
    cp = ClientPin(ctap)
    new = getpass("New FIDO2 PIN (4-63 chars): ")
    if len(new) < 4:
        die("PIN too short (min 4)")
    if getpass("Repeat new PIN: ") != new:
        die("PINs do not match")
    if has_pin:
        cp.change_pin(getpass("Current PIN: "), new)
        print("FIDO2 PIN changed.")
    else:
        cp.set_pin(new)
        print("FIDO2 PIN set.")
    print("clientPin now:", _ctap().info.options.get("clientPin"))


def list_passkeys(args):
    ctap = _ctap()
    print("credMgmt:", ctap.info.options.get("credMgmt"),
          "| clientPin:", ctap.info.options.get("clientPin"))
    if not ctap.info.options.get("clientPin"):
        die("no FIDO2 PIN set — set one first (rsk fido set-pin)")
    cp = ClientPin(ctap)
    token = cp.get_pin_token(getpass("FIDO2 PIN: "), ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CM(ctap, cp.protocol, token)
    meta = cm.get_metadata()
    existing = meta[CM.RESULT.EXISTING_CRED_COUNT]
    remaining = meta[CM.RESULT.MAX_REMAINING_COUNT]
    print(f"\ndiscoverable credentials: {existing}  (free slots: {remaining})")
    if existing == 0:
        print("  → none. An SSH `-O resident` key would show here.")
        return
    for rp in cm.enumerate_rps():
        rp_id = rp[CM.RESULT.RP].get("id")
        print(f"\nRP: {rp_id}")
        for cred in cm.enumerate_creds(rp[CM.RESULT.RP_ID_HASH]):
            user = cred[CM.RESULT.USER]
            cid = cred[CM.RESULT.CREDENTIAL_ID]["id"]
            name = user.get("name") or user.get("displayName") or user.get("id")
            print(f"   user={name}  credId={cid.hex()[:24]}…")
