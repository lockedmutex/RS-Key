# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Shared helpers: error exit, PIN resolution, picotool runner, FIDO HID connect."""
import subprocess
import sys
import unicodedata
from getpass import getpass


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def sanitize(text):
    """Map C0/C1 controls (incl. ESC) and Cf bidi/format chars in device-controlled
    text to U+FFFD, so a counterfeit device can't inject ANSI/OSC escapes or a
    Trojan-Source bidi override into the operator's terminal when we print it raw."""
    return "".join(
        "�" if unicodedata.category(ch) in ("Cc", "Cf") else ch
        for ch in str(text)
    )


def sanitize_join(seq, sep=", "):
    """Join a device-controlled sequence for display. A hostile/old device may
    send a scalar, None, or non-string elements where a list of strings is
    expected — coerce to a list and sanitize each element so neither a
    TypeError nor an injected terminal escape reaches the operator."""
    if isinstance(seq, (list, tuple)):
        items = seq
    elif seq is None:
        items = []
    else:
        items = [seq]
    return sep.join(sanitize(v) for v in items)


def confirm(token):
    """Interactive typed confirmation for an irreversible action."""
    print(f"\nThis is irreversible. Type exactly  {token}  to proceed.")
    if input("> ").strip() != token:
        die("confirmation mismatch")


# --- FIDO2 PIN entry ----------------------------------------------------------
# One way in for every command: the `--pin` flag OR an interactive prompt, never
# one without the other. `add_pin_arg` declares the flag identically everywhere;
# `resolve_pin` turns it (or a getpass prompt) into the PIN string, and only
# prompts when the device actually has a PIN so the touch-only flow is untouched.

def add_pin_arg(parser, help="FIDO2 PIN (prompted if the device has one and --pin is omitted)"):
    """Declare the shared --pin flag so every command spells it the same way."""
    parser.add_argument("--pin", help=help)


def device_has_pin(dev, cid):
    """Tri-state: does the open FIDO device have a clientPin set? (authenticator-
    GetInfo, touch-free). True / False, or None when getInfo can't be read."""
    from . import ctaphid

    r = ctaphid.send_cbor(dev, cid, bytes([ctaphid.CTAP_GET_INFO]))
    if not r or r[0] != 0:
        return None
    opts = ctaphid.decode(r[1:]).get(4) or {}
    return bool(opts.get("clientPin"))


def resolve_pin(args, *, has_pin=None, prompt="FIDO2 PIN: ", required=False):
    """Resolve the FIDO2 PIN uniformly: the --pin flag if given, else an
    interactive getpass prompt.

    `has_pin` (from device_has_pin) gates the prompt so a PIN-free device is
    never asked: True -> prompt when no flag; False -> None (or die if
    `required`); None -> prompt when no flag. A non-TTY stdin with no flag
    returns None (the caller's device-side 'PIN required' path then reports the
    actionable error), unless `required`, where it dies up front."""
    pin = getattr(args, "pin", None)
    if pin:
        return pin
    if has_pin is False:
        if required:
            die("no FIDO2 PIN set — set one first: rsk fido set-pin")
        return None
    if not sys.stdin.isatty():
        if required:
            die("device requires a PIN — pass --pin (stdin is not a terminal)")
        return None
    entered = getpass(prompt) or None
    if entered is None and required:
        die("a PIN is required")
    return entered


def picotool(*args, check=True):
    """Run picotool (in the dev shell); die on failure unless check=False."""
    r = subprocess.run(["picotool", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"picotool {' '.join(args)}\n{r.stdout}{r.stderr}")
    return r


def connect_fido():
    """Open the FIDO HID device and run CTAPHID INIT; returns (dev, cid)."""
    from . import ctaphid

    info = ctaphid.find()
    if not info:
        die("no FIDO HID device found (usage page 0xF1D0)")
    dev = ctaphid.hid.device()
    dev.open_path(info["path"])
    return dev, ctaphid.ctaphid_init(dev)
