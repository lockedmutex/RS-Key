# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Shared helpers: error exit, picotool runner, FIDO HID connect."""
import subprocess
import sys


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def confirm(token):
    """Interactive typed confirmation for an irreversible action."""
    print(f"\nThis is irreversible. Type exactly  {token}  to proceed.")
    if input("> ").strip() != token:
        die("confirmation mismatch")


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
