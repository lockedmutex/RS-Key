# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk reboot — vendor reboot to BOOTSEL or the application.

Reboot-to-BOOTSEL requires an on-device confirmation (the firmware gates it
against a hostile host); a plain app restart does not."""
import sys

from . import ccid


def register(sub):
    p = sub.add_parser("reboot", help="reboot the device (BOOTSEL or app) over CCID")
    p.add_argument("target", choices=["bootsel", "app"], help="where to reboot to")
    p.set_defaults(func=run)


def run(args):
    bootsel = args.target == "bootsel"
    if bootsel:
        print(
            "approve on the device (touch / on-screen Approve) to reboot to BOOTSEL…",
            file=sys.stderr,
        )
    sw = ccid.reboot(bootsel=bootsel)
    if sw == (0x69, 0x85):
        raise SystemExit(
            "reboot-to-BOOTSEL declined on the device (no confirmation). Approve on "
            "the device, or enter BOOTSEL manually (hold BOOTSEL and replug)."
        )
    print(f"reboot-to-{args.target} sent")
