# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk reboot — hands-free vendor reboot to BOOTSEL or the application."""
from . import ccid


def register(sub):
    p = sub.add_parser("reboot", help="reboot the device (BOOTSEL or app) over CCID")
    p.add_argument("target", choices=["bootsel", "app"], help="where to reboot to")
    p.set_defaults(func=run)


def run(args):
    ccid.reboot(bootsel=(args.target == "bootsel"))
    print(f"reboot-to-{args.target} sent")
