# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk — RS-Key device CLI entry point (`python -m rsk`, or `rsk` in the shell)."""
import argparse

from . import (__version__, audit, backup, fido, inventory, led, lock, offboard, openpgp,
               otp, reboot, secureboot, status)

GROUPS = [status, inventory, backup, lock, secureboot, otp, fido, led, openpgp, reboot,
          audit, offboard]


def main():
    p = argparse.ArgumentParser(
        prog="rsk", description="RS-Key device CLI — status, fleet inventory, seed backup, "
        "seed lock, secure boot, OTP, FIDO, LED, OpenPGP, reboot, audit, offboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"rsk {__version__}")
    sub = p.add_subparsers(dest="group", required=True, metavar="<group>")
    for mod in GROUPS:
        mod.register(sub)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
