# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk led — LED customization over the vendor applet (CCID).

SET LED (INS 0x10, P1=brightness, P2 = color | steady 0x08 | status<<4) / GET LED
(INS 0x11, returns [steady, (color, brightness) x idle/processing/touch/boot]).
Per-status color + brightness; --steady is a solid color (global). Persists in
flash, applies live.
"""
from . import ccid

COLORS = {"off": 0, "red": 1, "green": 2, "blue": 3,
          "yellow": 4, "magenta": 5, "cyan": 6, "white": 7}
COLOR_NAMES = {v: k for k, v in COLORS.items()}
STATUSES = {"idle": 0, "processing": 1, "touch": 2, "boot": 3}
STATUS_NAMES = {v: k for k, v in STATUSES.items()}
P2_STEADY = 0x08


def register(sub):
    p = sub.add_parser("led", help="LED color/brightness customization")
    p.add_argument("--status", choices=sorted(STATUSES), default="idle",
                   help="which status to change (default idle)")
    p.add_argument("--brightness", type=int, metavar="0-255",
                   help="per-channel brightness for --status (0 = off)")
    p.add_argument("--color", choices=sorted(COLORS), help="color for --status")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--steady", action="store_true", help="solid color, no blinking")
    g.add_argument("--blink", action="store_true", help="restore status blinking")
    p.add_argument("--get", action="store_true", help="read the current config")
    p.set_defaults(func=run)


def _get_block(conn):
    d, s1, s2 = ccid.transmit(conn, [0x00, 0x11, 0x00, 0x00, 0x00])
    if (s1, s2) != (0x90, 0x00) or len(d) < 9:
        raise SystemExit(f"GET LED failed: {s1:02X}{s2:02X} (len {len(d)})")
    return d


def run(args):
    conn = ccid.connect()
    ccid.select(conn, ccid.VENDOR_AID)
    changing = args.brightness is not None or args.color is not None or args.steady or args.blink
    if changing:
        block = _get_block(conn)
        st = STATUSES[args.status]
        b, c, steady = block[2 + 2 * st], block[1 + 2 * st], bool(block[0])
        if args.brightness is not None:
            if not 0 <= args.brightness <= 255:
                raise SystemExit("--brightness must be 0–255")
            b = args.brightness
        if args.color is not None:
            c = COLORS[args.color]
        steady = True if args.steady else False if args.blink else steady
        p2 = (c & 0x7) | (P2_STEADY if steady else 0) | (st << 4)
        _, s1, s2 = ccid.transmit(conn, [0x00, 0x10, b & 0xFF, p2])
        if (s1, s2) != (0x90, 0x00):
            raise SystemExit(f"SET LED failed: {s1:02X}{s2:02X}")
        print(f"set {args.status}: color={COLOR_NAMES.get(c, c)} brightness={b} "
              f"(mode={'steady' if steady else 'blink'})")
    if args.get or not changing:
        d = _get_block(conn)
        print(f"mode={'steady' if d[0] else 'blink'}")
        for st, name in sorted(STATUS_NAMES.items()):
            color = COLOR_NAMES.get(d[1 + 2 * st], d[1 + 2 * st])
            print(f"  {name:<10} color={color:<8} brightness={d[2 + 2 * st]}")
