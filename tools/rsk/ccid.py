# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PC/SC (CCID) transport helpers shared by the rsk subcommands."""
import sys

try:
    from smartcard.System import readers
except ImportError:
    readers = None

VENDOR_AID = [0xF0, 0x00, 0x00, 0x00, 0x01]


def _require():
    if readers is None:
        sys.exit("missing dependency: pyscard (run `rsk` from `nix develop`)")


def find_reader(substr="RSK"):
    _require()
    rs = readers()
    if not rs:
        sys.exit("no PC/SC readers — is the device flashed and the CCID driver bound?")
    return next((r for r in rs if substr in str(r)), rs[0])


def connect(substr="RSK"):
    conn = find_reader(substr).createConnection()
    conn.connect()
    return conn


def transmit(conn, data):
    d, sw1, sw2 = conn.transmit(list(data))
    return bytes(d), sw1, sw2


def select(conn, aid):
    return transmit(conn, [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00])


def reboot(conn=None, bootsel=True):
    """SELECT the vendor AID then the warm-reboot command (P1=1 BOOTSEL, P1=0 app).
    Hands-free; the device drops off the bus, so any reply is ignored."""
    if conn is None:
        conn = connect()
    transmit(conn, [0x00, 0xA4, 0x04, 0x00, len(VENDOR_AID)] + VENDOR_AID + [0x00])
    try:
        transmit(conn, [0x00, 0x1F, 0x01 if bootsel else 0x00, 0x00, 0x00])
    except Exception:
        pass
