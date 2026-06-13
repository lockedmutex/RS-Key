# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""rsk pair — guided setup of a PRIMARY + BACKUP pair of independent RS-Keys.

The redundancy model here is two SEPARATE keys with DIFFERENT seeds (not one seed
cloned onto both): you register both keys with every account, so losing or
breaking the primary leaves the backup — already enrolled everywhere — working.
No seed restore, and no single secret whose leak compromises both.

Each RS-Key generates its OWN seed on first boot, so two fresh devices already
have independent identities; the only way to make them share a seed is to
deliberately `rsk backup restore` the same mnemonic onto both (which this guide
tells you NOT to do). There is no cheap automatic "are the seeds different?"
check — RS-Key credentials are randomized (a fresh key handle per registration),
so nothing seed-derived is stable to compare, and the DEVK attestation is
per-chip, not per-seed. The wizard therefore reads each device in turn (serial +
FIDO state, touch-free), confirms they are two DIFFERENT physical keys, and
prints the dual-registration checklist + a record to keep.

  pair   plug in the primary, then the backup, when prompted (--json for the record)
"""
import json

from . import inventory
from .common import die


def register(sub):
    p = sub.add_parser("pair", help="guided primary + backup (two independent keys) setup")
    p.add_argument("--json", action="store_true", help="print the pair record as JSON")
    p.set_defaults(func=cmd_pair)


# --- pure helper (no device; unit-tested in test_pair.py) ---------------------

def _pair_verdict(primary, backup):
    """Classify the pair from two records by chip serial.

    same-device : identical serial — the same key was plugged in twice
    unknown     : a serial is missing (no CCID reader) — can't confirm distinctness
    ok          : two different physical devices
    """
    ps, bs = primary.get("serial"), backup.get("serial")
    if ps and bs and ps == bs:
        return "same-device"
    if not ps or not bs:
        return "unknown"
    return "ok"


# --- device interaction -------------------------------------------------------

def _read_one(role):
    input(f"\nPlug in ONLY your {role} RS-Key, then press Enter… ")
    recs = inventory.gather()
    if not recs:
        die(f"no RS-Key detected for the {role} step — plug it in and retry.")
    if len(recs) > 1:
        die(f"more than one key detected — for the {role} step plug in ONLY that key.")
    rec = recs[0]
    return {
        "role": role.lower(),
        "serial": rec.get("serial"),
        "fw": rec.get("fw"),
        "client_pin": rec.get("client_pin"),
        "has_seed": (rec.get("backup") or {}).get("has_seed"),
    }


def _show(dev):
    print(f"  {dev['role']:<7}: serial {dev['serial'] or '? (no CCID reader)'}"
          f"  fw {dev['fw'] or '?'}  PIN {dev['client_pin']}  has_seed {dev['has_seed']}")


def cmd_pair(args):
    print("RS-Key pairing — a PRIMARY + a BACKUP key, each with its OWN seed.")
    print("Register BOTH everywhere; if one is lost or breaks, the other already works.")
    primary = _read_one("PRIMARY")
    backup = _read_one("BACKUP")

    print("\nDevices:")
    _show(primary)
    _show(backup)

    verdict = _pair_verdict(primary, backup)
    if verdict == "same-device":
        die("that is the SAME physical key both times (identical serial) — use two devices.")
    if verdict == "unknown":
        print("\nnote: couldn't read a chip serial (no CCID reader?), so I can't confirm these")
        print("are two different keys — make sure you physically swapped to the OTHER key.")
    else:
        print("\ntwo distinct devices ✓")

    print("\nEach RS-Key made its OWN seed on first boot, so these identities are already")
    print("independent. Do NOT `rsk backup restore` the same mnemonic onto both — that turns")
    print("them into clones (one seed leak breaks both) and defeats the point of a backup.")

    print("\nSet-up checklist:")
    print("  1. Give each device its own PIN (browser / OS security-key settings).")
    print("  2. Back up each seed SEPARATELY — independent seeds means two phrases:")
    print("       rsk backup export   (per device) → write it down → rsk backup finalize")
    print("  3. Register BOTH keys on every important account (Google, GitHub, Microsoft…):")
    print("       in each account's security-key settings, add the primary AND the backup.")
    print("  4. Store the backup key in a different physical location from the primary.")
    print("  5. Test the backup: sign in once using only the backup key.")

    record = {"primary": {"serial": primary["serial"]},
              "backup": {"serial": backup["serial"]},
              "distinct": verdict == "ok"}
    if args.json:
        print(json.dumps(record))
    else:
        print("\n=== pair record (keep with your account inventory) ===")
        print(f"  primary : serial {primary['serial'] or '?'}")
        print(f"  backup  : serial {backup['serial'] or '?'}")
        print(f"  status  : {'DISTINCT DEVICES' if verdict == 'ok' else verdict.upper()}")
