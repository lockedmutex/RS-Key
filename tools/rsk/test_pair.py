# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.pair (no device).

Run from tools/:  python -m pytest rsk/test_pair.py
Pins the primary/backup verdict — same device twice vs two distinct keys vs
"can't tell" when no chip serial is available.
"""
from rsk import pair


def test_verdict_same_device():
    a = {"serial": "abcd"}
    b = {"serial": "abcd"}
    assert pair._pair_verdict(a, b) == "same-device"


def test_verdict_distinct():
    a = {"serial": "aaaa"}
    b = {"serial": "bbbb"}
    assert pair._pair_verdict(a, b) == "ok"


def test_verdict_unknown_without_serial():
    assert pair._pair_verdict({"serial": None}, {"serial": "bbbb"}) == "unknown"
    assert pair._pair_verdict({"serial": "aaaa"}, {"serial": None}) == "unknown"
    assert pair._pair_verdict({"serial": None}, {"serial": None}) == "unknown"


def test_verdict_missing_serial_key_is_unknown():
    # a record without a "serial" key at all (e.g. HID-only) is treated as unknown
    assert pair._pair_verdict({}, {"serial": "bbbb"}) == "unknown"
