# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for rsk.ctaphid.find() device detection (no real hidapi).

Run from tools/:  python -m pytest rsk/test_ctaphid_find.py

Pins that find() locates a FIDO device by its usage page even when hidapi leaves
`usage_page` unset (the Linux libusb/hidraw case behind issue #28), by falling
back to the HID report descriptor — VID/PID-agnostic, since RS-Key ships several
VID/PID presets and hard-coding one (as the issue's workaround did) breaks the
rest.
"""
import sys
import types

# find()/`_declares_fido` touch `hid` only; stub it before importing rsk.ctaphid,
# which sys.exits at import if hidapi is missing. Handles are installed per test.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest

from rsk import ctaphid

# A minimal FIDO report descriptor: Usage Page (0xF1D0), Usage (0x01),
# Collection (Application), End Collection.
FIDO_DESC = b"\x06\xd0\xf1\x09\x01\xa1\x01\xc0"
# A keyboard: Usage Page (Generic Desktop), Usage (Keyboard) — no FIDO item.
KEYBOARD_DESC = b"\x05\x01\x09\x06\xa1\x01\xc0"


class _FakeDev:
    """Stand-in for hid.device(); serves descriptors keyed by enumerate() path.

    A descriptor value that is an Exception instance is raised from
    get_report_descriptor() to exercise the error branches of _declares_fido.
    """

    def __init__(self, descriptors, opened):
        self._descriptors = descriptors
        self._opened = opened
        self._path = None

    def open_path(self, path):
        if path not in self._descriptors:
            raise OSError("access denied")  # no permission / device busy
        self._path = path
        self._opened.append(path)

    def get_report_descriptor(self):
        desc = self._descriptors[self._path]
        if isinstance(desc, Exception):
            raise desc
        return desc

    def close(self):
        self._path = None


def _install(monkeypatch, enum, descriptors):
    """Wire hid.enumerate()/hid.device() and return the list of probed paths."""
    opened = []
    monkeypatch.setattr(ctaphid.hid, "enumerate", lambda: enum, raising=False)
    monkeypatch.setattr(
        ctaphid.hid, "device", lambda: _FakeDev(descriptors, opened), raising=False
    )
    return opened


def test_fast_path_matches_usage_page_without_opening(monkeypatch):
    enum = [
        {"usage_page": 0x0001, "path": b"/kbd"},
        {"usage_page": ctaphid.FIDO_USAGE_PAGE, "path": b"/fido", "vendor_id": 0x1209},
    ]

    def no_open():
        raise AssertionError("fast path must not open any device")

    monkeypatch.setattr(ctaphid.hid, "enumerate", lambda: enum, raising=False)
    monkeypatch.setattr(ctaphid.hid, "device", no_open, raising=False)
    assert ctaphid.find()["path"] == b"/fido"


def test_fallback_reads_report_descriptor_when_usage_page_zero(monkeypatch):
    # The libusb/hidraw case: enumerate lists the device but usage_page is 0.
    enum = [{"usage_page": 0, "path": b"/fido"}]
    opened = _install(monkeypatch, enum, {b"/fido": FIDO_DESC})
    assert ctaphid.find()["path"] == b"/fido"
    assert opened == [b"/fido"]


def test_fallback_skips_non_fido_devices(monkeypatch):
    enum = [
        {"usage_page": 0, "path": b"/kbd"},
        {"usage_page": None, "path": b"/fido"},
    ]
    opened = _install(monkeypatch, enum, {b"/kbd": KEYBOARD_DESC, b"/fido": FIDO_DESC})
    assert ctaphid.find()["path"] == b"/fido"
    assert opened == [b"/kbd", b"/fido"]  # probed the keyboard, rejected it, went on


def test_fallback_only_probes_usage_page_unset(monkeypatch):
    # A populated non-FIDO usage_page is settled by the fast path and never opened.
    enum = [
        {"usage_page": 0x0001, "path": b"/kbd"},
        {"usage_page": 0, "path": b"/fido"},
    ]
    opened = _install(monkeypatch, enum, {b"/kbd": KEYBOARD_DESC, b"/fido": FIDO_DESC})
    assert ctaphid.find()["path"] == b"/fido"
    assert opened == [b"/fido"]


def test_unopenable_device_is_tolerated(monkeypatch):
    # A device we can't open (no descriptor mapping → OSError) is skipped, not fatal.
    enum = [
        {"usage_page": 0, "path": b"/locked"},
        {"usage_page": 0, "path": b"/fido"},
    ]
    opened = _install(monkeypatch, enum, {b"/fido": FIDO_DESC})
    assert ctaphid.find()["path"] == b"/fido"
    assert opened == [b"/fido"]  # /locked raised on open() and was skipped


def test_returns_none_when_no_fido_present(monkeypatch):
    enum = [{"usage_page": 0, "path": b"/kbd"}]
    _install(monkeypatch, enum, {b"/kbd": KEYBOARD_DESC})
    assert ctaphid.find() is None


def test_empty_path_is_skipped(monkeypatch):
    enum = [{"usage_page": 0, "path": None}]
    opened = _install(monkeypatch, enum, {})
    assert ctaphid.find() is None
    assert opened == []  # never tried to open a pathless entry


def test_report_descriptor_error_is_tolerated(monkeypatch):
    # get_report_descriptor() raising (ValueError/TypeError, e.g. a hidapi C-call
    # failure or a None result) skips that device instead of crashing find().
    enum = [
        {"usage_page": 0, "path": b"/flaky"},
        {"usage_page": 0, "path": b"/fido"},
    ]
    _install(monkeypatch, enum, {b"/flaky": ValueError("read failed"), b"/fido": FIDO_DESC})
    assert ctaphid.find()["path"] == b"/fido"


def test_device_without_report_descriptor_method_is_tolerated(monkeypatch):
    # An older/other hid backend whose device lacks get_report_descriptor()
    # raises AttributeError, which the fallback swallows.
    class _NoDescDev:
        def open_path(self, path):
            pass

        def close(self):
            pass

    monkeypatch.setattr(ctaphid.hid, "enumerate", lambda: [{"usage_page": 0, "path": b"/x"}], raising=False)
    monkeypatch.setattr(ctaphid.hid, "device", _NoDescDev, raising=False)
    assert ctaphid.find() is None
