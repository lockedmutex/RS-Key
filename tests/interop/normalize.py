# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Turn each tool's output into a canonical {dotted-path: value} map.

`diff.py` compares canonical fields, not raw text, so every consumer's output is
normalized here first. Two flavours of parser:

- **precise** — where the wire format is stable and we own it: the CTAP2 getInfo
  CBOR integer-key map, the management DeviceInfo TLV. These name every field
  exactly (`fido.getinfo.maxMsgSize`, `mgmt.serial`).
- **generic** — `kv_lines()` scrapes `Label: value` pairs out of ykman / gpg
  prose into `<ns>.<label>` keys. A blunt instrument, but it captures the field
  set for the diff; the precise parsers above override anything that matters.

Set-valued fields (versions, extensions, algorithms, transports) are returned as
**sorted lists** so the allow-list's Superset/ExpectDiff rules compare them
order-insensitively.
"""
import re

# ── CTAP2 authenticatorGetInfo integer keys (CTAP 2.1/2.2 §6.4) ──────────────
_GETINFO_KEYS = {
    0x01: "versions",
    0x02: "extensions",
    0x03: "aaguid",
    0x04: "options",
    0x05: "maxMsgSize",
    0x06: "pinUvAuthProtocols",
    0x07: "maxCredentialCountInList",
    0x08: "maxCredentialIdLength",
    0x09: "transports",
    0x0A: "algorithms",
    0x0B: "maxSerializedLargeBlobArray",
    0x0C: "forcePINChange",
    0x0D: "minPINLength",
    0x0E: "firmwareVersion",
    0x0F: "maxCredBlobLength",
    0x10: "maxRPIDsForSetMinPINLength",
    0x11: "preferredPlatformUvAttempts",
    0x12: "uvModality",
    0x13: "certifications",
    0x14: "remainingDiscoverableCredentials",
    0x15: "vendorPrototypeConfigCommands",
    0x16: "attestationFormats",
}


def uuid_str(b):
    """16 raw bytes → canonical lowercase UUID."""
    h = bytes(b).hex()
    if len(h) != 32:
        return h
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def fido_getinfo(cbor_map, ns="fido.getinfo"):
    """A decoded CTAP2 getInfo map (integer keys) → canonical fields."""
    out = {}
    for k, v in cbor_map.items():
        name = _GETINFO_KEYS.get(k, f"key_{k:#x}")
        path = f"{ns}.{name}"
        if name == "aaguid" and isinstance(v, (bytes, bytearray)):
            out[path] = uuid_str(v)
        elif name == "options" and isinstance(v, dict):
            for opt, val in v.items():
                out[f"{path}.{opt}"] = bool(val)
        elif name == "algorithms" and isinstance(v, list):
            algs = [e.get("alg") if isinstance(e, dict) else e for e in v]
            out[path] = sorted(str(a) for a in algs)
        elif name == "certifications" and isinstance(v, dict):
            for c, val in v.items():
                out[f"{path}.{c}"] = val
        elif isinstance(v, list):
            out[path] = sorted(str(x) for x in v)
        elif isinstance(v, (bytes, bytearray)):
            out[path] = bytes(v).hex()
        else:
            out[path] = v
    return out


# ── Management DeviceInfo TLV (READ CONFIG 0x1D) ─────────────────────────────
_MGMT_TAGS = {
    0x01: ("usbSupported", "int"),
    0x02: ("serial", "int"),
    0x03: ("usbEnabled", "int"),
    0x04: ("formFactor", "int"),
    0x05: ("version", "version"),
    0x06: ("autoEjectTimeout", "int"),
    0x07: ("chalRespTimeout", "int"),
    0x08: ("deviceFlags", "int"),
    0x0A: ("configLock", "int"),
    0x0D: ("nfcSupported", "int"),
    0x0E: ("nfcEnabled", "int"),
}


def _tlv_walk(blob):
    """Short-form (tag, len, value) TLVs → ordered list."""
    out, i = [], 0
    while i + 2 <= len(blob):
        tag, ln = blob[i], blob[i + 1]
        if i + 2 + ln > len(blob):
            break
        out.append((tag, bytes(blob[i + 2 : i + 2 + ln])))
        i += 2 + ln
    return out


def mgmt_deviceinfo(blob, ns="mgmt"):
    """READ CONFIG response → canonical mgmt.* fields. A real YubiKey prefixes the
    payload with a total-length byte; strip it when present."""
    blob = bytes(blob)
    if blob and blob[0] == len(blob) - 1:
        blob = blob[1:]
    out = {}
    for tag, val in _tlv_walk(blob):
        name, kind = _MGMT_TAGS.get(tag, (f"tag_{tag:#x}", "hex"))
        path = f"{ns}.{name}"
        if kind == "int":
            out[path] = int.from_bytes(val, "big") if val else 0
        elif kind == "version":
            out[path] = ".".join(str(x) for x in val)
        else:
            out[path] = val.hex()
    return out


# ── generic Label: value scraper for CLI prose ───────────────────────────────
_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /._()+-]*?)\s*:\s*(.+?)\s*$")


def _slug(label):
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


def kv_lines(text, ns):
    """Scrape `Label: value` lines into `<ns>.<slug(label)>` fields. Last write
    wins for a repeated label; empty values are dropped."""
    out = {}
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, val = _slug(m.group(1)), m.group(2).strip()
        if key and val:
            out[f"{ns}.{key}"] = val
    return out
