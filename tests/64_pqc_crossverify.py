#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Cross-verify on-device ML-DSA-44 and ML-DSA-65 signatures under THREE
independent implementations: dilithium-py (pure Python), OpenSSL (via pyca
`cryptography` >= 44), and — implicitly — the device's own `rsk-mldsa`. Proves
the real device output interoperates with the wider ecosystem, not just our
host tests.

    nix develop -c python tests/64_pqc_crossverify.py

Needs `hidapi` + `dilithium-py` + `cryptography` >= 44 (OpenSSL >= 3.5 backend
for ML-DSA); all three are in the nix devshell python. Flash the no-touch build
built `--features advertise-pqc`.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaphid import decode, enc, find, read, send_cbor, write  # noqa: E402

try:
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65
except ImportError:
    sys.exit("missing dependency: pip install dilithium-py")

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    sys.exit("missing dependency: pip install 'cryptography>=44'")

import hid  # noqa: E402

CTAPHID_INIT = 0x86
CDH = bytes(range(32))

# (label, cose alg, dilithium-py class, pyca public-key class, pk_len, sig_len)
SETS = [
    ("ML-DSA-44", -48, ML_DSA_44, mldsa.MLDSA44PublicKey, 1312, 2420),
    ("ML-DSA-65", -49, ML_DSA_65, mldsa.MLDSA65PublicKey, 1952, 3309),
]


def ctap(dev, cid, cmd, fields=None):
    payload = bytes([cmd]) + (enc(fields) if fields is not None else b"")
    r = send_cbor(dev, cid, payload)
    return r[0], (decode(r[1:]) if len(r) > 1 else None)


def parse_mc(resp):
    ad = resp[2]
    clen = int.from_bytes(ad[53:55], "big")
    cose = decode(ad[55 + clen:])
    return ad[55:55 + clen], cose[3], cose.get(-1), ad, resp[3]


def openssl_verify(cls, pk, msg, sig):
    try:
        cls.from_public_bytes(pk).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def main():
    info = find()
    if not info:
        sys.exit("No FIDO HID device found — is the board plugged in?")
    dev = hid.device()
    dev.open_path(info["path"])
    try:
        write(dev, b"\xff\xff\xff\xff" + bytes([CTAPHID_INIT, 0, 8]) + bytes(range(8)))
        cid = read(dev)[15:19]
        status, _ = ctap(dev, cid, 0x07)  # reset
        assert status == 0x00, f"reset status {status:#x}"

        for label, alg, dil, pyca_cls, pk_len, sig_len in SETS:
            req = {
                1: CDH,
                2: {"id": f"xverify.{alg}.example"},
                3: {"id": b"\x01\x02", "name": "xv"},
                4: [{"alg": alg, "type": "public-key"}],
            }
            status, resp = ctap(dev, cid, 0x01, req)
            assert status == 0x00, f"{label} makeCredential {status:#x}"
            cred_id, got_alg, pk, ad, att = parse_mc(resp)
            assert got_alg == alg and len(pk) == pk_len and len(att["sig"]) == sig_len

            # getAssertion under the same credential.
            status, ga = ctap(dev, cid, 0x02, {1: req[2]["id"], 2: CDH,
                                               3: [{"id": cred_id, "type": "public-key"}]})
            assert status == 0x00, f"{label} getAssertion {status:#x}"
            ga_ad, ga_sig = ga[2], ga[3]

            for what, msg, sig in [("attestation", ad + CDH, att["sig"]),
                                   ("assertion", ga_ad + CDH, ga_sig)]:
                dpy = dil.verify(pk, msg, sig)
                ossl = openssl_verify(pyca_cls, pk, msg, sig)
                mark = "OK" if (dpy and ossl) else "FAIL"
                print(f"{label} {what:11} dilithium-py={dpy} openssl={ossl}  [{mark}]")
                assert dpy, f"{label} {what}: dilithium-py rejected a valid device signature"
                assert ossl, f"{label} {what}: OpenSSL rejected a valid device signature"

            # Negative control: a one-bit flip must be rejected by BOTH.
            bad = bytearray(att["sig"])
            bad[100] ^= 0x01
            assert not dil.verify(pk, ad + CDH, bytes(bad)), f"{label} dilithium-py accepted a tampered sig"
            assert not openssl_verify(pyca_cls, pk, ad + CDH, bytes(bad)), f"{label} OpenSSL accepted a tampered sig"

        print("PASS (device ML-DSA-44 + -65 signatures verify under dilithium-py AND OpenSSL; tamper rejected)")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
