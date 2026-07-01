// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Minimal allocation-free DER encoder for the U2F attestation certificate, a
//! self-signed P-256 X.509 v3 cert. Every field except the 65-byte subject
//! public key, the 16-byte serial and the signature is fixed, so the
//! TBSCertificate is a constant-length template (206 content bytes).

use crate::ec::{MAX_DER_SIG, P256Key};

// [0] EXPLICIT version v3 (INTEGER 2).
const VERSION: &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
// AlgorithmIdentifier ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2).
const SIG_ALG: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];
// Name = SEQUENCE{ SET{ SEQ{ CN(2.5.4.3), UTF8String "RSK FIDO2" } } }.
const NAME: &[u8] = &[
    0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x09, b'R', b'S', b'K',
    b' ', b'F', b'I', b'D', b'O', b'2',
];
// Validity = SEQUENCE{ GeneralizedTime notBefore, notAfter }.
const VALIDITY: &[u8] = &[
    0x30, 0x22, 0x18, 0x0F, b'2', b'0', b'2', b'2', b'0', b'9', b'0', b'1', b'0', b'0', b'0', b'0',
    b'0', b'0', b'Z', 0x18, 0x0F, b'2', b'0', b'7', b'2', b'0', b'8', b'3', b'1', b'2', b'3', b'5',
    b'9', b'5', b'9', b'Z',
];
// SubjectPublicKeyInfo header up to the BIT STRING contents: SEQ{ SEQ{ ecPublicKey
// (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7) }, BIT STRING 0x00 ‖ … }.
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// TBSCertificate length (header `30 81 CE` + 206 content bytes).
const TBS_LEN: usize = 209;

/// Build the self-signed attestation certificate for `key` into `out`; returns its
/// DER length. `serial` is 16 random bytes (the caller clears the top bit to keep
/// the INTEGER positive). `out` should hold ≥ 384 bytes.
pub fn build_attestation_cert(key: &P256Key, serial: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let (x, y) = key.public_xy();

    // --- TBSCertificate (fixed 209 bytes) ---
    let mut tbs = [0u8; TBS_LEN];
    let mut p = 0;
    let put = |dst: &mut [u8; TBS_LEN], pos: &mut usize, b: &[u8]| {
        dst[*pos..*pos + b.len()].copy_from_slice(b);
        *pos += b.len();
    };
    put(&mut tbs, &mut p, &[0x30, 0x81, 0xCE]); // SEQUENCE, 206 content bytes
    put(&mut tbs, &mut p, VERSION);
    put(&mut tbs, &mut p, &[0x02, 0x10]); // INTEGER, 16 bytes
    put(&mut tbs, &mut p, serial);
    put(&mut tbs, &mut p, SIG_ALG);
    put(&mut tbs, &mut p, NAME); // issuer
    put(&mut tbs, &mut p, VALIDITY);
    put(&mut tbs, &mut p, NAME); // subject
    put(&mut tbs, &mut p, SPKI_PREFIX);
    put(&mut tbs, &mut p, &[0x04]); // uncompressed point marker
    put(&mut tbs, &mut p, &x);
    put(&mut tbs, &mut p, &y);
    debug_assert_eq!(p, TBS_LEN);

    // --- sign the TBS, assemble the Certificate ---
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&tbs, &mut sig);

    let content = TBS_LEN + SIG_ALG.len() + 3 + sl; // tbs + sigAlg + BITSTRING(03 len 00) + sig
    let total = 4 + content; // 30 82 hi lo
    if out.len() < total {
        return None;
    }
    let mut q = 0;
    out[q..q + 4].copy_from_slice(&[0x30, 0x82, (content >> 8) as u8, content as u8]);
    q += 4;
    out[q..q + TBS_LEN].copy_from_slice(&tbs);
    q += TBS_LEN;
    out[q..q + SIG_ALG.len()].copy_from_slice(SIG_ALG);
    q += SIG_ALG.len();
    out[q..q + 3].copy_from_slice(&[0x03, (1 + sl) as u8, 0x00]); // BIT STRING, 0 unused bits
    q += 3;
    out[q..q + sl].copy_from_slice(&sig[..sl]);
    q += sl;
    Some(q)
}

// ---- org attestation chain (EF_ATT_CHAIN) ----

/// Caps for an org-provisioned attestation chain (vendor ATT_IMPORT).
pub(crate) const ATT_CHAIN_MAX: usize = 2048;
pub(crate) const ATT_CHAIN_MAX_CERTS: usize = 4;

/// Total length of the DER TLV at the head of `b` (SEQUENCE tag), or `None`.
fn der_seq_len(b: &[u8]) -> Option<usize> {
    if b.len() < 2 || b[0] != 0x30 {
        return None;
    }
    match b[1] {
        l @ 0..=0x7F => Some(2 + l as usize),
        0x81 => (b.len() >= 3).then(|| 3 + b[2] as usize),
        0x82 => (b.len() >= 4).then(|| 4 + u16::from_be_bytes([b[2], b[3]]) as usize),
        _ => None, // > 64 KiB cannot be a sane certificate
    }
}

/// Validate a leaf-first concatenation of DER certificates and pack it into
/// the `EF_ATT_CHAIN` layout: `count(1) ‖ (len(2 LE) ‖ der)*`. Framing only —
/// the import channel is authenticated, and a key/cert mismatch is the org's
/// own first verification failure, not a parsing concern.
pub(crate) fn att_chain_pack(chain: &[u8], out: &mut [u8]) -> Option<usize> {
    if chain.is_empty() || chain.len() > ATT_CHAIN_MAX {
        return None;
    }
    let mut count = 0u8;
    let (mut src, mut dst) = (0usize, 1usize);
    while src < chain.len() {
        let l = der_seq_len(&chain[src..])?;
        if src + l > chain.len() || count as usize == ATT_CHAIN_MAX_CERTS || dst + 2 + l > out.len()
        {
            return None;
        }
        out[dst..dst + 2].copy_from_slice(&(l as u16).to_le_bytes());
        out[dst + 2..dst + 2 + l].copy_from_slice(&chain[src..src + l]);
        dst += 2 + l;
        src += l;
        count += 1;
    }
    out[0] = count;
    Some(dst)
}

/// Number of certificates in a packed chain.
pub(crate) fn att_chain_count(blob: &[u8]) -> u8 {
    blob.first().copied().unwrap_or(0)
}

/// Byte range of the `i`-th certificate in a packed chain.
pub(crate) fn att_chain_cert_range(blob: &[u8], i: u8) -> Option<(usize, usize)> {
    let mut off = 1usize;
    for idx in 0..att_chain_count(blob) {
        if off + 2 > blob.len() {
            return None;
        }
        let l = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
        if off + 2 + l > blob.len() {
            return None;
        }
        if idx == i {
            return Some((off + 2, l));
        }
        off += 2 + l;
    }
    None
}

/// The `i`-th certificate of a packed chain.
pub(crate) fn att_chain_cert(blob: &[u8], i: u8) -> Option<&[u8]> {
    att_chain_cert_range(blob, i).map(|(o, l)| &blob[o..o + l])
}

#[cfg(test)]
#[path = "cert_tests.rs"]
mod tests;
