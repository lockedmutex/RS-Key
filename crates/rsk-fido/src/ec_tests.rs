// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use p256::EncodedPoint;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

#[test]
fn sign_is_deterministic_and_verifies() {
    let scalar = [0x11u8; 32];
    let key = P256Key::from_scalar(&scalar).unwrap();
    let msg = b"authData||clientDataHash";

    let mut a = [0u8; MAX_DER_SIG];
    let mut b = [0u8; MAX_DER_SIG];
    let na = key.sign_der(msg, &mut a);
    let nb = key.sign_der(msg, &mut b);
    assert_eq!(&a[..na], &b[..nb], "RFC 6979 nonce → identical signatures");

    // Reconstruct the public key from the COSE coords and verify.
    let (x, y) = key.public_xy();
    let pt = EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
    let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
    let sig = Signature::from_der(&a[..na]).unwrap();
    assert!(vk.verify(msg, &sig).is_ok());
}

#[test]
fn out_of_range_scalar_rejected() {
    // n < this < 2^256: the group order's high bytes are 0xFFFF…, so all-FF
    // is above n and must be rejected.
    assert!(P256Key::from_scalar(&[0xFFu8; 32]).is_none());
    // Zero is not a valid private scalar either.
    assert!(P256Key::from_scalar(&[0u8; 32]).is_none());
}

#[test]
fn distinct_scalars_give_distinct_keys() {
    let k1 = P256Key::from_scalar(&[0x11u8; 32]).unwrap();
    let k2 = P256Key::from_scalar(&[0x22u8; 32]).unwrap();
    assert_ne!(k1.public_xy(), k2.public_xy());
}

use crate::consts::{
    ALG_EDDSA, ALG_ES256K, ALG_ES384, ALG_ES512, CURVE_ED25519, CURVE_P256K1, CURVE_P384,
    CURVE_P521,
};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

const MSG: &[u8] = b"authData||clientDataHash";

#[test]
fn p521_comb_matches_mul_by_generator() {
    use p521::Scalar;
    use p521::elliptic_curve::PrimeField;
    use p521::elliptic_curve::ops::MulByGenerator;
    use p521::elliptic_curve::sec1::ToEncodedPoint;

    // Scalars exercising each 131-bit comb block, its boundaries, and a spread.
    let mut reprs: std::vec::Vec<[u8; 66]> = std::vec::Vec::new();
    reprs.push([0u8; 66]); // 0 → identity
    let mut one = [0u8; 66];
    one[65] = 1;
    reprs.push(one); // 1 → G
    for bitpos in [131usize, 262, 393, 520] {
        let mut r = [0u8; 66];
        r[65 - bitpos / 8] = 1 << (bitpos % 8);
        reprs.push(r); // 2^bitpos → a comb base point / block boundary
    }
    let mut spread = [0u8; 66];
    for (b, byte) in spread.iter_mut().enumerate() {
        *byte = (b as u8).wrapping_mul(37).wrapping_add(1);
    }
    spread[0] = 0; // keep < 2^520 < n so from_repr accepts
    reprs.push(spread);

    for r in reprs {
        let fb = p521::FieldBytes::clone_from_slice(&r);
        let k = Option::<Scalar>::from(Scalar::from_repr(fb)).expect("scalar in range");
        let got = comb_mul(&k).to_affine().to_encoded_point(false);
        let want = p521::ProjectivePoint::mul_by_generator(&k)
            .to_affine()
            .to_encoded_point(false);
        assert_eq!(got, want, "comb mismatch for scalar {r:?}");
    }
}

struct SeqRng(u64);
impl crate::Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

// Encode cose_public and pull the (x, y) byte strings (curve-agnostic shape).
fn cose_xy(key: &CredKey) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        key.cose_public(&mut e).unwrap();
        e.writer().position()
    };
    let mut d = Decoder::new(&buf[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 5);
    d.u8().unwrap();
    d.u8().unwrap(); // 1: kty 2
    d.u8().unwrap();
    d.i64().unwrap(); // 3: alg
    d.i8().unwrap();
    d.u8().unwrap(); // -1: crv
    d.i8().unwrap();
    let x = d.bytes().unwrap().to_vec(); // -2
    d.i8().unwrap();
    let y = d.bytes().unwrap().to_vec(); // -3
    (x, y)
}

#[test]
fn p384_sign_verifies_under_cose_key() {
    use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let key = CredKey::from_raw(CURVE_P384 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
    assert_eq!(key.alg(), ALG_ES384);
    let mut sig = [0u8; MAX_SIG_LEN];
    let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
    let (x, y) = cose_xy(&key);
    assert_eq!(x.len(), 48);
    let pt = p384::EncodedPoint::from_affine_coordinates(
        p384::FieldBytes::from_slice(&x),
        p384::FieldBytes::from_slice(&y),
        false,
    );
    let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
    vk.verify(MSG, &Signature::from_der(&sig[..n]).unwrap())
        .unwrap();
}

#[test]
fn p521_sign_verifies_under_cose_key() {
    use p521::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let key = CredKey::from_raw(CURVE_P521 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
    assert_eq!(key.alg(), ALG_ES512);
    let mut sig = [0u8; MAX_SIG_LEN];
    let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
    let (x, y) = cose_xy(&key);
    assert_eq!(x.len(), 66);
    let pt = p521::EncodedPoint::from_affine_coordinates(
        p521::FieldBytes::from_slice(&x),
        p521::FieldBytes::from_slice(&y),
        false,
    );
    let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
    vk.verify(MSG, &Signature::from_der(&sig[..n]).unwrap())
        .unwrap();
}

#[test]
fn k256_sign_verifies_under_cose_key() {
    use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let key = CredKey::from_raw(CURVE_P256K1 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
    assert_eq!(key.alg(), ALG_ES256K);
    let mut sig = [0u8; MAX_SIG_LEN];
    let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
    let (x, y) = cose_xy(&key);
    assert_eq!(x.len(), 32);
    let pt = k256::EncodedPoint::from_affine_coordinates(
        k256::FieldBytes::from_slice(&x),
        k256::FieldBytes::from_slice(&y),
        false,
    );
    let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
    vk.verify(MSG, &Signature::from_der(&sig[..n]).unwrap())
        .unwrap();
}

#[test]
fn ed25519_sign_verifies_under_cose_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = CredKey::from_raw(CURVE_ED25519 as i64, &[0x11u8; RATCHET_LEN]).unwrap();
    assert_eq!(key.alg(), ALG_EDDSA);
    let mut sig = [0u8; MAX_SIG_LEN];
    let n = key.sign(MSG, &mut SeqRng(1), &mut sig);
    assert_eq!(n, 64, "EdDSA signatures are raw 64 bytes");

    // OKP COSE key: {1: 1, 3: EdDSA, -1: 6, -2: pubkey(32)}.
    let mut buf = [0u8; 128];
    let cn = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        key.cose_public(&mut e).unwrap();
        e.writer().position()
    };
    let mut d = Decoder::new(&buf[..cn]);
    assert_eq!(d.map().unwrap().unwrap(), 4);
    d.u8().unwrap();
    assert_eq!(d.u8().unwrap(), 1); // kty OKP
    d.u8().unwrap();
    assert_eq!(d.i64().unwrap(), ALG_EDDSA);
    d.i8().unwrap();
    assert_eq!(d.u8().unwrap(), CURVE_ED25519);
    d.i8().unwrap();
    let pk: [u8; 32] = d.bytes().unwrap().try_into().unwrap();

    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    vk.verify(MSG, &Signature::from_slice(&sig[..n]).unwrap())
        .unwrap();
}

// Rough timing of the makeCredential crypto (from_raw + cose_public + sign)
// per curve. Ignored by default; run with `--release` and
// `--ignored --nocapture` to compare opt-levels (set CARGO_PROFILE_RELEASE_OPT_LEVEL).
#[test]
#[ignore]
fn bench_register_crypto() {
    use std::time::Instant;
    let raw = [0x11u8; RATCHET_LEN];
    for (name, curve) in [
        ("P256", CURVE_P256),
        ("P384", CURVE_P384),
        ("P521", CURVE_P521),
        ("K256", CURVE_P256K1),
        ("Ed25519", CURVE_ED25519),
    ] {
        let iters = 50u32;
        let mut rng = SeqRng(1);
        let mut sig = [0u8; MAX_SIG_LEN];
        let mut buf = [0u8; 256];
        let t = Instant::now();
        for _ in 0..iters {
            let key = CredKey::from_raw(curve as i64, &raw).unwrap();
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            key.cose_public(&mut e).unwrap();
            key.sign(MSG, &mut rng, &mut sig);
        }
        let per = t.elapsed() / iters;
        std::eprintln!("{name}: {per:?}/register-crypto");
    }
}

#[test]
fn p256_credkey_matches_p256key() {
    // CredKey::P256 and P256Key derive the same public point from one scalar.
    let raw = [0x11u8; RATCHET_LEN];
    let ck = CredKey::from_raw(CURVE_P256 as i64, &raw).unwrap();
    assert_eq!(ck.alg(), ALG_ES256);
    let (x, y) = cose_xy(&ck);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&raw[..32]);
    let (px, py) = P256Key::from_scalar(&scalar).unwrap().public_xy();
    assert_eq!(x, px);
    assert_eq!(y, py);
}

#[test]
fn credkey_stays_compact_so_mldsa_key_is_off_the_stack() {
    // The ML-DSA-44 keypair is ~13 KB of `rsk-mldsa` expanded-key state. Held
    // inline in `CredKey` it rode the worker stack into `sign`, which already
    // nearly fills the RP2350's ~222 KiB stack — the 13 KB tipped getAssertion
    // into overflow → a hard device wedge. It MUST stay `Box`-ed (heap, idle
    // during a FIDO request). This guard fails loudly if the key regresses back
    // inline: the boxed enum is a few hundred bytes (largest inline variant is
    // Ed25519's expanded `SigningKey`), an inline keypair would be ~13 KB.
    let size = core::mem::size_of::<CredKey>();
    assert!(
        size <= 512,
        "CredKey is {size} bytes — is the ML-DSA-44 keypair still Box-ed? \
         An inline rsk-mldsa keypair (~13 KB) overflows the worker stack in sign()."
    );
}
