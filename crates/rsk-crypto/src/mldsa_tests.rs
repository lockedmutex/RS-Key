// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SEED: [u8; 32] = [0x42; 32];
const MSG: &[u8] = b"authData||clientDataHash";

#[test]
fn keygen_is_deterministic_and_seed_sensitive() {
    let a = MlDsa44::from_seed(&SEED);
    let b = MlDsa44::from_seed(&SEED);
    assert_eq!(a.public_key(), b.public_key());

    let mut other = SEED;
    other[0] ^= 1;
    assert_ne!(a.public_key(), MlDsa44::from_seed(&other).public_key());
}

// Regression pin: the public key for a fixed seed must not silently change
// across fips204 upgrades (it is a deterministic function of ξ). Pinned as
// a SHA-256 to keep the test readable.
#[test]
fn keygen_pk_regression_pin() {
    let pk = MlDsa44::from_seed(&SEED).public_key();
    let digest = crate::sha256(&pk);
    assert_eq!(
        digest,
        [
            0x19, 0x50, 0x6c, 0x63, 0xf5, 0x04, 0xc1, 0x75, 0x01, 0x3c, 0xf1, 0xb4, 0x59, 0x39,
            0x7b, 0xbb, 0xc2, 0xce, 0x6a, 0x3f, 0xd8, 0x41, 0xba, 0xb6, 0x8b, 0x38, 0x98, 0xf6,
            0xf2, 0xfd, 0xdc, 0x2f
        ],
        "pinned ML-DSA-44 public key changed — fips204 behavior shift?"
    );
}

#[test]
fn sign_verify_roundtrip() {
    let key = MlDsa44::from_seed(&SEED);
    let mut sig = [0u8; MLDSA44_SIG_LEN];
    let n = key.sign(MSG, &[7u8; 32], &mut sig).unwrap();
    assert_eq!(n, MLDSA44_SIG_LEN);
    assert!(mldsa44_verify(&key.public_key(), MSG, &sig));
}

#[test]
fn verify_rejects_wrong_message_key_and_tamper() {
    let key = MlDsa44::from_seed(&SEED);
    let mut sig = [0u8; MLDSA44_SIG_LEN];
    key.sign(MSG, &[7u8; 32], &mut sig).unwrap();
    let pk = key.public_key();

    assert!(!mldsa44_verify(&pk, b"other message", &sig));

    let mut other_seed = SEED;
    other_seed[31] ^= 1;
    let other_pk = MlDsa44::from_seed(&other_seed).public_key();
    assert!(!mldsa44_verify(&other_pk, MSG, &sig));

    let mut bad = sig;
    bad[100] ^= 1;
    assert!(!mldsa44_verify(&pk, MSG, &bad));
}

#[test]
fn same_rnd_same_signature_distinct_rnd_distinct() {
    let key = MlDsa44::from_seed(&SEED);
    let mut a = [0u8; MLDSA44_SIG_LEN];
    let mut b = [0u8; MLDSA44_SIG_LEN];
    key.sign(MSG, &[1u8; 32], &mut a).unwrap();
    key.sign(MSG, &[1u8; 32], &mut b).unwrap();
    assert_eq!(a, b, "fixed hedge rnd → reproducible signature");

    key.sign(MSG, &[2u8; 32], &mut b).unwrap();
    assert_ne!(a, b, "different hedge rnd → different signature");
    assert!(mldsa44_verify(&key.public_key(), MSG, &b));
}

#[test]
fn sign_buffer_too_small() {
    let key = MlDsa44::from_seed(&SEED);
    let mut tiny = [0u8; 64];
    assert_eq!(key.sign(MSG, &[0u8; 32], &mut tiny), Err(Error::BadLength));
}

// Does keygen → sign → verify fit in a `STACK_KIB`-KiB stack? One size per
// process — a thread stack overflow aborts the whole process on macOS, so
// the caller loops over sizes from the shell and reads pass/abort:
//   for k in 24 32 48 64; STACK_KIB=$k cargo test --release -p rsk-crypto \
//     --target <host> -- --ignored stack_floor_probe; end
// The RP2350 worker must keep at least the floor (plus our frames) free.
#[test]
#[ignore]
fn stack_floor_probe() {
    let kib: usize = std::env::var("STACK_KIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(|| {
            let key = MlDsa44::from_seed(&SEED);
            let mut sig = [0u8; MLDSA44_SIG_LEN];
            key.sign(MSG, &[7u8; 32], &mut sig).unwrap();
            assert!(mldsa44_verify(&key.public_key(), MSG, &sig));
        })
        .unwrap()
        .join()
        .unwrap();
    std::eprintln!("ML-DSA-44 keygen+sign+verify fits in {kib} KiB stack");
}
