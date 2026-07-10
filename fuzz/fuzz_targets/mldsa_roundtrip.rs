// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Property-fuzz the ML-DSA sign path the device actually runs. Expand a keypair
//! from a fuzzed seed, sign a fuzzed message with fuzzed hedge randomness, and
//! require the produced signature to verify `true`; then require a one-bit
//! tamper to verify `false`. Also require a short output buffer to be rejected.
//! This drives the rejection loop, packing and reduce/NTT arithmetic (keygen +
//! sign + verify) on non-KAT inputs for both parameter sets — the arithmetic the
//! valid-only ACVP KATs and the decode-reject `mldsa_verify` target never reach.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rsk_crypto::{
    MLDSA44_SIG_LEN, MLDSA65_SIG_LEN, MlDsa44, MlDsa65, mldsa44_verify, mldsa65_verify,
};

fuzz_target!(|data: &[u8]| {
    // First 32 bytes → seed ξ, next 32 → hedge randomness, remainder → message.
    let mut seed = [0u8; 32];
    let mut rnd = [0u8; 32];
    let seed_src = &data[..data.len().min(32)];
    let rnd_src = if data.len() > 32 {
        &data[32..data.len().min(64)]
    } else {
        &[][..]
    };
    let msg = if data.len() > 64 {
        &data[64..]
    } else {
        &[][..]
    };
    seed[..seed_src.len()].copy_from_slice(seed_src);
    rnd[..rnd_src.len()].copy_from_slice(rnd_src);

    // --- ML-DSA-44 ---
    let k44 = MlDsa44::from_seed(&seed);
    let pk44 = k44.public_key();
    let mut small = [0u8; MLDSA44_SIG_LEN - 1];
    assert!(
        k44.sign(msg, &rnd, &mut small).is_err(),
        "short buffer rejected"
    );
    let mut sig44 = [0u8; MLDSA44_SIG_LEN];
    let n44 = k44.sign(msg, &rnd, &mut sig44).expect("full buffer signs");
    assert_eq!(n44, MLDSA44_SIG_LEN);
    assert!(
        mldsa44_verify(&pk44, msg, &sig44),
        "own -44 signature verifies"
    );
    sig44[0] ^= 1;
    assert!(
        !mldsa44_verify(&pk44, msg, &sig44),
        "one-bit tamper breaks -44"
    );

    // --- ML-DSA-65 ---
    let k65 = MlDsa65::from_seed(&seed);
    let pk65 = k65.public_key();
    let mut sig65 = [0u8; MLDSA65_SIG_LEN];
    let n65 = k65.sign(msg, &rnd, &mut sig65).expect("full buffer signs");
    assert_eq!(n65, MLDSA65_SIG_LEN);
    assert!(
        mldsa65_verify(&pk65, msg, &sig65),
        "own -65 signature verifies"
    );
    sig65[0] ^= 1;
    assert!(
        !mldsa65_verify(&pk65, msg, &sig65),
        "one-bit tamper breaks -65"
    );
});
