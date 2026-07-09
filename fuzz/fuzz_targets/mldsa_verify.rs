// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fuzz the ML-DSA verification decoders for BOTH parameter sets: the
//! already-covered `mldsa44_verify` and the newer `mldsa65_verify` (COSE -49),
//! whose distinct monomorphization (K=6/L=5, ω=55, γ1=2^19 → 20-bit z packing,
//! the γ2=(q−1)/32 `use_hint` branch, τ=49) sees no adversarial input today —
//! only the valid-only ACVP KATs. Attacker-shaped public keys + signatures flow
//! through `pk_decode` / `sig_decode` (bit-unpack + hint decode) and the verify
//! arithmetic. Nothing may panic, and a forged input must never verify `true`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rsk_crypto::{
    MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, mldsa44_verify,
    mldsa65_verify,
};

/// Spread `data` across a fixed-size buffer, offset per buffer so short inputs
/// still differentiate them — the shaping the existing `pqc` target uses.
fn fill(dst: &mut [u8], data: &[u8], salt: usize) {
    for (i, b) in dst.iter_mut().enumerate() {
        *b = data
            .get((i + salt) % data.len().max(1))
            .copied()
            .unwrap_or(salt as u8);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut pk44 = [0u8; MLDSA44_PK_LEN];
    let mut sig44 = [0u8; MLDSA44_SIG_LEN];
    let mut pk65 = [0u8; MLDSA65_PK_LEN];
    let mut sig65 = [0u8; MLDSA65_SIG_LEN];
    fill(&mut pk44, data, 0);
    fill(&mut sig44, data, 1);
    fill(&mut pk65, data, 2);
    fill(&mut sig65, data, 3);

    // The message is the raw input; no attacker without the secret key can make
    // these decode-and-verify true.
    assert!(!mldsa44_verify(&pk44, data, &sig44));
    assert!(!mldsa65_verify(&pk65, data, &sig65));
});
