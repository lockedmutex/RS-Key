// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bounded proofs for the rounding invariants (FIPS 204 §7.4). Each takes a
//! single symbolic `i32`, so the arithmetic is straight-line and fully
//! explored — no unwinding needed.

use super::*;
use crate::params::{ML_DSA_44, ML_DSA_65, Q};

/// `Decompose(r) = (r1, r0)` with `r ≡ r1·2γ2 + r0 (mod q)` and `|r0| ≤ γ2`.
fn decompose_reconstructs(gamma2: i32) {
    let r: i32 = kani::any();
    kani::assume((0..Q).contains(&r));
    let (r1, r0) = decompose(gamma2, r);
    assert!((r1 * 2 * gamma2 + r0).rem_euclid(Q) == r.rem_euclid(Q));
    assert!(r0 >= -gamma2 && r0 <= gamma2);
}

#[kani::proof]
fn decompose_reconstructs_mldsa44() {
    decompose_reconstructs(ML_DSA_44.gamma2);
}

#[kani::proof]
fn decompose_reconstructs_mldsa65() {
    decompose_reconstructs(ML_DSA_65.gamma2);
}

/// `UseHint(MakeHint(z, r), r) = HighBits(r + z)` for `|z| ≤ γ2` (FIPS 204's
/// hint-correctness guarantee).
fn use_make_hint_roundtrip(gamma2: i32) {
    let r: i32 = kani::any();
    let z: i32 = kani::any();
    kani::assume((0..Q).contains(&r));
    kani::assume(z >= -gamma2 && z <= gamma2);
    let h = i32::from(make_hint(gamma2, z, r));
    assert!(use_hint(gamma2, h, r) == high_bits(gamma2, (r + z).rem_euclid(Q)));
}

#[kani::proof]
fn use_make_hint_roundtrip_mldsa44() {
    use_make_hint_roundtrip(ML_DSA_44.gamma2);
}

#[kani::proof]
fn use_make_hint_roundtrip_mldsa65() {
    use_make_hint_roundtrip(ML_DSA_65.gamma2);
}
