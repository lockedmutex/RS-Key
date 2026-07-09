// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! High/low-order bits, rounding and hints (FIPS 204 §7.4, Alg 35–40), ported
//! faithfully. `decompose` is branchless and parameter-selected (`gamma2`'s bit
//! 17 distinguishes ML-DSA-44 from -65/-87), so it stays constant-time on the
//! secret coefficients that flow through it during signing. `use_hint` operates
//! only on public signature data and need not be constant-time.

use crate::params::{D, Q};
use crate::poly::Poly;
use crate::reduce::full_reduce32;

/// Power2Round over a whole polynomial (Alg 35): `r ≡ r1·2^d + r0 (mod q)` with
/// `r0` centered. Input coefficients must be in [0, q). Returns `(r1, r0)`.
pub(crate) fn power2round(r: &Poly) -> (Poly, Poly) {
    debug_assert!(
        r.0.iter().all(|&e| (0..Q).contains(&e)),
        "power2round input not in [0,q)"
    );
    let mut r1 = Poly::zero();
    let mut r0 = Poly::zero();
    for n in 0..256 {
        let hi = (r.0[n] + (1 << (D - 1)) - 1) >> D;
        r1.0[n] = hi;
        r0.0[n] = r.0[n] - (hi << D);
        debug_assert_eq!(r.0[n], (r1.0[n] << D) + r0.0[n], "power2round reconstruct");
    }
    (r1, r0)
}

/// Decompose (Alg 36): `r ≡ r1·(2γ2) + r0 (mod q)` with `r0` centered.
pub(crate) fn decompose(gamma2: i32, r: i32) -> (i32, i32) {
    let rp = full_reduce32(r);
    let mut r1;
    if gamma2 & (1 << 17) == 0 {
        // ML-DSA-44 (γ2 = (q−1)/88): m = (q−1)/(2γ2) = 44
        r1 = (rp + 127) >> 7;
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
    } else {
        // ML-DSA-65 / -87 (γ2 = (q−1)/32): m = 16
        r1 = (rp + 127) >> 7;
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15;
    }
    let mut r0 = rp - r1 * 2 * gamma2;
    r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;
    debug_assert_eq!(
        r.rem_euclid(Q),
        (r1 * 2 * gamma2 + r0).rem_euclid(Q),
        "decompose reconstruct"
    );
    (r1, r0)
}

/// HighBits (Alg 37): the `r1` component of `Decompose`.
pub(crate) fn high_bits(gamma2: i32, r: i32) -> i32 {
    decompose(gamma2, r).0
}

/// LowBits (Alg 38): the `r0` component of `Decompose`.
pub(crate) fn low_bits(gamma2: i32, r: i32) -> i32 {
    decompose(gamma2, r).1
}

/// MakeHint (Alg 39): does adding `z` to `r` change `r`'s high bits?
pub(crate) fn make_hint(gamma2: i32, z: i32, r: i32) -> bool {
    high_bits(gamma2, r) != high_bits(gamma2, r + z)
}

/// UseHint (Alg 40): reconstruct high bits from `r` adjusted by hint `h`. Public
/// data only — the branches here are not on secrets.
pub(crate) fn use_hint(gamma2: i32, h: i32, r: i32) -> i32 {
    let (r1, r0) = decompose(gamma2, r);
    if h == 0 {
        return r1;
    }
    if gamma2 & (1 << 17) == 0 {
        // ML-DSA-44, modulus m = 44
        if r0 > 0 {
            if r1 == 43 { 0 } else { r1 + 1 }
        } else if r1 == 0 {
            43
        } else {
            r1 - 1
        }
    } else {
        // ML-DSA-65 / -87, modulus m = 16
        if r0 > 0 { (r1 + 1) & 15 } else { (r1 - 1) & 15 }
    }
}

#[cfg(test)]
#[path = "round_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "round_kani.rs"]
mod proofs;
