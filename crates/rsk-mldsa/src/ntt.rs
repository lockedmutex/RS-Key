// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The Number-Theoretic Transform (FIPS 204 §7.5, Alg 41/42), transforming **in
//! place** on a [`Poly`]. This is the one deliberate departure from the
//! reference, which returns a fresh `[T; KL]` array each call: in-place removes
//! the per-transform copy that (multiplied across a signing loop) is a large part
//! of why the by-value implementation overflows the RP2350 stack.
//!
//! `ntt` maps normal → NTT domain and `inv_ntt` maps back (with the 1/256
//! factor), so `inv_ntt(ntt(x)) == x` for `x` reduced to [0, q). The twiddles
//! are pre-multiplied by 2^32 so the butterfly's `mont_reduce` yields a plain
//! (non-Montgomery) product.

use crate::params::{N, Q, ZETA};
use crate::poly::Poly;
use crate::reduce::{full_reduce32, mont_reduce};

/// ζ^brv8(i)·2^32 mod q for i ∈ [0, 256). Built at compile time.
static ZETA_TABLE_MONT: [i32; N] = gen_zeta_table_mont();

const fn gen_zeta_table_mont() -> [i32; N] {
    let mut result = [0i32; N];
    let mut x = 1i64;
    let mut i = 0u32;
    while i < 256 {
        result[(i as u8).reverse_bits() as usize] = ((x << 32) % (Q as i64)) as i32;
        x = (x * ZETA as i64) % (Q as i64);
        i += 1;
    }
    result
}

/// Forward NTT in place (Alg 41). Input normal domain → output NTT domain.
pub(crate) fn ntt_inplace(w: &mut Poly) {
    let mut m = 0usize;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < 256 {
            m += 1;
            let zeta = i64::from(ZETA_TABLE_MONT[m]);
            for j in start..(start + len) {
                let t = mont_reduce(zeta * i64::from(w.0[j + len]));
                w.0[j + len] = w.0[j] - t;
                w.0[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT in place (Alg 42). Input NTT domain → output normal domain,
/// reduced to [0, q).
pub(crate) fn inv_ntt_inplace(w: &mut Poly) {
    #[allow(clippy::cast_possible_truncation)]
    const F_MONT: i64 = 8_347_681_i128.wrapping_mul(1 << 32).rem_euclid(Q as i128) as i64; // (256^-1)·2^32
    let mut m = 256usize;
    let mut len = 1;
    while len < 256 {
        let mut start = 0;
        while start < 256 {
            m -= 1;
            let zeta = -ZETA_TABLE_MONT[m];
            for j in start..(start + len) {
                let t = w.0[j];
                w.0[j] = t + w.0[j + len];
                w.0[j + len] = t - w.0[j + len];
                w.0[j + len] = mont_reduce(i64::from(zeta) * i64::from(w.0[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in &mut w.0 {
        *c = full_reduce32(mont_reduce(F_MONT * i64::from(*c)));
    }
}

#[cfg(test)]
#[path = "ntt_tests.rs"]
mod tests;
