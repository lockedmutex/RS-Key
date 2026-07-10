// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bit-level packing of polynomials (FIPS 204 §7.1, Alg 16–21), ported
//! faithfully. `bit_unpack` / `hint_bit_unpack` take untrusted input during
//! verification and **reject** out-of-range or malformed encodings — that is the
//! surface where a forged signature would try to smuggle values, so the range
//! checks are load-bearing, not cosmetic.

use crate::poly::{Poly, zero_vec};

/// Bits needed to represent `x` (x ≥ 1). Only ever applied to public size
/// parameters, so its non-constant-time `ilog2` leaks nothing.
pub(crate) const fn bit_length(x: i32) -> usize {
    (x.ilog2() as usize) + 1
}

/// BitPack (Alg 17): encode coefficients in [−a, b] as `bitlen(a+b)` bits each.
pub(crate) fn bit_pack(w: &Poly, a: i32, b: i32, bytes_out: &mut [u8]) {
    debug_assert_eq!(
        w.0.len() * bit_length(a + b),
        bytes_out.len() * 8,
        "bit_pack bad size"
    );
    debug_assert!(
        w.0.iter().all(|&e| e >= -a && e <= b),
        "bit_pack input out of [-a,b]"
    );
    let bitlen = bit_length(a + b) as u32;
    let mut temp = 0u32;
    let mut byte_index = 0;
    let mut bit_index = 0u32;
    for &coeff in &w.0 {
        if a > 0 {
            temp |= b.abs_diff(coeff) << bit_index;
        } else {
            temp |= coeff.unsigned_abs() << bit_index;
        }
        bit_index += bitlen;
        while bit_index > 7 {
            bytes_out[byte_index] = temp.to_le_bytes()[0];
            temp >>= 8;
            byte_index += 1;
            bit_index -= 8;
        }
    }
}

/// SimpleBitPack (Alg 16): encode coefficients in [0, b].
pub(crate) fn simple_bit_pack(w: &Poly, b: i32, bytes_out: &mut [u8]) {
    bit_pack(w, 0, b, bytes_out);
}

/// BitUnpack (Alg 19): reverse of [`bit_pack`], with a range check. `Err` when a
/// decoded coefficient lands outside [b − 2^c + 1, b].
pub(crate) fn bit_unpack(v: &[u8], a: i32, b: i32) -> Result<Poly, ()> {
    debug_assert_eq!(v.len(), 32 * bit_length(a + b), "bit_unpack bad size");
    let bitlen = bit_length(a + b) as u32;
    let mut w = Poly::zero();
    let mut temp = 0i32;
    let mut r_index = 0;
    let mut bit_index = 0u32;
    for &byte in v {
        temp |= i32::from(byte) << bit_index;
        bit_index += 8;
        while bit_index >= bitlen {
            let tmask = temp & ((1 << bitlen) - 1);
            w.0[r_index] = if a == 0 { tmask } else { b - tmask };
            bit_index -= bitlen;
            temp >>= bitlen;
            r_index += 1;
        }
    }
    let bot = (b - (1 << bitlen) + 1).abs();
    if w.0.iter().all(|&e| e >= -bot && e <= b) {
        Ok(w)
    } else {
        Err(())
    }
}

/// SimpleBitUnpack (Alg 18): reverse of [`simple_bit_pack`].
pub(crate) fn simple_bit_unpack(v: &[u8], b: i32) -> Result<Poly, ()> {
    bit_unpack(v, 0, b)
}

/// HintBitPack (Alg 20): encode the `k` binary hint polynomials into `ω+k` bytes
/// (positions of the 1s, then the per-row cumulative counts). Non-secret output.
pub(crate) fn hint_bit_pack<const K: usize>(omega: i32, h: &[Poly; K], y_bytes: &mut [u8]) {
    let omega_u = omega as usize;
    debug_assert_eq!(y_bytes.len(), omega_u + K, "hint_bit_pack bad size");
    y_bytes.iter_mut().for_each(|e| *e = 0);
    let mut index = 0usize;
    for i in 0..K {
        for j in 0..256usize {
            if h[i].0[j] != 0 {
                y_bytes[index] = j as u8;
                index += 1;
            }
        }
        y_bytes[omega_u + i] = index as u8;
    }
}

/// HintBitUnpack (Alg 21): reverse of [`hint_bit_pack`] on untrusted input. `Err`
/// on any malformation (non-monotone indices, over-count, non-zero padding).
pub(crate) fn hint_bit_unpack<const K: usize>(omega: i32, y_bytes: &[u8]) -> Result<[Poly; K], ()> {
    let omega_u = omega as usize;
    debug_assert_eq!(y_bytes.len(), omega_u + K, "hint_bit_unpack bad size");
    let mut h: [Poly; K] = zero_vec();
    let mut index: u8 = 0;
    for i in 0..K {
        let lim = y_bytes[omega_u + i];
        if lim < index || lim > omega as u8 {
            return Err(());
        }
        let first = index;
        while index < lim {
            if index > first && y_bytes[usize::from(index) - 1] >= y_bytes[usize::from(index)] {
                return Err(());
            }
            h[i].0[usize::from(y_bytes[usize::from(index)])] = 1;
            index += 1;
        }
    }
    for i in index..(omega as u8) {
        if y_bytes[usize::from(i)] != 0 {
            return Err(());
        }
    }
    Ok(h)
}

#[cfg(test)]
#[path = "pack_tests.rs"]
mod tests;
