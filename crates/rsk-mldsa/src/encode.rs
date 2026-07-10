// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Key and signature (de)serialization (FIPS 204 §7.2, Alg 22–28), ported
//! faithfully. Encoders write into a caller-provided slice of the exact
//! `pk_len` / `sig_len`; decoders take untrusted bytes in verification and
//! propagate the range rejections from [`crate::pack`].

use crate::pack::{
    bit_length, bit_pack, bit_unpack, hint_bit_pack, hint_bit_unpack, simple_bit_pack,
    simple_bit_unpack,
};
use crate::params::Q;
use crate::poly::{Poly, zero_vec};

// `D` is only referenced by the test-only sk decoder below.
#[cfg(test)]
use crate::params::D;

/// bitlen(q−1) − d = 23 − 13: the width of each packed `t1` coefficient.
const BLQD: usize = 10;

/// pkEncode (Alg 22): `pk = rho || SimpleBitPack(t1[i], 2^10−1)`. `out.len()` must
/// equal the parameter set's `pk_len`.
pub(crate) fn pk_encode<const K: usize>(rho: &[u8; 32], t1: &[Poly; K], out: &mut [u8]) {
    out[0..32].copy_from_slice(rho);
    let step = 32 * BLQD;
    for i in 0..K {
        simple_bit_pack(
            &t1[i],
            (1 << BLQD) - 1,
            &mut out[32 + i * step..32 + (i + 1) * step],
        );
    }
}

/// pkDecode (Alg 23): recover `(rho, t1)` from untrusted bytes. `Err` on malformed `t1`.
pub(crate) fn pk_decode<const K: usize>(pk: &[u8]) -> Result<([u8; 32], [Poly; K]), ()> {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[0..32]);
    let mut t1 = zero_vec::<K>();
    let step = 32 * BLQD;
    for i in 0..K {
        t1[i] = simple_bit_unpack(&pk[32 + i * step..32 + (i + 1) * step], (1 << BLQD) - 1)?;
    }
    Ok((rho, t1))
}

/// skDecode (Alg 25): reverse of skEncode. Test-only — the firmware re-expands
/// from the 32-byte seed and never deserializes `sk`; used to drive the ACVP
/// sigGen KAT from its `sk` bytes.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub(crate) fn sk_decode<const K: usize, const L: usize>(
    eta: i32,
    sk: &[u8],
) -> (
    [u8; 32],
    [u8; 32],
    [u8; 64],
    [Poly; L],
    [Poly; K],
    [Poly; K],
) {
    let top = 1 << (D - 1);
    let mut rho = [0u8; 32];
    let mut cap_k = [0u8; 32];
    let mut tr = [0u8; 64];
    rho.copy_from_slice(&sk[0..32]);
    cap_k.copy_from_slice(&sk[32..64]);
    tr.copy_from_slice(&sk[64..128]);
    let step = 32 * bit_length(2 * eta);
    let off_s1 = 128;
    let off_s2 = off_s1 + L * step;
    let off_t0 = off_s2 + K * step;
    let step_t0 = 32 * D as usize;
    let s1: [Poly; L] = core::array::from_fn(|i| {
        bit_unpack(&sk[off_s1 + i * step..off_s1 + (i + 1) * step], eta, eta).unwrap()
    });
    let s2: [Poly; K] = core::array::from_fn(|i| {
        bit_unpack(&sk[off_s2 + i * step..off_s2 + (i + 1) * step], eta, eta).unwrap()
    });
    let t0: [Poly; K] = core::array::from_fn(|i| {
        bit_unpack(
            &sk[off_t0 + i * step_t0..off_t0 + (i + 1) * step_t0],
            top - 1,
            top,
        )
        .unwrap()
    });
    (rho, cap_k, tr, s1, s2, t0)
}

/// sigEncode (Alg 26): `sig = c_tilde || BitPack(z, γ1−1, γ1) || HintBitPack(h)`.
pub(crate) fn sig_encode<const K: usize, const L: usize>(
    gamma1: i32,
    omega: i32,
    lambda_div4: usize,
    c_tilde: &[u8],
    z: &[Poly; L],
    h: &[Poly; K],
    out: &mut [u8],
) {
    out[..lambda_div4].copy_from_slice(&c_tilde[..lambda_div4]);
    let step = 32 * (1 + bit_length(gamma1 - 1));
    let start = lambda_div4;
    for i in 0..L {
        bit_pack(
            &z[i],
            gamma1 - 1,
            gamma1,
            &mut out[start + i * step..start + (i + 1) * step],
        );
    }
    hint_bit_pack::<K>(omega, h, &mut out[start + L * step..]);
}

/// sigDecode (Alg 27): recover `(c_tilde, z, h)` from an untrusted signature.
/// `Err` on out-of-range `z` or a malformed hint. `c_tilde` is returned in a
/// 64-byte buffer; only the first `lambda_div4` bytes are meaningful.
#[allow(clippy::type_complexity)]
pub(crate) fn sig_decode<const K: usize, const L: usize>(
    gamma1: i32,
    omega: i32,
    lambda_div4: usize,
    sig: &[u8],
) -> Result<([u8; 64], [Poly; L], [Poly; K]), ()> {
    let mut c_tilde = [0u8; 64];
    c_tilde[..lambda_div4].copy_from_slice(&sig[..lambda_div4]);
    let step = 32 * (bit_length(gamma1 - 1) + 1);
    let start = lambda_div4;
    let mut z = zero_vec::<L>();
    for i in 0..L {
        z[i] = bit_unpack(
            &sig[start + i * step..start + (i + 1) * step],
            gamma1 - 1,
            gamma1,
        )?;
    }
    let h = hint_bit_unpack::<K>(omega, &sig[start + L * step..])?;
    Ok((c_tilde, z, h))
}

/// w1Encode (Alg 28): `SimpleBitPack(w1[i], (q−1)/(2γ2)−1)` concatenated. `out.len()`
/// must equal the parameter set's `w1_len`.
pub(crate) fn w1_encode<const K: usize>(gamma2: i32, w1: &[Poly; K], out: &mut [u8]) {
    let bound = (Q - 1) / (2 * gamma2) - 1;
    let step = 32 * bit_length(bound);
    for i in 0..K {
        simple_bit_pack(&w1[i], bound, &mut out[i * step..(i + 1) * step]);
    }
}

#[cfg(test)]
#[path = "encode_tests.rs"]
mod tests;
