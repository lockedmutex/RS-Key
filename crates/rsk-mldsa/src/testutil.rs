// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Deterministic helpers shared by the host tests — a SplitMix64 PRNG, ranged
//! polynomial generators, and a hex parser — so the tests pull in neither `rand`
//! nor `hex`. `std` is available here (the crate is `no_std` only for
//! `not(test)`).

use crate::params::Q;
use crate::poly::Poly;

/// SplitMix64 — small, fast, fully deterministic from its seed.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.next_u64() as u8;
        }
    }
}

/// A polynomial with coefficients uniform in [lo, hi].
pub(crate) fn rand_poly_range(rng: &mut Rng, lo: i32, hi: i32) -> Poly {
    let span = (hi - lo + 1) as u64;
    let mut p = Poly::zero();
    for c in &mut p.0 {
        *c = lo + (rng.next_u64() % span) as i32;
    }
    p
}

/// A canonical polynomial with coefficients in [0, q).
pub(crate) fn rand_poly_q(rng: &mut Rng) -> Poly {
    let mut p = Poly::zero();
    for c in &mut p.0 {
        *c = (rng.next_u64() % (Q as u64)) as i32;
    }
    p
}

/// Parse an ASCII hex string (any case, no separators) into bytes.
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}
