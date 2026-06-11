// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! HMAC-DRBG (NIST SP 800-90A) over HMAC-SHA256 — the firmware's whitening
//! CSPRNG. The firmware seeds and periodically reseeds it from the hardware TRNG
//! at sample-chain length 0; per-operation TRNG draws are avoided because the
//! TRNG's autocorrelation health test stalls at longer chain settings. Per-draw
//! cost is a few HMAC-SHA256 ops — microseconds, uniform.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// HMAC-SHA256 output / DRBG state size.
const SEEDLEN: usize = 32;

/// HMAC-DRBG over HMAC-SHA256. Instantiate with [`HmacDrbg::new`], draw with
/// [`HmacDrbg::fill`], refresh entropy with [`HmacDrbg::reseed`].
pub struct HmacDrbg {
    k: [u8; SEEDLEN],
    v: [u8; SEEDLEN],
}

impl HmacDrbg {
    /// Instantiate from `seed` — the caller concatenates entropy ‖ nonce ‖
    /// personalization (SP 800-90A 10.1.2.3).
    pub fn new(seed: &[u8]) -> Self {
        let mut d = Self {
            k: [0x00; SEEDLEN],
            v: [0x01; SEEDLEN],
        };
        d.update(seed);
        d
    }

    /// `HMAC(key, a ‖ b ‖ c)` — parts fed without concatenating (no alloc).
    fn hmac(key: &[u8; SEEDLEN], a: &[u8], b: &[u8], c: &[u8]) -> [u8; SEEDLEN] {
        let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(a);
        m.update(b);
        m.update(c);
        let mut out = [0u8; SEEDLEN];
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }

    /// SP 800-90A 10.1.2.2 Update; an empty `provided` is the no-data form.
    fn update(&mut self, provided: &[u8]) {
        // K = HMAC(K, V ‖ 0x00 ‖ provided); V = HMAC(K, V)
        self.k = Self::hmac(&self.k, &self.v, &[0x00], provided);
        self.v = Self::hmac(&self.k, &self.v, &[], &[]);
        if !provided.is_empty() {
            // K = HMAC(K, V ‖ 0x01 ‖ provided); V = HMAC(K, V)
            self.k = Self::hmac(&self.k, &self.v, &[0x01], provided);
            self.v = Self::hmac(&self.k, &self.v, &[], &[]);
        }
    }

    /// Fill `out` with DRBG output (SP 800-90A 10.1.2.5, no additional input). Each
    /// call is one Generate: the state ratchets afterwards, so two `fill`s yield a
    /// different stream than one `fill` of the combined length (by design).
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            self.v = Self::hmac(&self.k, &self.v, &[], &[]);
            let n = (out.len() - i).min(SEEDLEN);
            out[i..i + n].copy_from_slice(&self.v[..n]);
            i += n;
        }
        self.update(&[]);
    }

    /// Mix fresh entropy into the state (SP 800-90A 10.1.2.4 reseed).
    pub fn reseed(&mut self, entropy: &[u8]) {
        self.update(entropy);
    }

    /// Wipe the internal state — for a secure reboot, destroy the live keystream
    /// before handing control to the bootloader. Unusable until re-seeded.
    pub fn scrub(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
    }
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream<const N: usize>(d: &mut HmacDrbg) -> [u8; N] {
        let mut b = [0u8; N];
        d.fill(&mut b);
        b
    }

    #[test]
    fn deterministic_for_a_seed() {
        let mut a = HmacDrbg::new(b"seed material xyz");
        let mut b = HmacDrbg::new(b"seed material xyz");
        assert_eq!(stream::<64>(&mut a), stream::<64>(&mut b));
    }

    #[test]
    fn seed_sensitive() {
        let mut a = HmacDrbg::new(b"seed-A");
        let mut b = HmacDrbg::new(b"seed-B");
        assert_ne!(stream::<64>(&mut a), stream::<64>(&mut b));
    }

    #[test]
    fn successive_draws_differ() {
        let mut d = HmacDrbg::new(b"seed");
        assert_ne!(stream::<32>(&mut d), stream::<32>(&mut d));
    }

    #[test]
    fn reseed_changes_stream() {
        let mut a = HmacDrbg::new(b"seed");
        let mut b = HmacDrbg::new(b"seed");
        b.reseed(b"fresh entropy");
        assert_ne!(stream::<32>(&mut a), stream::<32>(&mut b));
    }

    #[test]
    fn fills_arbitrary_lengths() {
        // A request spanning many 32-byte blocks must be fully written (no zeros tail).
        let mut d = HmacDrbg::new(b"seed");
        let mut big = [0u8; 200];
        d.fill(&mut big);
        assert!(big.iter().any(|&x| x != 0));
        assert!(big[160..].iter().any(|&x| x != 0)); // last block written
    }

    #[test]
    fn matches_sp800_90a_via_verified_hmac() {
        // KAT: pin the byte output to the SP 800-90A 10.1.2 formulas expressed
        // directly through the RFC-4231-verified `hmac_sha256`. This proves the DRBG
        // state machine matches the spec (HMAC itself is already KAT-tested), and is
        // immune to CAVP-vector transcription error.
        use crate::mac::hmac_sha256;
        let seed = b"DRBG known-answer seed";

        // Instantiate: K = 0x00.., V = 0x01.., then Update(seed) (provided non-empty
        // → both K/V pairs).
        let k0 = [0x00u8; 32];
        let v0 = [0x01u8; 32];
        let cat = |v: &[u8; 32], byte: u8| {
            let mut m = std::vec::Vec::with_capacity(33 + seed.len());
            m.extend_from_slice(v);
            m.push(byte);
            m.extend_from_slice(seed);
            m
        };
        let k1 = hmac_sha256(&k0, &cat(&v0, 0x00));
        let v1 = hmac_sha256(&k1, &v0);
        let k2 = hmac_sha256(&k1, &cat(&v1, 0x01));
        let v2 = hmac_sha256(&k2, &v1);

        // First Generate block (no additional input) = HMAC(K2, V2).
        let expected = hmac_sha256(&k2, &v2);

        let mut d = HmacDrbg::new(seed);
        let mut out = [0u8; 32];
        d.fill(&mut out);
        assert_eq!(out, expected);
    }
}
