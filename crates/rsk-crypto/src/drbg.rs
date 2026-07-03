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
#[path = "drbg_tests.rs"]
mod tests;
