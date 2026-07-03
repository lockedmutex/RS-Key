// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ML-DSA-44 (FIPS 204) signatures over `fips204`. All randomness is passed in
//! (the 32-byte keygen seed ξ, the 32-byte hedge value `rnd`), so operations are
//! deterministic under test. Only ML-DSA-44 (COSE -48) is enabled — smallest
//! signatures, lowest stack of the three parameter sets; the COSE / WebAuthn
//! profile signs the raw message with an empty FIPS 204 context (no pre-hash).

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

use crate::{Error, Result};

/// Keygen seed ξ length (the `KeyGen_internal` input).
pub const MLDSA44_SEED_LEN: usize = 32;
/// Serialized public-key length.
pub const MLDSA44_PK_LEN: usize = ml_dsa_44::PK_LEN; // 1312
/// Signature length.
pub const MLDSA44_SIG_LEN: usize = ml_dsa_44::SIG_LEN; // 2420

/// An ML-DSA-44 keypair expanded from a 32-byte seed.
///
/// Holds the precomputed (NTT-form) keys — ~17 KB of RAM — so derive, use and
/// drop it within one request. Both halves zeroize on drop (`fips204` derives
/// `ZeroizeOnDrop`; the public key needs no secrecy but wipes anyway).
pub struct MlDsa44 {
    pk: ml_dsa_44::PublicKey,
    sk: ml_dsa_44::PrivateKey,
}

impl MlDsa44 {
    /// Deterministically expand the keypair from ξ — same seed, same keys.
    pub fn from_seed(xi: &[u8; MLDSA44_SEED_LEN]) -> Self {
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(xi);
        Self { pk, sk }
    }

    /// The serialized public key (the COSE `pub` parameter).
    pub fn public_key(&self) -> [u8; MLDSA44_PK_LEN] {
        self.pk.clone().into_bytes()
    }

    /// Sign `msg` (empty context string) into `out`; returns the signature
    /// length, always [`MLDSA44_SIG_LEN`]. `rnd` is the FIPS 204 hedge
    /// randomness: fresh RNG bytes in firmware; a fixed value reproduces the
    /// same signature, and all-zero is the spec's deterministic variant.
    pub fn sign(&self, msg: &[u8], rnd: &[u8; 32], out: &mut [u8]) -> Result<usize> {
        if out.len() < MLDSA44_SIG_LEN {
            return Err(Error::BadLength);
        }
        let sig = self
            .sk
            .try_sign_with_seed(rnd, msg, &[])
            .map_err(|_| Error::Pqc)?;
        out[..MLDSA44_SIG_LEN].copy_from_slice(&sig);
        Ok(MLDSA44_SIG_LEN)
    }
}

/// Verify an ML-DSA-44 signature (empty context string) against a serialized
/// public key. Malformed keys verify as `false`.
pub fn mldsa44_verify(pk: &[u8; MLDSA44_PK_LEN], msg: &[u8], sig: &[u8; MLDSA44_SIG_LEN]) -> bool {
    let Ok(pk) = ml_dsa_44::PublicKey::try_from_bytes(*pk) else {
        return false;
    };
    pk.verify(msg, sig, &[])
}

#[cfg(test)]
#[path = "mldsa_tests.rs"]
mod tests;
