// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ML-KEM-768 (FIPS 203) key encapsulation over `ml-kem` — scaffolding for a
//! future PQC PIN/UV-auth protocol; nothing in the applet layer calls it yet.
//! As in [`crate::mldsa`], all randomness is passed in (the 64-byte keygen seed
//! `d‖z`, the 32-byte encapsulation randomness `m`) for deterministic tests.

use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};

use crate::{Error, Result};

/// Keygen seed length (`d ‖ z`, 32 + 32).
pub const MLKEM768_SEED_LEN: usize = 64;
/// Serialized encapsulation (public) key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// Ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Shared-secret length.
pub const MLKEM768_SS_LEN: usize = 32;

/// An ML-KEM-768 decapsulation keypair expanded from a 64-byte seed.
///
/// The decapsulation key zeroizes on drop (`ml-kem`'s `zeroize` feature).
pub struct MlKem768Pair {
    dk: DecapsulationKey<MlKem768>,
}

impl MlKem768Pair {
    /// Deterministically expand the keypair from `d ‖ z` — same seed, same keys.
    pub fn from_seed(seed: &[u8; MLKEM768_SEED_LEN]) -> Self {
        Self {
            dk: DecapsulationKey::from_seed(ml_kem::Seed::from(*seed)),
        }
    }

    /// The serialized encapsulation key (what the peer encapsulates to).
    pub fn encapsulation_key(&self) -> [u8; MLKEM768_EK_LEN] {
        self.dk.encapsulation_key().to_bytes().into()
    }

    /// Recover the shared secret from a peer's ciphertext. ML-KEM never fails
    /// on a well-formed-length ciphertext — a corrupted one yields the implicit
    ///-rejection secret, which simply won't match the peer's.
    pub fn decapsulate(&self, ct: &[u8; MLKEM768_CT_LEN]) -> [u8; MLKEM768_SS_LEN] {
        self.dk
            .decapsulate_slice(ct)
            .expect("fixed-length ciphertext")
            .into()
    }
}

/// Encapsulate to a peer's serialized key: returns `(ciphertext, shared_secret)`.
/// `m` is the FIPS 203 encapsulation randomness — fresh RNG bytes in firmware, a
/// fixed value in tests. Fails on a malformed (non-reduced) encapsulation key.
pub fn mlkem768_encapsulate(
    ek: &[u8; MLKEM768_EK_LEN],
    m: &[u8; 32],
) -> Result<([u8; MLKEM768_CT_LEN], [u8; MLKEM768_SS_LEN])> {
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::from(*ek);
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| Error::Pqc)?;
    let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(*m));
    Ok((ct.into(), ss.into()))
}

#[cfg(test)]
#[path = "mlkem_tests.rs"]
mod tests;
