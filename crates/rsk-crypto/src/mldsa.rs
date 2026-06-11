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
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42; 32];
    const MSG: &[u8] = b"authData||clientDataHash";

    #[test]
    fn keygen_is_deterministic_and_seed_sensitive() {
        let a = MlDsa44::from_seed(&SEED);
        let b = MlDsa44::from_seed(&SEED);
        assert_eq!(a.public_key(), b.public_key());

        let mut other = SEED;
        other[0] ^= 1;
        assert_ne!(a.public_key(), MlDsa44::from_seed(&other).public_key());
    }

    // Regression pin: the public key for a fixed seed must not silently change
    // across fips204 upgrades (it is a deterministic function of ξ). Pinned as
    // a SHA-256 to keep the test readable.
    #[test]
    fn keygen_pk_regression_pin() {
        let pk = MlDsa44::from_seed(&SEED).public_key();
        let digest = crate::sha256(&pk);
        assert_eq!(
            digest,
            [
                0x19, 0x50, 0x6c, 0x63, 0xf5, 0x04, 0xc1, 0x75, 0x01, 0x3c, 0xf1, 0xb4, 0x59, 0x39,
                0x7b, 0xbb, 0xc2, 0xce, 0x6a, 0x3f, 0xd8, 0x41, 0xba, 0xb6, 0x8b, 0x38, 0x98, 0xf6,
                0xf2, 0xfd, 0xdc, 0x2f
            ],
            "pinned ML-DSA-44 public key changed — fips204 behavior shift?"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = MlDsa44::from_seed(&SEED);
        let mut sig = [0u8; MLDSA44_SIG_LEN];
        let n = key.sign(MSG, &[7u8; 32], &mut sig).unwrap();
        assert_eq!(n, MLDSA44_SIG_LEN);
        assert!(mldsa44_verify(&key.public_key(), MSG, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message_key_and_tamper() {
        let key = MlDsa44::from_seed(&SEED);
        let mut sig = [0u8; MLDSA44_SIG_LEN];
        key.sign(MSG, &[7u8; 32], &mut sig).unwrap();
        let pk = key.public_key();

        assert!(!mldsa44_verify(&pk, b"other message", &sig));

        let mut other_seed = SEED;
        other_seed[31] ^= 1;
        let other_pk = MlDsa44::from_seed(&other_seed).public_key();
        assert!(!mldsa44_verify(&other_pk, MSG, &sig));

        let mut bad = sig;
        bad[100] ^= 1;
        assert!(!mldsa44_verify(&pk, MSG, &bad));
    }

    #[test]
    fn same_rnd_same_signature_distinct_rnd_distinct() {
        let key = MlDsa44::from_seed(&SEED);
        let mut a = [0u8; MLDSA44_SIG_LEN];
        let mut b = [0u8; MLDSA44_SIG_LEN];
        key.sign(MSG, &[1u8; 32], &mut a).unwrap();
        key.sign(MSG, &[1u8; 32], &mut b).unwrap();
        assert_eq!(a, b, "fixed hedge rnd → reproducible signature");

        key.sign(MSG, &[2u8; 32], &mut b).unwrap();
        assert_ne!(a, b, "different hedge rnd → different signature");
        assert!(mldsa44_verify(&key.public_key(), MSG, &b));
    }

    #[test]
    fn sign_buffer_too_small() {
        let key = MlDsa44::from_seed(&SEED);
        let mut tiny = [0u8; 64];
        assert_eq!(key.sign(MSG, &[0u8; 32], &mut tiny), Err(Error::BadLength));
    }

    // Does keygen → sign → verify fit in a `STACK_KIB`-KiB stack? One size per
    // process — a thread stack overflow aborts the whole process on macOS, so
    // the caller loops over sizes from the shell and reads pass/abort:
    //   for k in 24 32 48 64; STACK_KIB=$k cargo test --release -p rsk-crypto \
    //     --target <host> -- --ignored stack_floor_probe; end
    // The RP2350 worker must keep at least the floor (plus our frames) free.
    #[test]
    #[ignore]
    fn stack_floor_probe() {
        let kib: usize = std::env::var("STACK_KIB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128);
        std::thread::Builder::new()
            .stack_size(kib * 1024)
            .spawn(|| {
                let key = MlDsa44::from_seed(&SEED);
                let mut sig = [0u8; MLDSA44_SIG_LEN];
                key.sign(MSG, &[7u8; 32], &mut sig).unwrap();
                assert!(mldsa44_verify(&key.public_key(), MSG, &sig));
            })
            .unwrap()
            .join()
            .unwrap();
        std::eprintln!("ML-DSA-44 keygen+sign+verify fits in {kib} KiB stack");
    }
}
