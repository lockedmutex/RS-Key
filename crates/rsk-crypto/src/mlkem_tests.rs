// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SEED: [u8; MLKEM768_SEED_LEN] = [0x42; MLKEM768_SEED_LEN];

#[test]
fn keygen_is_deterministic_and_seed_sensitive() {
    let a = MlKem768Pair::from_seed(&SEED);
    let b = MlKem768Pair::from_seed(&SEED);
    assert_eq!(a.encapsulation_key(), b.encapsulation_key());

    let mut other = SEED;
    other[0] ^= 1;
    let c = MlKem768Pair::from_seed(&other);
    assert_ne!(a.encapsulation_key(), c.encapsulation_key());
}

#[test]
fn encaps_decaps_roundtrip() {
    let pair = MlKem768Pair::from_seed(&SEED);
    let (ct, ss_peer) = mlkem768_encapsulate(&pair.encapsulation_key(), &[7u8; 32]).unwrap();
    let ss_own = pair.decapsulate(&ct);
    assert_eq!(ss_peer, ss_own);
}

#[test]
fn fixed_m_reproducible() {
    let pair = MlKem768Pair::from_seed(&SEED);
    let ek = pair.encapsulation_key();
    let (ct1, ss1) = mlkem768_encapsulate(&ek, &[9u8; 32]).unwrap();
    let (ct2, ss2) = mlkem768_encapsulate(&ek, &[9u8; 32]).unwrap();
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
}

#[test]
fn corrupted_ciphertext_implicitly_rejects() {
    let pair = MlKem768Pair::from_seed(&SEED);
    let (mut ct, ss_peer) = mlkem768_encapsulate(&pair.encapsulation_key(), &[7u8; 32]).unwrap();
    ct[0] ^= 1;
    // No panic, no error — just a shared secret that matches nothing.
    assert_ne!(pair.decapsulate(&ct), ss_peer);
}

#[test]
fn malformed_ek_rejected() {
    // An all-0xFF key has non-reduced coefficients → InvalidKey.
    assert!(mlkem768_encapsulate(&[0xFF; MLKEM768_EK_LEN], &[0u8; 32]).is_err());
}

/// Emit a deterministic KAT (fixed `d‖z` seed + fixed `m`) so the host
/// toolchain's ML-KEM-768 (OpenSSL, via `cryptography`) can be cross-checked
/// against this RustCrypto implementation off-device: same seed must give the
/// same `ek`, and the host must decapsulate this `ct` back to this `ss`. Run:
/// `cargo test -p rsk-crypto --target <host> --ignored mlkem_interop_kat -- --nocapture`
#[test]
#[ignore = "prints an interop KAT for the host ML-KEM cross-check"]
fn mlkem_interop_kat() {
    fn hex(b: &[u8]) -> std::string::String {
        let mut s = std::string::String::new();
        for x in b {
            s.push_str(&std::format!("{x:02x}"));
        }
        s
    }
    let seed = [0x5Au8; MLKEM768_SEED_LEN];
    let m = [0x3Cu8; 32];
    let pair = MlKem768Pair::from_seed(&seed);
    let ek = pair.encapsulation_key();
    let (ct, ss) = mlkem768_encapsulate(&ek, &m).unwrap();
    std::println!("SEED {}", hex(&seed));
    std::println!("EK {}", hex(&ek));
    std::println!("CT {}", hex(&ct));
    std::println!("SS {}", hex(&ss));
}
