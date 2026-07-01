// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsa::RsaPublicKey;

// A fixed RSA-2048 key (openssl genrsa), primes sans the DER sign byte.
const P_HEX: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
const Q_HEX: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";
const N_HEX: &str = "ba8654a65ddb75e8cf593ee635345ac0a64d43bd328849683979bf25928cf46489051bf991cdb56a464d83069048c651b049d0181bc08a1e34cb9130a86c67a6283e79100d6c32dce9ddf852ba94cbe1d2b3c89358096cd48a8c90fcb6089819258e44d92d25b0cc4ab2a9224e4489e2eec8abc13a19f520adec2710f8f8ac21b4cebe99a958fe38fe43b50c97375076c2ff5e98980af0c5a719a417ba8f657328ea95f50936d6f459af093bc864b222f89302e9e9972ff491608f7ef93b509c8a65bad0e51bcbf0d2e43d2c9956d762af1d26a01b776471e39a2338babb4f8a30199cf26dd8dbdccf59ef77912b1b700e59c3a7e327ffbb58b6584b827ed449";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn test_key() -> RsaPrivateKey {
    rsa_from_pqe(&[0x01, 0x00, 0x01], &hex(P_HEX), &hex(Q_HEX)).unwrap()
}

#[test]
fn import_recovers_modulus() {
    // from_p_q must reconstruct N = P·Q (the make_rsa_response modulus).
    let key = test_key();
    let mut out = [0u8; MAX_RSA_PUBDO];
    let n = make_rsa_response(&key, &mut out);
    assert_eq!(&out[..3], &[0x7f, 0x49, 0x82]); // outer DO
    assert_eq!(&out[5..7], &[0x81, 0x82]); // modulus tag + 2-byte length
    assert_eq!(u16::from_be_bytes([out[7], out[8]]), 256); // RSA-2048 modulus
    assert_eq!(&out[9..9 + 256], hex(N_HEX).as_slice());
    // Exponent 0x010001 follows the modulus.
    assert_eq!(out[9 + 256], 0x82);
    assert_eq!(out[9 + 256 + 1], 3);
    assert_eq!(&out[9 + 256 + 2..9 + 256 + 5], &[0x01, 0x00, 0x01]);
    assert_eq!(n, 270);
}

#[test]
fn sign_digestinfo_verifies() {
    let key = test_key();
    // A SHA-256 DigestInfo (what gpg sends for an RSA signature).
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut sig = [0u8; MAX_RSA_BYTES];
    let n = rsa_sign(&key, &di, &mut SeqRng(1), &mut sig).unwrap();
    assert_eq!(n, 256);
    RsaPublicKey::from(&key)
        .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..n])
        .unwrap();
}

#[test]
fn sign_bare_hash_infers_alg() {
    // A bare 32-byte hash is treated as SHA-256 (length inference), so it must
    // verify against the same DigestInfo signature.
    let key = test_key();
    let hash = [0x37u8; 32];
    let mut sig = [0u8; MAX_RSA_BYTES];
    let n = rsa_sign(&key, &hash, &mut SeqRng(2), &mut sig).unwrap();
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&hash);
    RsaPublicKey::from(&key)
        .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..n])
        .unwrap();
}

#[test]
fn decipher_roundtrip() {
    let key = test_key();
    let msg = b"a-32-byte-openpgp-session-key!!!";
    let ct = RsaPublicKey::from(&key)
        .encrypt(&mut RngAdapter(&mut SeqRng(7)), Pkcs1v15Encrypt, msg)
        .unwrap();
    // The DECIPHER command prepends the OpenPGP padding-indicator byte.
    let mut data = vec![0x00u8];
    data.extend_from_slice(&ct);
    let mut out = [0u8; MAX_RSA_BYTES];
    let n = rsa_decipher(&key, &mut SeqRng(8), &data, &mut out).unwrap();
    assert_eq!(&out[..n], msg);
}

#[test]
fn keygen_pool_assembles_in_either_order() {
    // The dual-core search feeds primes through `offer` in whatever order the
    // cores find them — both orders must assemble the same modulus.
    let p = BigUint::from_bytes_be(&hex(P_HEX));
    let q = BigUint::from_bytes_be(&hex(Q_HEX));
    for (first, second) in [(p.clone(), q.clone()), (q, p)] {
        let mut kg = RsaKeygen::new(2048);
        assert!(kg.usable());
        assert_eq!(kg.half_bytes(), 128);
        assert!(matches!(kg.offer(first), RsaStep::More));
        match kg.offer(second) {
            RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
            _ => panic!("two distinct primes must complete the key"),
        }
    }
}

#[test]
fn keygen_pool_le_transport() {
    // The inter-core transport: primes as little-endian bytes, scrubbed on use.
    let (mut p_le, mut q_le) = (hex(P_HEX), hex(Q_HEX));
    p_le.reverse();
    q_le.reverse();
    let mut kg = RsaKeygen::new(2048);
    assert!(matches!(kg.offer_le(&mut p_le), RsaStep::More));
    assert!(
        p_le.iter().all(|&b| b == 0),
        "transport buffer not scrubbed"
    );
    match kg.offer_le(&mut q_le) {
        RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
        _ => panic!("two distinct primes must complete the key"),
    }
}

#[test]
fn try_candidate_le_finds_exact_half() {
    // Smallest asm-eligible half (32 bytes = RSA-512) so the host search is
    // quick; a find must fill the half exactly, odd and with the top bits set.
    let mut rng = SeqRng(42);
    let mut sieve = IncrementalSieve::new();
    let mut out = [0u8; 32];
    let mut tries = 0;
    let len = loop {
        tries += 1;
        assert!(tries < 200_000, "prime search did not converge");
        if let Some(n) = RsaKeygen::try_candidate_le(&mut sieve, &mut rng, 32, &mut out) {
            break n;
        }
    };
    assert_eq!(len, 32);
    assert_eq!(out[31] & 0xC0, 0xC0);
    assert_eq!(out[0] & 1, 1);
}

#[test]
fn keygen_bpsw_split_matches_library() {
    // try_candidate's accept = strong-MR(asm) + strong-Lucas. Any prime it
    // produces must satisfy the library's own one-call Baillie-PSW — the
    // split changed backends, not the test.
    use num_bigint_dig::prime::probably_prime;
    let mut rng = SeqRng(7);
    let mut sieve = IncrementalSieve::new();
    let (mut found, mut tries) = (0, 0);
    while found < 2 {
        tries += 1;
        assert!(tries < 200_000, "prime search did not converge");
        if let Some(p) = RsaKeygen::try_candidate(&mut sieve, &mut rng, 32) {
            assert!(
                probably_prime(&p, 0),
                "split BPSW accepted what the library rejects"
            );
            found += 1;
        }
    }
}

#[test]
fn keygen_pool_rejects_duplicate_prime() {
    let p = BigUint::from_bytes_be(&hex(P_HEX));
    let mut kg = RsaKeygen::new(2048);
    assert!(matches!(kg.offer(p.clone()), RsaStep::More));
    // The same prime again must not assemble a broken p == q key…
    assert!(matches!(kg.offer(p), RsaStep::More));
    // …and the held prime survives: a distinct second one completes the key.
    let q = BigUint::from_bytes_be(&hex(Q_HEX));
    assert!(matches!(kg.offer(q), RsaStep::Done(_)));
}
