// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

const SEED: [u8; 32] = [0x42; 32];
const IV: [u8; 12] = [0x11; 12];

fn input() -> CredInput<'static> {
    CredInput {
        rp_id: "example.com",
        user_id: &[0xDE, 0xAD, 0xBE, 0xEF],
        user_name: "alice",
        user_display_name: "Alice Smith",
        use_sign_count: true,
        rk: false,
        created_ms: 12345,
        alg: ALG_ES256,
        curve: CURVE_P256 as i64,
        ext: CredExt::default(),
    }
}

#[test]
fn create_load_roundtrip() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    assert_eq!(&out[..4], CRED_PROTO);

    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.rp_id, "example.com");
    assert_eq!(c.user_id, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(c.user_name, "alice");
    assert_eq!(c.user_display_name, "Alice Smith");
    assert!(c.use_sign_count);
    assert_eq!(c.alg, ALG_ES256);
    assert_eq!(c.curve, CURVE_P256 as i64);
}

#[test]
fn non_p256_alg_curve_roundtrip() {
    use crate::consts::{ALG_ES512, CURVE_P521};
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut inp = input();
    inp.alg = ALG_ES512;
    inp.curve = CURVE_P521 as i64;
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.alg, ALG_ES512);
    assert_eq!(c.curve, CURVE_P521 as i64);
}

#[test]
fn extensions_roundtrip_through_box() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut inp = input();
    inp.rk = true;
    inp.ext = CredExt {
        cred_protect: 2,
        cred_blob: &[0xBE, 0xEF, 0x42],
        hmac_secret: true,
        large_blob_key: true,
        third_party_payment: true,
    };
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();

    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.ext.cred_protect, 2);
    assert_eq!(c.ext.cred_blob, &[0xBE, 0xEF, 0x42]);
    assert!(c.ext.hmac_secret);
    assert!(c.ext.large_blob_key);
    assert!(c.ext.third_party_payment);
    assert!(c.rk);
}

#[test]
fn oversized_cred_blob_is_dropped() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let big = [0u8; MAX_CREDBLOB_LENGTH + 1];
    let mut inp = input();
    inp.ext.cred_blob = &big;
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert!(
        c.ext.cred_blob.is_empty(),
        "oversized credBlob is not sealed"
    );
}

#[test]
fn wrong_rp_hash_fails_to_decrypt() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    let other = sha256(b"evil.com");
    let mut scratch = [0u8; 512];
    assert!(credential_load(&SEED, &out[..len], &other, &mut scratch).is_none());
}

#[test]
fn tampered_box_fails() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    out[HEAD_LEN] ^= 0x01; // flip a ciphertext byte
    let mut scratch = [0u8; 512];
    assert!(credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).is_none());
}

#[test]
fn hmac_key_deterministic_uv_halves_differ() {
    let box1 = [0x55u8; 80];
    let mut box2 = box1;
    box2[40] ^= 0xFF;
    let k1 = derive_hmac_key(&SEED, &box1);
    assert_eq!(k1, derive_hmac_key(&SEED, &box1), "deterministic");
    // The CredRandomWithUV ([32..64]) and CredRandomWithoutUV ([0..32]) differ.
    assert_ne!(&k1[..32], &k1[32..]);
    // A different box yields a different cred_random.
    assert_ne!(k1, derive_hmac_key(&SEED, &box2));
    // The proto prefix (first 4 bytes) is folded in, so it is path-sensitive.
    assert_ne!(
        derive_hmac_key(&SEED, &box1),
        derive_hmac_key(&[0x43; 32], &box1)
    );
}

#[test]
fn large_blob_key_deterministic_and_box_sensitive() {
    let box1 = [0x55u8; 80];
    let mut box2 = box1;
    box2[10] ^= 0xFF;
    let k1 = derive_large_blob_key(&SEED, &box1);
    assert_eq!(k1, derive_large_blob_key(&SEED, &box1));
    assert_ne!(k1, derive_large_blob_key(&SEED, &box2));
    assert_ne!(k1, derive_hmac_key(&SEED, &box1)[..32]);
}

#[test]
fn resident_id_format_and_determinism() {
    let d = dev();
    let cred_id = [0x55u8; 80];
    let r1 = derive_resident(&cred_id, &d);
    let r2 = derive_resident(&cred_id, &d);
    assert_eq!(r1, r2);
    assert_eq!(r1.len(), CRED_RESIDENT_LEN);
    assert_eq!(&r1[4..8], CRED_PROTO_RESIDENT);
    // New resident ids are stamped v2 (byte 8), in the header before the chain.
    assert_eq!(r1[RESIDENT_VERSION_IDX], RESIDENT_VERSION_V2);
    assert_eq!(r1[9], 0);
    assert!(is_resident(&r1));
}

// The v2 marker sits OUTSIDE the [10..42] hash chain, so flipping it does not
// perturb the id's entropy: an id built with a v1 marker (0) shares the [10..42]
// tail with the v2 id for the same box. This is what makes the flip forward-safe
// for already-stored v1 ids.
#[test]
fn resident_version_marker_is_outside_the_hash_chain() {
    let d = dev();
    let cred_id = [0x55u8; 80];
    let v2 = derive_resident(&cred_id, &d);
    let mut v1 = v2;
    v1[RESIDENT_VERSION_IDX] = 0;
    assert_eq!(
        v1[CRED_RESIDENT_HEADER_LEN..],
        v2[CRED_RESIDENT_HEADER_LEN..],
        "marker byte must not change the [10..42] chain"
    );
}

// The reseal-stability fix at the derivation level: a v2 resident id is the key
// input regardless of the (resealed) box, so the signing / hmac-secret /
// largeBlobKey derivations are identical across an updateUserInformation box
// swap; a v1 id (older firmware) still follows the box; a non-resident box has no
// id. Also pins per-credential key uniqueness.
#[test]
fn resident_key_input_v2_is_reseal_stable_v1_follows_box() {
    use crate::keyderiv::fido_load_key;
    let d = dev();
    // Two DIFFERENT boxes, as an updateUserInformation reseal (fresh IV) yields.
    let box1 = [0x55u8; 80];
    let box2 = [0xAAu8; 80];

    let rid = derive_resident(&box1, &d);
    assert_eq!(rid[RESIDENT_VERSION_IDX], RESIDENT_VERSION_V2);

    // v2: the key input is the STABLE id, independent of the box.
    assert_eq!(resident_key_input(&box1, Some(&rid[..])), &rid[..]);
    assert_eq!(resident_key_input(&box2, Some(&rid[..])), &rid[..]);
    let (ki1, ki2) = (
        resident_key_input(&box1, Some(&rid[..])),
        resident_key_input(&box2, Some(&rid[..])),
    );
    assert_eq!(
        fido_load_key(&SEED, ki1),
        fido_load_key(&SEED, ki2),
        "signing key stable across reseal"
    );
    assert_eq!(
        derive_hmac_key(&SEED, ki1),
        derive_hmac_key(&SEED, ki2),
        "hmac-secret stable across reseal"
    );
    assert_eq!(
        derive_large_blob_key(&SEED, ki1),
        derive_large_blob_key(&SEED, ki2),
        "largeBlobKey stable across reseal"
    );

    // v1 (marker 0): the key input is the box, so the RP's box-derived pubkey
    // keeps verifying — no rotation, no regression for older credentials.
    let mut rid_v1 = rid;
    rid_v1[RESIDENT_VERSION_IDX] = 0;
    assert_eq!(resident_key_input(&box1, Some(&rid_v1[..])), &box1[..]);
    assert_eq!(resident_key_input(&box2, Some(&rid_v1[..])), &box2[..]);

    // Non-resident credential: no resident id → the box.
    assert_eq!(resident_key_input(&box1, None), &box1[..]);

    // Uniqueness: two distinct credentials get distinct v2 ids → distinct keys.
    let rid_other = derive_resident(&box2, &d);
    assert_ne!(
        rid[CRED_RESIDENT_HEADER_LEN..],
        rid_other[CRED_RESIDENT_HEADER_LEN..]
    );
    assert_ne!(
        fido_load_key(&SEED, &rid[..]),
        fido_load_key(&SEED, &rid_other[..])
    );
}

#[test]
fn store_then_dedup_and_rp_count() {
    let d = dev();
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new(), &[]);
    let rp_hash = sha256(b"example.com");

    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    credential_store(
        &SEED,
        &d,
        &mut fs,
        &out[..len],
        &rp_hash,
        "example.com",
        &[0xDE, 0xAD, 0xBE, 0xEF],
    )
    .unwrap();

    // Stored in the first EF_CRED slot, record = rp_hash ‖ resident ‖ box.
    assert!(fs.has_data(EF_CRED));
    let mut rec = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut rec).unwrap();
    assert_eq!(&rec[..32], &rp_hash[..]);
    assert_eq!(n, RECORD_PREFIX + len);
    // EF_RP created with count 1.
    let mut rp = [0u8; 256];
    let m = fs.read(EF_RP, &mut rp).unwrap();
    assert_eq!(rp[0], 1);
    assert_eq!(&rp[1..33], &rp_hash[..]);
    // The rpId domain tail is boxed under the seed: not cleartext on flash,
    // but it un-boxes back to the original domain.
    assert_ne!(&rp[RP_PREFIX..m], b"example.com");
    let mut scratch = [0u8; 256];
    let (domain, was_boxed) =
        unseal_rp_id(&SEED, &rp_hash, &rp[RP_PREFIX..m], &mut scratch).unwrap();
    assert_eq!(domain, "example.com");
    assert!(was_boxed);

    // Re-registering the SAME user reuses the slot (no new RP record / count bump).
    let iv2 = [0x22u8; 12];
    let len2 = credential_create(&SEED, &d, &input(), &rp_hash, &iv2, &mut out).unwrap();
    credential_store(
        &SEED,
        &d,
        &mut fs,
        &out[..len2],
        &rp_hash,
        "example.com",
        &[0xDE, 0xAD, 0xBE, 0xEF],
    )
    .unwrap();
    assert!(!fs.has_data(EF_CRED + 1)); // still one credential slot used
    let m2 = fs.read(EF_RP, &mut rp).unwrap();
    assert_eq!(rp[0], 1, "same user must not bump the rp count");
    assert_eq!(m2, m);
}

#[test]
fn nick_seal_roundtrip_and_binds_to_rp() {
    let rp_hash = sha256(b"github.com");
    let mut out = [0u8; NICK_BOX_MAX];
    let len = seal_nick(&SEED, &rp_hash, "Work GitHub", &mut out).unwrap();
    // Not cleartext on flash.
    assert!(!out[..len].windows(11).any(|w| w == b"Work GitHub"));

    let mut plain = [0u8; RP_NICK_MAX_LEN];
    let got = unseal_nick(&SEED, &rp_hash, &out[..len], &mut plain).unwrap();
    assert_eq!(got, "Work GitHub");

    // The rpIdHash is the AEAD's AAD, so the box won't open under another RP — this
    // is the slot-reuse guard a stale leftover hits.
    let other = sha256(b"evil.com");
    let mut p2 = [0u8; RP_NICK_MAX_LEN];
    assert!(unseal_nick(&SEED, &other, &out[..len], &mut p2).is_none());
}

#[test]
fn nick_rename_draws_a_fresh_iv() {
    // The synthetic IV is plaintext-bound, so renaming to a different value uses a
    // different IV — never reusing a nonce against a changed plaintext.
    let rp_hash = sha256(b"github.com");
    let mut a = [0u8; NICK_BOX_MAX];
    let mut b = [0u8; NICK_BOX_MAX];
    seal_nick(&SEED, &rp_hash, "first", &mut a).unwrap();
    seal_nick(&SEED, &rp_hash, "secnd", &mut b).unwrap();
    assert_ne!(
        a[..IV_LEN],
        b[..IV_LEN],
        "different plaintext → different IV"
    );
}

#[test]
fn nick_too_long_is_rejected_by_seal() {
    let rp_hash = sha256(b"github.com");
    let mut out = [0u8; NICK_BOX_MAX + 64];
    let long = [b'a'; RP_NICK_MAX_LEN + 1];
    let long = core::str::from_utf8(&long).unwrap();
    assert!(seal_nick(&SEED, &rp_hash, long, &mut out).is_err());
}

// `truncate_utf8` must never panic and must return a char-boundary byte-prefix
// no longer than `max`. The function's domain is small, so prove it by
// EXHAUSTION over a stress alphabet spanning every UTF-8 length class (1..4
// bytes), for every string of up to 3 such chars and every cap 0..=input len.
#[test]
fn truncate_utf8_is_exhaustively_safe() {
    // ASCII 'a' (1B), 'é' (2B), '€' (3B), '𝔸' (4B) — one representative per class.
    let alphabet = ['a', 'é', '€', '𝔸'];
    let mut corpus = std::vec::Vec::new();
    corpus.push(std::string::String::new());
    for &a in &alphabet {
        corpus.push(a.to_string());
        for &b in &alphabet {
            corpus.push(std::format!("{a}{b}"));
            for &c in &alphabet {
                corpus.push(std::format!("{a}{b}{c}"));
            }
        }
    }
    for s in &corpus {
        for max in 0..=s.len() + 1 {
            let t = truncate_utf8(s, max);
            assert!(t.len() <= max, "{s:?} @ {max}: len {} > cap", t.len());
            assert!(
                s.as_bytes().starts_with(t.as_bytes()),
                "{s:?} @ {max}: not a prefix"
            );
            // The cut is a real char boundary: `t` re-parses as the char prefix
            // that fits, and dropping one more char would exceed `max`.
            assert!(s.starts_with(t));
            if t.len() < s.len() {
                let next = s[..].chars().nth(t.chars().count()).unwrap();
                assert!(
                    t.len() + next.len_utf8() > max,
                    "{s:?} @ {max}: truncated too early"
                );
            }
        }
    }
}
