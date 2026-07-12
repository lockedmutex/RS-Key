// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.1 `authenticatorMakeCredential` conformance assertions, driven
//! through the wire envelope (`process_cbor`): the attestation-object shape, the
//! authenticator-data layout, the packed self-attestation statement, and the
//! unsupported-algorithm rejection. A no-PIN request is user-presence-only, so
//! `AlwaysConfirm` satisfies it without arming a token.

use super::{Authr, Resp, assert_ok, field_at, int_map_keys};
use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, CTAP_MAKE_CREDENTIAL, FLAG_AT, FLAG_UP, MAX_CRED_ID_LENGTH,
};
use crate::error::CtapError;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use rsk_crypto::sha256;

const RP_ID: &str = "example.com";

/// makeCredential ships `fmt:"none"` by default and `fmt:"packed"` under
/// `fido-conformance` (the packed self-attestation the conformance tool verifies).
const ATT_FMT: &str = if cfg!(feature = "fido-conformance") {
    "packed"
} else {
    "none"
};

/// A minimal single-algorithm makeCredential request over `RP_ID` (keys 1–4:
/// clientDataHash, rp, user, pubKeyCredParams).
fn mc_request(alg: i64) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(alg).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A makeCredential over `RP_ID` whose excludeList (key 5) names `cred_id`.
fn mc_request_exclude(cred_id: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn make_es256() -> Resp {
    Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(ALG_ES256))
}

#[test]
fn makecred_response_envelope() {
    let r = make_es256();
    assert_ok(&r);
    // Attestation object: exactly {1: fmt, 2: authData, 3: attStmt}, canonical.
    assert_eq!(int_map_keys(&r.body), vec![1u32, 2, 3]);
    let mut d = field_at(&r.body, 1).expect("fmt (0x01) present");
    assert_eq!(
        d.str().unwrap(),
        ATT_FMT,
        "attestation format must match the profile default"
    );
}

#[test]
fn makecred_authdata_structure() {
    let r = make_es256();
    let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // rpIdHash(32) | flags(1) | counter(4) | aaguid(16) | credLen(2) | credId | COSE key
    assert!(
        ad.len() >= 55,
        "authData too short for attested credential data"
    );
    assert_eq!(
        &ad[..32],
        &sha256(RP_ID.as_bytes())[..],
        "rpIdHash must be SHA-256(rpId)"
    );
    assert_eq!(
        ad[32] & (FLAG_AT | FLAG_UP),
        FLAG_AT | FLAG_UP,
        "AT (attested data) and UP (user present) flags must be set"
    );
    assert_eq!(
        &ad[37..53],
        &AAGUID[..],
        "attested aaguid must equal the model constant"
    );
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    assert!(cred_len > 0, "credential id must be non-empty");
    assert!(
        cred_len <= MAX_CRED_ID_LENGTH as usize,
        "credential id exceeds the advertised ceiling"
    );
    assert!(
        ad.len() >= 55 + cred_len,
        "authData truncated before the COSE public key"
    );
}

#[test]
fn makecred_attestation_statement() {
    let r = make_es256();
    let mut d = field_at(&r.body, 3).expect("attStmt (0x03) present");
    if cfg!(feature = "fido-conformance") {
        // Packed self-attestation is exactly {alg, sig} — no x5c chain.
        assert_eq!(
            d.map().unwrap().unwrap(),
            2,
            "self-attestation attStmt is {{alg, sig}}"
        );
        assert_eq!(d.str().unwrap(), "alg");
        assert_eq!(
            d.i64().unwrap(),
            ALG_ES256,
            "attStmt alg must match the credential key"
        );
        assert_eq!(d.str().unwrap(), "sig");
        assert!(
            !d.bytes().unwrap().is_empty(),
            "attStmt signature must be present"
        );
    } else {
        // Default ships fmt "none" (issue #26): no fragile self-attestation.
        let mut f = field_at(&r.body, 1).expect("fmt (0x01) present");
        assert_eq!(f.str().unwrap(), "none");
        assert_eq!(d.map().unwrap().unwrap(), 0, "default attStmt is empty");
    }
}

/// Reproduce GitHub issue #26: OpenSSH 10.0p2 (via libfido2) runs
/// `fido_cred_verify_self` on the packed EdDSA self-attestation and rejects it with
/// FIDO_ERR_INVALID_SIG, while ES256 self-attestation from the same device passes.
/// libfido2 reconstructs the credential public key from the emitted COSE bytes and
/// verifies the raw-64-byte Ed25519 signature over `authData ‖ clientDataHash`
/// (PureEdDSA, no pre-hash). Do exactly that here — reconstructing the key from the
/// wire bytes, NOT from the signing key object — so a sign/COSE mismatch or a
/// wrong-message bug is caught the way an external verifier catches it.
#[test]
fn makecred_ed25519_self_attestation_verifies_independently() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(ALG_EDDSA));
    assert_ok(&r);

    // Default ships fmt "none" precisely so no EdDSA self-attestation is emitted
    // (this issue-#26 verification only applies to the packed conformance profile).
    if !cfg!(feature = "fido-conformance") {
        let mut f = field_at(&r.body, 1).expect("fmt (0x01) present");
        assert_eq!(f.str().unwrap(), "none");
        let mut s = field_at(&r.body, 3).expect("attStmt (0x03) present");
        assert_eq!(s.map().unwrap().unwrap(), 0, "default attStmt is empty");
        return;
    }

    let ad = {
        let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
        d.bytes().unwrap().to_vec()
    };
    // attestedCredentialData: rpIdHash(32)|flags(1)|count(4)|aaguid(16)|credLen(2)|credId|COSEkey
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cose = &ad[55 + cred_len..];
    // OKP credentialPublicKey {1:1, 3:-8, -1:6, -2:<32-byte x>} — pull key -2 the way
    // libfido2's cbor_decode_eddsa_pubkey does.
    let mut x = [0u8; 32];
    {
        let mut d = Decoder::new(cose);
        let n = d.map().unwrap().unwrap();
        for _ in 0..n {
            let key = d.i8().unwrap();
            if key == -2 {
                x.copy_from_slice(d.bytes().unwrap());
            } else {
                d.skip().unwrap();
            }
        }
    }
    let sig_bytes = {
        let mut d = field_at(&r.body, 3).expect("attStmt (0x03) present");
        let m = d.map().unwrap().unwrap();
        let mut sig = Vec::new();
        for _ in 0..m {
            let key = d.str().unwrap().to_string();
            if key == "sig" {
                sig = d.bytes().unwrap().to_vec();
            } else {
                d.skip().unwrap();
            }
        }
        sig
    };

    // Packed self-attestation signs authData ‖ clientDataHash; mc_request uses 0xCD*32.
    let mut signed = ad.clone();
    signed.extend_from_slice(&[0xCD; 32]);

    let vk = VerifyingKey::from_bytes(&x).expect("emitted COSE -2 is a valid Ed25519 point");
    let sig = Signature::from_slice(&sig_bytes).expect("attStmt sig is 64 bytes");
    vk.verify(&signed, &sig).expect(
        "RS-Key Ed25519 self-attestation must verify under the emitted COSE key over \
         authData‖clientDataHash — exactly what OpenSSH 10.0p2 / libfido2 fido_cred_verify_self does",
    );
    // Also strict: rejects a non-canonical A/R or a small-order component — so a
    // stricter external verifier (LibreSSL) cannot reject what this accepts. If both
    // pass, the on-wire signature is fully spec-clean and any Windows failure is a
    // transport/webauthn re-serialization issue, not our bytes (GitHub issue #26).
    vk.verify_strict(&signed, &sig)
        .expect("RS-Key Ed25519 self-attestation must also pass strict verification");
}

#[test]
fn makecred_unsupported_algorithm_rejected() {
    // A request whose only pubKeyCredParams entry is an unsupported COSE id (RS256,
    // -257) must fail with CTAP2_ERR_UNSUPPORTED_ALGORITHM (CTAP 2.1 §6.1).
    let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(-257));
    assert_eq!(r.status, CtapError::UnsupportedAlgorithm.as_u8());
    assert!(r.body.is_empty(), "an error response carries no CBOR body");
}

#[test]
fn makecred_exclude_list_rejects_existing() {
    let mut a = Authr::fresh();
    let r1 = a.send(CTAP_MAKE_CREDENTIAL, &mc_request(ALG_ES256));
    assert_ok(&r1);
    let cred_id = {
        let mut d = field_at(&r1.body, 2).expect("authData (0x02) present");
        let ad = d.bytes().unwrap();
        let cl = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        ad[55..55 + cl].to_vec()
    };
    // Re-registering with that credential in excludeList → CREDENTIAL_EXCLUDED (§6.1).
    let r2 = a.send(CTAP_MAKE_CREDENTIAL, &mc_request_exclude(&cred_id));
    assert_eq!(r2.status, CtapError::CredentialExcluded.as_u8());
}

#[test]
fn makecred_attestation_signature_verifies() {
    let r = make_es256();
    // Default ships fmt "none" (empty attStmt); the packed self-attestation
    // signature only exists in the conformance profile.
    if !cfg!(feature = "fido-conformance") {
        let mut f = field_at(&r.body, 1).expect("fmt (0x01) present");
        assert_eq!(f.str().unwrap(), "none");
        let mut s = field_at(&r.body, 3).expect("attStmt (0x03) present");
        assert_eq!(s.map().unwrap().unwrap(), 0, "default attStmt is empty");
        return;
    }
    let ad = {
        let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
        d.bytes().unwrap().to_vec()
    };
    let (x, y) = super::credential_pubkey(&ad);
    let sig = {
        let mut d = field_at(&r.body, 3).expect("attStmt (0x03) present");
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.str().unwrap(), "alg");
        d.i64().unwrap();
        assert_eq!(d.str().unwrap(), "sig");
        d.bytes().unwrap().to_vec()
    };
    // Packed self-attestation signs authData ‖ clientDataHash with the credential key.
    let mut signed = ad;
    signed.extend_from_slice(&[0xCD; 32]);
    super::verify_p256(&x, &y, &signed, &sig);
}
