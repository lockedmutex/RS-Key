// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.1 `authenticatorMakeCredential` conformance assertions, driven
//! through the wire envelope (`process_cbor`): the attestation-object shape, the
//! authenticator-data layout, the packed self-attestation statement, and the
//! unsupported-algorithm rejection. A no-PIN request is user-presence-only, so
//! `AlwaysConfirm` satisfies it without arming a token.

use super::{Authr, Resp, assert_ok, field_at, int_map_keys};
use crate::consts::{
    AAGUID, ALG_ES256, CTAP_MAKE_CREDENTIAL, FLAG_AT, FLAG_UP, MAX_CRED_ID_LENGTH,
};
use crate::error::CtapError;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::sha256;

const RP_ID: &str = "example.com";

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
        "packed",
        "attestation format must be packed"
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
}

#[test]
fn makecred_unsupported_algorithm_rejected() {
    // A request whose only pubKeyCredParams entry is an unsupported COSE id (RS256,
    // -257) must fail with CTAP2_ERR_UNSUPPORTED_ALGORITHM (CTAP 2.1 §6.1).
    let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(-257));
    assert_eq!(r.status, CtapError::UnsupportedAlgorithm.as_u8());
    assert!(r.body.is_empty(), "an error response carries no CBOR body");
}
