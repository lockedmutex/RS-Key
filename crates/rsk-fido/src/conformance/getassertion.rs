// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.2 `authenticatorGetAssertion` conformance assertions, driven
//! through the wire envelope (`process_cbor`). A discoverable credential is
//! created first (makeCredential rk=true), then asserted; both are
//! user-presence-only (no PIN), so `AlwaysConfirm` satisfies them.

use super::{Authr, assert_ok, field_at, int_map_keys};
use crate::consts::{
    ALG_ES256, CTAP_GET_ASSERTION, CTAP_GET_NEXT_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_AT, FLAG_UP,
};
use crate::error::CtapError;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::sha256;

const RP_ID: &str = "example.com";
const USER_ID: &[u8] = &[1, 2, 3, 4];

/// A discoverable (rk=true) ES256 makeCredential request over `RP_ID`.
fn mc_rk_request() -> Vec<u8> {
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
        e.str("id").unwrap().bytes(USER_ID).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion request over `rp` with no allowList (discoverable lookup).
fn ga_request(rp: &str) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().str(rp).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A fresh authenticator carrying one discoverable ES256 credential for `RP_ID`.
fn authr_with_credential() -> Authr {
    let mut a = Authr::fresh();
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_request());
    assert_ok(&r); // precondition, not the assertion under test
    a
}

#[test]
fn getassertion_response_envelope() {
    let mut a = authr_with_credential();
    let r = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));
    assert_ok(&r);
    // Single discoverable credential → {1: credential, 2: authData, 3: sig, 4: user}.
    assert_eq!(int_map_keys(&r.body), vec![1u32, 2, 3, 4]);
    let mut d = field_at(&r.body, 1).expect("credential (0x01) present");
    assert_eq!(
        d.map().unwrap().unwrap(),
        2,
        "credential descriptor is {{id, type}}"
    );
    assert_eq!(d.str().unwrap(), "id");
    assert!(!d.bytes().unwrap().is_empty(), "credential id present");
    assert_eq!(d.str().unwrap(), "type");
    assert_eq!(d.str().unwrap(), "public-key");
}

#[test]
fn getassertion_authdata_and_user() {
    let mut a = authr_with_credential();
    let r = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));

    let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4): no attested data.
    assert!(
        ad.len() >= 37,
        "assertion authData must carry rpIdHash + flags + counter"
    );
    assert_eq!(
        &ad[..32],
        &sha256(RP_ID.as_bytes())[..],
        "rpIdHash must be SHA-256(rpId)"
    );
    assert_eq!(ad[32] & FLAG_UP, FLAG_UP, "UP flag must be set");
    assert_eq!(
        ad[32] & FLAG_AT,
        0,
        "an assertion carries no attested credential data"
    );

    let mut s = field_at(&r.body, 3).expect("signature (0x03) present");
    assert!(
        !s.bytes().unwrap().is_empty(),
        "assertion signature must be present"
    );

    let mut u = field_at(&r.body, 4).expect("user (0x04) present");
    assert_eq!(
        u.map().unwrap().unwrap(),
        1,
        "user is id-only without UV (§6.2.2 privacy)"
    );
    assert_eq!(u.str().unwrap(), "id");
    assert_eq!(
        u.bytes().unwrap(),
        USER_ID,
        "user handle must round-trip the registered id"
    );
}

#[test]
fn getassertion_no_credentials() {
    // An assertion for an RP with no credentials → CTAP2_ERR_NO_CREDENTIALS (§6.2).
    let r = Authr::fresh().send(CTAP_GET_ASSERTION, &ga_request("absent.example"));
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
    assert!(r.body.is_empty(), "an error response carries no CBOR body");
}

/// A discoverable makeCredential over `RP_ID` with an explicit user id.
fn mc_rk_user(uid: &[u8]) -> Vec<u8> {
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
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The user id ("id") from an assertion's user field (key 4).
fn assertion_user_id(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 4).expect("user (0x04) present");
    assert!(d.map().unwrap().unwrap() >= 1);
    assert_eq!(d.str().unwrap(), "id");
    d.bytes().unwrap().to_vec()
}

#[test]
fn getnextassertion_walks_multiple_credentials() {
    let mut a = Authr::fresh();
    // Two discoverable credentials on the same RP (distinct user ids).
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_user(&[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_user(&[0xB2])));

    // The first getAssertion reports the count and returns one credential.
    let g1 = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));
    assert_ok(&g1);
    let mut d = field_at(&g1.body, 5).expect("numberOfCredentials (0x05) present");
    assert_eq!(d.u32().unwrap(), 2, "two credentials must be reported");
    let u1 = assertion_user_id(&g1.body);

    // getNextAssertion returns the other; a further call is exhausted.
    let g2 = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_ok(&g2);
    let u2 = assertion_user_id(&g2.body);
    assert_ne!(u1, u2, "the two assertions cover distinct credentials");
    // getNextAssertion carries no numberOfCredentials.
    assert!(
        field_at(&g2.body, 5).is_none(),
        "only the first assertion counts"
    );

    let g3 = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_eq!(
        g3.status,
        CtapError::NotAllowed.as_u8(),
        "walk is exhausted"
    );
}
