// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 extension conformance (credBlob §12.5, hmac-secret §12.5), driven
//! through the wire envelope (`process_cbor`): makeCredential echoes the
//! extension outputs in authData, and getAssertion returns the stored credBlob.

use super::{Authr, assert_ok, field_at};
use crate::consts::{ALG_ES256, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_ED};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

const RP_ID: &str = "ext.example";
const CDH: [u8; 32] = [0xCD; 32];
const USER_ID: &[u8] = &[3, 1, 4, 1];
const BLOB: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];

/// A discoverable makeCredential over `RP_ID` whose extensions map (key 6) holds
/// `ext_count` entries written by `ext`.
fn mc_with_ext(ext_count: u64, ext: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap(); // keys 1,2,3,4,6,7
        e.u8(1).unwrap().bytes(&CDH).unwrap();
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
        e.str("name").unwrap().str("frank").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(ext_count).unwrap();
        ext(&mut e);
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

/// A getAssertion over `RP_ID` requesting the stored credBlob (extensions key 4).
fn ga_credblob() -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credBlob")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Read a boolean extension output from a makeCredential authData (walking past
/// the attested credential data and the COSE public key to the extension map).
fn mc_ext_bool(body: &[u8], name: &str) -> Option<bool> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut ext = Decoder::new(&ad[55 + cred_len..]);
    ext.skip().unwrap(); // the COSE public key
    let n = ext.map().ok()??;
    for _ in 0..n {
        if ext.str().unwrap() == name {
            return ext.bool().ok();
        }
        ext.skip().unwrap();
    }
    None
}

#[test]
fn credblob_makecredential_echoes_stored_flag() {
    // A short credBlob is stored → authData echoes credBlob: true.
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_ext(1, |e| {
            e.str("credBlob").unwrap().bytes(&BLOB).unwrap();
        }),
    );
    assert_ok(&r);
    assert_eq!(mc_ext_bool(&r.body, "credBlob"), Some(true));
}

#[test]
fn hmac_secret_makecredential_echoes_true() {
    // hmac-secret is acknowledged in the makeCredential authData as a bool true.
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_ext(1, |e| {
            e.str("hmac-secret").unwrap().bool(true).unwrap();
        }),
    );
    assert_ok(&r);
    assert_eq!(mc_ext_bool(&r.body, "hmac-secret"), Some(true));
}

#[test]
fn credblob_returned_by_getassertion() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_ext(1, |e| {
            e.str("credBlob").unwrap().bytes(&BLOB).unwrap();
        }),
    ));
    let g = a.send(CTAP_GET_ASSERTION, &ga_credblob());
    assert_ok(&g);
    let mut d = field_at(&g.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    assert_eq!(
        ad[32] & FLAG_ED,
        FLAG_ED,
        "ED flag set (extension output present)"
    );
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4) | extension map.
    let mut ext = Decoder::new(&ad[37..]);
    let n = ext.map().unwrap().unwrap();
    let mut got = None;
    for _ in 0..n {
        if ext.str().unwrap() == "credBlob" {
            got = Some(ext.bytes().unwrap().to_vec());
        } else {
            ext.skip().unwrap();
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(&BLOB[..]),
        "getAssertion returns the stored credBlob"
    );
}
