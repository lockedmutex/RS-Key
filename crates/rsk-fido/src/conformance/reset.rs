// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §5.6 `authenticatorReset` conformance, driven through the wire
//! envelope (`process_cbor`): a present-gated wipe that clears credentials, and
//! a no-presence rejection.

use super::{Authr, assert_ok, assert_ok_empty};
use crate::consts::{ALG_ES256, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, CTAP_RESET};
use crate::error::CtapError;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

const RP_ID: &str = "reset.example";

fn mc_rk() -> Vec<u8> {
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
        e.str("id").unwrap().bytes(&[5, 5, 5, 5]).unwrap();
        e.str("name").unwrap().str("erin").unwrap();
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

fn ga() -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn reset_wipes_credentials() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk()));
    // authenticatorReset erases all FIDO state on user presence.
    assert_ok_empty(&a.send(CTAP_RESET, &[]));
    // The discoverable credential is gone.
    let r = a.send(CTAP_GET_ASSERTION, &ga());
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
}

#[test]
fn reset_denied_without_presence() {
    // Reset is destructive → it must not proceed without a touch (§5.6).
    let r = Authr::declining().send(CTAP_RESET, &[]);
    assert_eq!(r.status, CtapError::UserActionTimeout.as_u8());
}
