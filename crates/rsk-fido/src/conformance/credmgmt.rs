// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.8 `authenticatorCredentialManagement` conformance, driven through
//! the wire envelope (`process_cbor`): getCredsMetadata's count response, the
//! pinUvAuthParam requirement, and the credMgmt-permission check. The MAC over a
//! parameter-less subcommand covers just its command byte (§6.8).

use super::{Authr, assert_ok, field_at, int_map_keys, pin_auth};
use crate::consts::{ALG_ES256, CM_GET_CREDS_METADATA, CTAP_CREDENTIAL_MGMT, CTAP_MAKE_CREDENTIAL};
use crate::error::CtapError;
use crate::state::{PERM_CM, PERM_GA};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// A discoverable ES256 makeCredential request over `rp` with user id `uid`.
fn mc_rk(rp: &str, uid: &[u8]) -> Vec<u8> {
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
            .str(rp)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("dave").unwrap();
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

/// getCredsMetadata request: `{1: subCommand, [3: proto, 4: pinUvAuthParam]}`.
fn cm_metadata(param: Option<&[u8]>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if param.is_some() { 3 } else { 1 }).unwrap();
        e.u8(1).unwrap().u64(CM_GET_CREDS_METADATA).unwrap();
        if let Some(p) = param {
            e.u8(3).unwrap().u64(2).unwrap();
            e.u8(4).unwrap().bytes(p).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn credmgmt_creds_metadata_counts() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk("a.example", &[1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk("b.example", &[2])));

    let token = a.arm_token(PERM_CM);
    let param = pin_auth(&token, &[CM_GET_CREDS_METADATA as u8]);
    let r = a.send(CTAP_CREDENTIAL_MGMT, &cm_metadata(Some(&param)));
    assert_ok(&r);
    // { 1: existingResidentCredentials, 2: maxPossibleRemainingResidentCredentials }
    assert_eq!(int_map_keys(&r.body), vec![1u32, 2]);
    let mut d = field_at(&r.body, 1).expect("existing count (0x01)");
    assert_eq!(
        d.u16().unwrap(),
        2,
        "two resident credentials were registered"
    );
    let mut d = field_at(&r.body, 2).expect("remaining count (0x02)");
    assert!(d.u16().unwrap() >= 1, "remaining capacity must be reported");
}

#[test]
fn credmgmt_requires_pinuvauth() {
    // credMgmt with no pinUvAuthParam → CTAP2_ERR_PUAT_REQUIRED (§6.8).
    let r = Authr::fresh().send(CTAP_CREDENTIAL_MGMT, &cm_metadata(None));
    assert_eq!(r.status, CtapError::PuatRequired.as_u8());
}

#[test]
fn credmgmt_wrong_permission_rejected() {
    // A token missing the credMgmt permission → CTAP2_ERR_PIN_AUTH_INVALID (§6.8).
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_GA);
    let param = pin_auth(&token, &[CM_GET_CREDS_METADATA as u8]);
    let r = a.send(CTAP_CREDENTIAL_MGMT, &cm_metadata(Some(&param)));
    assert_eq!(r.status, CtapError::PinAuthInvalid.as_u8());
}
