// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.5 clientPIN crypto-flow conformance, driven through the wire
//! envelope (`process_cbor`): key agreement (ECDH), setPIN, getPinToken (correct
//! PIN → a decryptable token; wrong PIN → PIN_INVALID + a retry decrement) and
//! changePIN. The platform side runs the real pinUvAuthProtocol-2 primitives, so
//! the exchange is verified end to end.

use super::{Authr, assert_ok_empty, field_at};
use crate::consts::{CTAP_CLIENT_PIN, MAX_PIN_RETRIES};
use crate::cose::cose_key_ecdh;
use crate::error::{CTAP2_OK, CtapError};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::pinproto::{self, PinProto, public_xy};
use rsk_crypto::sha256;

const PIN: &[u8] = b"1234";

/// A short two-key clientPIN request `{1: proto=2, 2: subCommand}`.
fn cp_short(sub: u64) -> Vec<u8> {
    let mut buf = [0u8; 16];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(2).unwrap();
        e.u8(2).unwrap().u64(sub).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Read `options.clientPin` from a fresh getInfo.
fn client_pin_set(a: &mut Authr) -> bool {
    let r = a.get_info();
    let mut d = field_at(&r.body, 4).expect("options (0x04) present");
    let n = d.map().unwrap().unwrap();
    for _ in 0..n {
        let hit = d.str().unwrap() == "clientPin";
        let v = d.bool().unwrap();
        if hit {
            return v;
        }
    }
    false
}

/// getPINRetries (subCommand 1) → the current counter.
fn pin_retries(a: &mut Authr) -> u8 {
    let r = a.send(CTAP_CLIENT_PIN, &cp_short(1));
    let mut d = field_at(&r.body, 3).expect("retries (0x03) present");
    d.u8().unwrap()
}

/// The platform half of the PIN protocol: a fixed ECDH key + the shared secret.
struct PinClient {
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl PinClient {
    /// Perform key agreement (getKeyAgreement) and derive the shared secret.
    fn establish(a: &mut Authr) -> Self {
        let r = a.send(CTAP_CLIENT_PIN, &cp_short(2));
        let (ax, ay) = authenticator_public(&r.body);
        let mut s = [0u8; 32];
        s[0] = 0x13;
        s[31] = 0x42;
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(PinProto::Two, &s, &ax, &ay, &mut shared).unwrap();
        PinClient {
            x,
            y,
            shared: shared[..slen].to_vec(),
        }
    }

    fn enc(&self, pt: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::encrypt(PinProto::Two, &self.shared, &[0x55; 16], pt, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 32];
        let n = pinproto::authenticate(PinProto::Two, &self.shared, data, &mut out).unwrap();
        out[..n].to_vec()
    }

    /// setPIN request: `{1:2, 2:3, 3:keyAgreement, 4:pinUvAuthParam, 5:newPinEnc}`.
    fn set_pin(&self, pin: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin);
        let npe = self.enc(&padded);
        let puap = self.mac(&npe);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(3).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(4).unwrap().bytes(&puap).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// Legacy getPinToken request: `{1:2, 2:5, 3:keyAgreement, 6:pinHashEnc}`.
    fn get_token(&self, pin: &[u8]) -> Vec<u8> {
        let h = sha256(pin);
        let phe = self.enc(&h[..16]);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(5).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// changePIN request: `{1:2, 2:4, 3:keyAgreement, 4:puap, 5:newPinEnc, 6:pinHashEnc}`.
    fn change_pin(&self, old: &[u8], new: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..new.len()].copy_from_slice(new);
        let npe = self.enc(&padded);
        let oh = sha256(old);
        let phe = self.enc(&oh[..16]);
        let mut macd = npe.clone();
        macd.extend_from_slice(&phe);
        let puap = self.mac(&macd);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(4).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(4).unwrap().bytes(&puap).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// Decrypt the pinUvAuthToken from a getPinToken response `{2: enc}`.
    fn decrypt_token(&self, body: &[u8]) -> [u8; 32] {
        let mut d = field_at(body, 2).expect("pinUvAuthToken (0x02) present");
        let enc = d.bytes().unwrap();
        let mut tok = [0u8; 32];
        let n = pinproto::decrypt(PinProto::Two, &self.shared, enc, &mut tok).unwrap();
        assert_eq!(n, 32, "a pinUvAuthToken is 32 bytes");
        tok
    }
}

/// The authenticator's key-agreement public key (x, y) from getKeyAgreement:
/// `{1: {1:2, 3:-25, -1:1, -2:x, -3:y}}`.
fn authenticator_public(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut d = field_at(body, 1).expect("keyAgreement (0x01) present");
    assert_eq!(d.map().unwrap().unwrap(), 5);
    d.u8().unwrap();
    d.u8().unwrap(); // 1: kty = 2
    d.u8().unwrap();
    d.i64().unwrap(); // 3: alg = -25
    d.i8().unwrap();
    d.u8().unwrap(); // -1: crv = 1
    d.i8().unwrap(); // -2: x label
    let mut x = [0u8; 32];
    x.copy_from_slice(d.bytes().unwrap());
    d.i8().unwrap(); // -3: y label
    let mut y = [0u8; 32];
    y.copy_from_slice(d.bytes().unwrap());
    (x, y)
}

#[test]
fn clientpin_set_pin_enables_client_pin() {
    let mut a = Authr::fresh();
    assert!(!client_pin_set(&mut a), "clientPin starts unset");
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    assert!(
        client_pin_set(&mut a),
        "clientPin flips to true after setPIN"
    );
    assert_eq!(
        pin_retries(&mut a),
        MAX_PIN_RETRIES,
        "setPIN does not consume a retry"
    );
}

#[test]
fn clientpin_get_token_with_correct_pin() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token(PIN));
    assert_eq!(r.status, CTAP2_OK);
    let tok = pc.decrypt_token(&r.body);
    assert_ne!(tok, [0u8; 32], "a non-trivial pinUvAuthToken is returned");
}

#[test]
fn clientpin_wrong_pin_decrements_retries() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let before = pin_retries(&mut a);
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token(b"9999"));
    assert_eq!(r.status, CtapError::PinInvalid.as_u8());
    assert_eq!(
        pin_retries(&mut a),
        before - 1,
        "a wrong PIN consumes exactly one retry"
    );
}

#[test]
fn clientpin_change_pin() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.change_pin(PIN, b"5678")));
    // The new PIN yields a token; the old PIN is rejected.
    assert_eq!(
        a.send(CTAP_CLIENT_PIN, &pc.get_token(b"5678")).status,
        CTAP2_OK
    );
    assert_eq!(
        a.send(CTAP_CLIENT_PIN, &pc.get_token(PIN)).status,
        CtapError::PinInvalid.as_u8()
    );
}
