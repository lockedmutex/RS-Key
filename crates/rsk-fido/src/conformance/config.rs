// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.11 `authenticatorConfig` conformance, driven through the wire
//! envelope (`process_cbor`): enableEnterpriseAttestation round-trips into
//! getInfo `options.ep`, and the credMgmt-style pinUvAuthParam over
//! `0xff*32 ‖ 0x0d ‖ subCommand ‖ params` is permission-checked (PERM_ACFG).

use super::{Authr, assert_ok_empty, field_at, pin_auth};
use crate::consts::{
    CONFIG_ENABLE_EA, CONFIG_SET_MIN_PIN, CONFIG_TOGGLE_ALWAYS_UV, CTAP_CONFIG, MIN_PIN_LENGTH,
};
use crate::error::CtapError;
use crate::state::{PERM_ACFG, PERM_GA, puat_subcommand_msg};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// authenticatorConfig request `{1: subCommand, 3: proto, 4: pinUvAuthParam}`.
fn config_request(subcommand: u64, param: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().u64(subcommand).unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(param).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The pinUvAuthParam for a parameter-less authenticatorConfig subcommand.
fn acfg_param(token: &[u8; 32], subcommand: u64) -> Vec<u8> {
    let mut msg = [0u8; 64];
    let n = puat_subcommand_msg(&mut msg, CTAP_CONFIG, subcommand as u8, &[]);
    pin_auth(token, &msg[..n])
}

/// Read a boolean `options.<name>` from a fresh getInfo (false if absent).
fn getinfo_option(a: &mut Authr, name: &str) -> bool {
    let r = a.get_info();
    let mut d = field_at(&r.body, 4).expect("options (0x04) present");
    let n = d.map().unwrap().unwrap();
    for _ in 0..n {
        let hit = d.str().unwrap() == name;
        let val = d.bool().unwrap();
        if hit {
            return val;
        }
    }
    false
}

#[test]
fn config_enable_enterprise_attestation_round_trips() {
    let mut a = Authr::fresh();
    assert!(!getinfo_option(&mut a, "ep"), "options.ep starts disabled");
    let token = a.arm_token(PERM_ACFG);
    let param = acfg_param(&token, CONFIG_ENABLE_EA);
    assert_ok_empty(&a.send(CTAP_CONFIG, &config_request(CONFIG_ENABLE_EA, &param)));
    assert!(
        getinfo_option(&mut a, "ep"),
        "options.ep must flip to true after enableEnterpriseAttestation"
    );
}

#[test]
fn config_toggle_always_uv_round_trips() {
    let mut a = Authr::fresh();
    // alwaysUv starts at the compiled default — disabled on the shipped and
    // conformance images, enabled only under `--features always-uv` — and
    // toggleAlwaysUv must flip whatever that default is. A real conformance run is a
    // default build, so it still observes the "starts disabled → true" path.
    let start = getinfo_option(&mut a, "alwaysUv");
    assert_eq!(
        start,
        cfg!(feature = "always-uv"),
        "options.alwaysUv starts at the compiled default"
    );
    let token = a.arm_token(PERM_ACFG);
    let param = acfg_param(&token, CONFIG_TOGGLE_ALWAYS_UV);
    assert_ok_empty(&a.send(
        CTAP_CONFIG,
        &config_request(CONFIG_TOGGLE_ALWAYS_UV, &param),
    ));
    assert_eq!(
        getinfo_option(&mut a, "alwaysUv"),
        !start,
        "toggleAlwaysUv must flip options.alwaysUv"
    );
}

#[test]
fn config_wrong_permission_rejected() {
    // A token without the authenticatorConfiguration permission → PIN_AUTH_INVALID.
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_GA);
    let param = acfg_param(&token, CONFIG_ENABLE_EA);
    let r = a.send(CTAP_CONFIG, &config_request(CONFIG_ENABLE_EA, &param));
    assert_eq!(r.status, CtapError::PinAuthInvalid.as_u8());
}

/// Read `minPINLength` (getInfo 0x0D).
fn getinfo_min_pin(a: &mut Authr) -> u8 {
    let r = a.get_info();
    let mut d = field_at(&r.body, 0x0D).expect("minPINLength (0x0D) present");
    d.u8().unwrap()
}

/// setMinPINLength request with subCommandParams `{1: newMin}`; the pinUvAuthParam
/// covers `0xff*32 ‖ 0x0d ‖ 0x03 ‖ <raw subCommandParams>`.
fn set_min_pin_req(token: &[u8; 32], new_min: u64) -> Vec<u8> {
    let mut sub = [0u8; 8];
    let sn = {
        let mut e = Encoder::new(Cursor::new(&mut sub[..]));
        e.map(1).unwrap();
        e.u8(1).unwrap().u64(new_min).unwrap();
        e.writer().position()
    };
    let mut msg = [0u8; 64];
    let mn = puat_subcommand_msg(&mut msg, CTAP_CONFIG, CONFIG_SET_MIN_PIN as u8, &sub[..sn]);
    let puap = pin_auth(token, &msg[..mn]);
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().u64(CONFIG_SET_MIN_PIN).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(new_min)
            .unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&puap).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn config_set_min_pin_length_round_trips() {
    let mut a = Authr::fresh();
    assert_eq!(
        getinfo_min_pin(&mut a),
        MIN_PIN_LENGTH,
        "minPINLength starts at the build default"
    );
    let token = a.arm_token(PERM_ACFG);
    assert_ok_empty(&a.send(CTAP_CONFIG, &set_min_pin_req(&token, 6)));
    assert_eq!(
        getinfo_min_pin(&mut a),
        6,
        "getInfo minPINLength reflects setMinPINLength"
    );
}
