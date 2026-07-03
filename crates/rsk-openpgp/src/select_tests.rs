// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::*;

#[test]
fn fci_shape_is_faithful() {
    let mut out = [0u8; 64];
    let n = build_fci(&mut out);
    assert_eq!(n, 34);
    assert_eq!(out[0], 0x6F);
    assert_eq!(out[1], 0x20); // 32 = 24 (62 template) + 8 (64 DO)
    assert_eq!(out[2], 0x62);
    assert_eq!(out[3], 0x16); // FCP template length = 22
    assert_eq!(&out[15..17], &[0x84, 0x06]); // 84 06 <AID>
    assert_eq!(&out[17..23], OPENPGP_AID);
    // 64 06 53 04 <heap>
    assert_eq!(&out[26..30], &[0x64, 0x06, 0x53, 0x04]);
}

fn parse(raw: &[u8]) -> Apdu<'_> {
    Apdu::parse(raw).unwrap()
}

#[test]
fn select_by_name_matches_aid() {
    let mut raw = vec![0x00, INS_SELECT, 0x04, 0x00, OPENPGP_AID.len() as u8];
    raw.extend_from_slice(OPENPGP_AID);
    let (n, sw) = cmd_select(&parse(&raw), &mut [0u8; 64]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(n, 0); // P2 == 0x00 → no FCI body
}

#[test]
fn select_by_fid_known_do() {
    let raw = [0x00, INS_SELECT, 0x02, 0x00, 0x02, 0x00, 0x6E];
    let (_, sw) = cmd_select(&parse(&raw), &mut [0u8; 64]);
    assert_eq!(sw, Sw::OK);
}

#[test]
fn select_unknown_fid_not_found() {
    let raw = [0x00, INS_SELECT, 0x02, 0x00, 0x02, 0x42, 0x42];
    let (_, sw) = cmd_select(&parse(&raw), &mut [0u8; 64]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
}
