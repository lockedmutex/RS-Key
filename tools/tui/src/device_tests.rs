// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn ber_find_walks_top_level_tlvs() {
    // 4F (short) · 5F52 (2-byte tag) · C4 (short): ber_find must step over the
    // 2-byte-tag object to reach C4, and match the 2-byte tag itself.
    let d = [
        0x4F, 0x02, 0xAA, 0xBB, // 4F
        0x5F, 0x52, 0x01, 0x99, // 5F52
        0xC4, 0x03, 0x01, 0x02, 0x03, // C4
    ];
    assert_eq!(ber_find(&d, 0x4F), Some(&[0xAA, 0xBB][..]));
    assert_eq!(ber_find(&d, 0x5F52), Some(&[0x99][..]));
    assert_eq!(ber_find(&d, 0xC4), Some(&[0x01, 0x02, 0x03][..]));
    assert_eq!(ber_find(&d, 0x7F), None);
}

#[test]
fn ber_find_unwraps_6e_and_reads_pgp_fields() {
    // A minimal 6E template: 4F AID (serial = bytes 10..14) + C4 PW status.
    let inner = [
        0x4F, 0x10, // AID, 16 bytes
        0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF, 0x00,
        0x00, // serial DEADBEEF at 10..14
        0xC4, 0x07, 0x00, 0x7F, 0x00, 0x03, 0x02, 0x00, 0x03, // PW1=2, RC=0, PW3=3
    ];
    let mut d = vec![0x6E, inner.len() as u8];
    d.extend_from_slice(&inner);
    let body = ber_find(&d, 0x6E).unwrap();
    let aid = ber_find(body, 0x4F).unwrap();
    assert_eq!(&aid[10..14], &[0xDE, 0xAD, 0xBE, 0xEF]);
    let c4 = ber_find(body, 0xC4).unwrap();
    assert_eq!([c4[4], c4[5], c4[6]], [2, 0, 3]);
}

#[test]
fn ber_find_handles_long_form_length_and_truncation() {
    let mut d = vec![0xC5, 0x81, 0x3C]; // len 60 via 0x81
    d.extend(std::iter::repeat_n(0u8, 60));
    assert_eq!(ber_find(&d, 0xC5).map(<[u8]>::len), Some(60));
    // Length claims 4 but only 2 bytes present → None, never a panic.
    assert_eq!(ber_find(&[0x4F, 0x04, 0x01, 0x02], 0x4F), None);
}

#[test]
fn parse_led_stride2_and_stride3() {
    // stride 2: [steady, (color, brightness) × 4].
    let d2 = [1, 6, 16, 3, 32, 2, 64, 7, 8];
    let l = parse_led(&d2, 2).unwrap();
    assert!(l.steady);
    assert_eq!((l.idle, l.processing, l.touch, l.boot), (6, 3, 2, 7));
    // stride 3: [steady, (effect, color, brightness) × 4] — colour is the +1 byte.
    let d3 = [0, 1, 6, 16, 2, 3, 32, 0, 2, 64, 4, 7, 8];
    let l = parse_led(&d3, 3).unwrap();
    assert!(!l.steady);
    assert_eq!((l.idle, l.processing, l.touch, l.boot), (6, 3, 2, 7));
    // Too short for four blocks → None, never an index panic.
    assert!(parse_led(&[1, 6], 2).is_none());
}
