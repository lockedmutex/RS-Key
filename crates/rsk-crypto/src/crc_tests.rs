// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn check_value() {
    // The canonical CRC-32 check: "123456789" -> 0xCBF43926.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn empty_is_zero() {
    assert_eq!(crc32(b""), 0);
}

#[test]
fn known_strings() {
    assert_eq!(
        crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
}
