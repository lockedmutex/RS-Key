// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn rows_match_the_datasheet_map() {
    // RBIT-3: each value owns three consecutive rows, hence the spacing.
    assert_eq!(BOOT_FLAGS0_ROW, 0x048);
    assert_eq!(DEFAULT_BOOT_VERSION0_ROW, 0x04E);
    assert_eq!(DEFAULT_BOOT_VERSION1_ROW, DEFAULT_BOOT_VERSION0_ROW + 3);
    assert_eq!(VERSION_CAPACITY as u32, 2 * 24);
}

#[test]
fn majority_is_two_of_three_bitwise() {
    assert_eq!(majority([0, 0, 0]), 0);
    assert_eq!(majority([0b1010, 0b1010, 0]), 0b1010);
    assert_eq!(majority([0b1010, 0, 0b1010]), 0b1010);
    assert_eq!(majority([0b0110, 0b0011, 0b0101]), 0b0111); // per-bit, not per-row
    // A single-copy write (interrupted burn) does not count…
    assert_eq!(majority([ROLLBACK_REQUIRED_BIT, 0, 0]), 0);
    // …two copies do.
    assert_eq!(
        majority([ROLLBACK_REQUIRED_BIT, ROLLBACK_REQUIRED_BIT, 0]),
        ROLLBACK_REQUIRED_BIT
    );
}

#[test]
fn required_reads_bit_11() {
    assert!(!required(0));
    assert!(required(ROLLBACK_REQUIRED_BIT));
    assert!(required(0x00FF_FFFF));
    assert!(!required(!ROLLBACK_REQUIRED_BIT & 0x00FF_FFFF));
}

#[test]
fn version_counts_thermometer_bits() {
    assert_eq!(version_count(0, 0), 0);
    assert_eq!(version_count(0b1, 0), 1);
    assert_eq!(version_count(0b111, 0), 3);
    // Sparse bits still count — robust against odd burn orders.
    assert_eq!(version_count(0b101, 0), 2);
    assert_eq!(version_count(0x00FF_FFFF, 0), 24);
    assert_eq!(version_count(0x00FF_FFFF, 0b1), 25);
    assert_eq!(version_count(0x00FF_FFFF, 0x00FF_FFFF), VERSION_CAPACITY);
    // Bits above the 24-bit row width are masked, not counted.
    assert_eq!(version_count(0xFF00_0000, 0xFF00_0000), 0);
}
