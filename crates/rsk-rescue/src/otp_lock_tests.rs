// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn row_is_page58_lock1() {
    // PAGE_N_LOCK1 = 0xF80 + 2*N + 1.
    assert_eq!(PAGE58_LOCK1_ROW, 0xF80 + 58 * 2 + 1);
}

#[test]
fn value_keeps_secure_rw_blocks_bl_and_ns() {
    let byte = PAGE58_LOCK_VALUE & 0xFF;
    assert_eq!(byte & 0b11, 0, "LOCK_S must be 0 = secure read-write");
    assert_eq!((byte >> 2) & 0b11, 3, "LOCK_NS must be 3 = inaccessible");
    assert_eq!((byte >> 4) & 0b11, 3, "LOCK_BL must be 3 = inaccessible");
    // Majority-vote: the same byte in all three copies (R2 | R1 | base).
    assert_eq!(PAGE58_LOCK_VALUE, byte | (byte << 8) | (byte << 16));
}

#[test]
fn blank_row_writes() {
    assert_eq!(lock_decision(0), LockDecision::Write);
}

#[test]
fn our_value_is_idempotent() {
    assert_eq!(
        lock_decision(PAGE58_LOCK_VALUE),
        LockDecision::AlreadyLocked
    );
}

#[test]
fn foreign_or_partial_value_refused() {
    // A page-63-style factory lock, a single-copy partial, secure-locked —
    // anything that is neither blank nor exactly ours must be refused.
    assert_eq!(lock_decision(0x14_14_14), LockDecision::Unexpected);
    assert_eq!(lock_decision(0x00_00_3C), LockDecision::Unexpected);
    assert_eq!(lock_decision(0x3F_3F_3F), LockDecision::Unexpected);
}
