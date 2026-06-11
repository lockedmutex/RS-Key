// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Page-58 hard-lock decision. The MKEK/DEVK live in OTP page 58; their lock row
//! PAGE58_LOCK1 (0xFF5) is in page 63, which RP2350 ships bootloader-read-only, so
//! only secure firmware can write it — one idempotent, guarded fuse write, never at boot.

/// OTP row of PAGE58_LOCK1 (= PAGE0_LOCK0 0xF80 + 58*2 + 1).
pub const PAGE58_LOCK1_ROW: usize = 0xFF5;

/// The only value the firmware will ever write to that row: byte 0x3C in each
/// of the row's three majority-vote copies. 0x3C = LOCK_S 0 (secure read-write —
/// the firmware keeps reading the keys), LOCK_NS 3 and LOCK_BL 3 (inaccessible).
/// Once it lands, `picotool otp get` can no longer read the page-58 keys.
pub const PAGE58_LOCK_VALUE: u32 = 0x3C_3C_3C;

/// What to do given the current raw value of PAGE58_LOCK1.
#[derive(Debug, PartialEq, Eq)]
pub enum LockDecision {
    /// Row is blank — write the lock.
    Write,
    /// Row already holds exactly our value — idempotent no-op.
    AlreadyLocked,
    /// Row holds some other (partial / foreign) value — refuse. OTP bits only
    /// ever go 0→1, so ORing our value into a non-zero row could land a
    /// different, unintended access config; never clobber.
    Unexpected,
}

/// Decide the lock action purely from the row's current raw value.
pub fn lock_decision(current_raw: u32) -> LockDecision {
    match current_raw {
        0 => LockDecision::Write,
        PAGE58_LOCK_VALUE => LockDecision::AlreadyLocked,
        _ => LockDecision::Unexpected,
    }
}

#[cfg(test)]
mod tests {
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
}
