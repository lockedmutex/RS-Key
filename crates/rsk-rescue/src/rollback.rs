// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Anti-rollback decision. The bootrom refuses a secure image whose rollback
//! version is below the `DEFAULT_BOOT_VERSION` thermometer in OTP, and advances
//! the thermometer when a higher-versioned image boots — but images carrying
//! *no* version item boot regardless until `BOOT_FLAGS0.ROLLBACK_REQUIRED` is
//! fused. That bit is the teeth of the whole feature, and on a board whose OTP
//! page 1 is already bootloader-read-only (`rsk secure-boot lock`) only secure
//! firmware can set it — same situation as the page-58 lock, same shape of
//! guarded, idempotent fuse write, never at boot.
//!
//! All three rows involved are RBIT-3: the value is stored in three consecutive
//! rows and the bootrom reads the bitwise 2-of-3 majority.

/// First RBIT-3 copy of BOOT_FLAGS0 (copies at 0x48, 0x49, 0x4A).
/// `ROLLBACK_REQUIRED` lives here.
pub const BOOT_FLAGS0_ROW: usize = 0x048;

/// First RBIT-3 copy of DEFAULT_BOOT_VERSION0 — thermometer bits 23:0
/// (copies at 0x4E, 0x4F, 0x50).
pub const DEFAULT_BOOT_VERSION0_ROW: usize = 0x04E;

/// First RBIT-3 copy of DEFAULT_BOOT_VERSION1 — thermometer bits 47:24
/// (copies at 0x51, 0x52, 0x53).
pub const DEFAULT_BOOT_VERSION1_ROW: usize = 0x051;

/// BOOT_FLAGS0 bit 11: in secure mode, refuse to boot any image that does not
/// carry a rollback version.
pub const ROLLBACK_REQUIRED_BIT: u32 = 1 << 11;

/// The thermometer spans two 24-bit rows: epoch budget for the board's life.
pub const VERSION_CAPACITY: u8 = 48;

/// Raw 24-bit values of the three RBIT-3 copies of each anti-rollback row, as
/// read from OTP (no majority applied — that is [`majority`]'s job, so the
/// decision logic stays host-testable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackRaw {
    pub flags0: [u32; 3],
    pub version0: [u32; 3],
    pub version1: [u32; 3],
}

/// Bitwise 2-of-3 majority — what the bootrom sees through RBIT-3.
pub fn majority(rows: [u32; 3]) -> u32 {
    let [a, b, c] = rows;
    (a & b) | (a & c) | (b & c)
}

/// Whether the (majority) BOOT_FLAGS0 value has ROLLBACK_REQUIRED fused.
pub fn required(flags0: u32) -> bool {
    flags0 & ROLLBACK_REQUIRED_BIT != 0
}

/// Thermometer count from the two (majority) version words. The bootrom burns
/// one bit per epoch; counting set bits — rather than scanning for the highest —
/// reads the same value even if a copy ever ends up sparse.
pub fn version_count(version0: u32, version1: u32) -> u8 {
    ((version0 & 0x00FF_FFFF).count_ones() + (version1 & 0x00FF_FFFF).count_ones()) as u8
}

#[cfg(test)]
#[path = "rollback_tests.rs"]
mod tests;
