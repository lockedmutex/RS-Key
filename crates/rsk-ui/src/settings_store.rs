// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_DISPLAY` wire-format codec — the persisted on-device display settings the
//! trusted-display firmware reads at boot and writes when the user edits them in
//! Settings → Display.
//!
//! The block is `[brightness, sleep_secs_be(2)]` (3 bytes): the backlight level
//! (`1..=BRIGHTNESS_LEVELS`) and the display-sleep timeout in seconds (`0` = Off).
//! The **touch timeout** is *not* here — it persists in the phy record's
//! `PresenceTimeout` tag (shared with `rsk hw --touch-timeout`), so it keeps one
//! source of truth.
//!
//! [`DisplayConfig::apply_block`] overlays a stored block onto a default `self`, so
//! a record written by an *older* firmware (a shorter block) or read by an *older*
//! firmware (a future, longer block — only its known prefix is read) survives a
//! firmware upgrade without losing or misreading a field; anything a shorter block
//! omits keeps its current value. [`DisplayConfig::default`] mirrors the firmware's
//! live defaults, so a device with no record behaves exactly as before.
//!
//! Like `rsk-led`'s codec this crate is pure (no `embassy` / HAL), so the format is
//! unit-testable on the host; `firmware/src/display.rs` owns the live brightness
//! field and the `SLEEP_TIMEOUT_MS` atomic and marshals them through here.

/// `EF_DISPLAY` length: `[brightness, sleep_secs_be(2)]`.
pub const CONF_LEN: usize = 3;

/// Default display-sleep timeout in seconds — mirrors the firmware's
/// `DEFAULT_SLEEP_MS` (60 s) so a device with no record blanks on the same schedule
/// it did before this record existed.
pub const DEFAULT_SLEEP_SECS: u16 = 60;

/// The persisted display settings: backlight level plus the display-sleep timeout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisplayConfig {
    /// Backlight level `1..=BRIGHTNESS_LEVELS`. Stored raw; the firmware clamps it
    /// to the valid range when it applies it to the PWM, so a corrupt or
    /// out-of-range byte can never blank or over-drive the panel.
    pub brightness: u8,
    /// Display-sleep timeout in seconds; `0` = Off (never blanks).
    pub sleep_secs: u16,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            brightness: crate::BRIGHTNESS_LEVELS,
            sleep_secs: DEFAULT_SLEEP_SECS,
        }
    }
}

impl DisplayConfig {
    /// Pack into the 3-byte wire block: `[brightness, sleep_secs_be]` (big-endian
    /// sleep, matching the phy record's byte order).
    pub fn encode(&self) -> [u8; CONF_LEN] {
        let s = self.sleep_secs.to_be_bytes();
        [self.brightness, s[0], s[1]]
    }

    /// Overlay a stored block onto `self`. The block always carries both fields
    /// (there is no shorter legacy layout — this record was born at `CONF_LEN`), and a
    /// future, longer block is read up to its known prefix. Anything shorter than
    /// `CONF_LEN` can only be flash corruption, so `self` is left at its defaults
    /// rather than half-applied.
    pub fn apply_block(&mut self, b: &[u8]) {
        if b.len() >= CONF_LEN {
            self.brightness = b[0];
            self.sleep_secs = u16::from_be_bytes([b[1], b[2]]);
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `apply_block(encode()) == id` for every config: the round-trip never loses
    /// or corrupts a field.
    #[kani::proof]
    fn encode_apply_block_roundtrip() {
        let cfg = DisplayConfig {
            brightness: kani::any(),
            sleep_secs: kani::any(),
        };
        let mut got = DisplayConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_len_matches_layout() {
        assert_eq!(CONF_LEN, 3);
    }

    #[test]
    fn default_mirrors_firmware_runtime_defaults() {
        let d = DisplayConfig::default();
        assert_eq!(d.brightness, crate::BRIGHTNESS_LEVELS);
        assert_eq!(d.sleep_secs, 60);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let cfg = DisplayConfig {
            brightness: 3,
            sleep_secs: 120,
        };
        let mut got = DisplayConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }

    #[test]
    fn encode_layout_is_brightness_then_be_sleep() {
        let b = DisplayConfig {
            brightness: 4,
            sleep_secs: 300,
        }
        .encode();
        assert_eq!(b.len(), 3);
        assert_eq!(b[0], 4);
        assert_eq!(u16::from_be_bytes([b[1], b[2]]), 300);
    }

    #[test]
    fn off_sentinel_roundtrips() {
        let cfg = DisplayConfig {
            brightness: 5,
            sleep_secs: 0, // Off
        };
        let mut got = DisplayConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }

    #[test]
    fn empty_block_keeps_defaults() {
        let mut got = DisplayConfig::default();
        got.apply_block(&[]);
        assert_eq!(got, DisplayConfig::default());
    }

    #[test]
    fn short_block_below_conf_len_keeps_defaults() {
        // No sub-CONF_LEN layout was ever written, so a 1- or 2-byte block is
        // corruption: leave both fields at their defaults rather than half-apply.
        for short in [&[2u8][..], &[2u8, 0u8][..]] {
            let mut got = DisplayConfig::default();
            got.apply_block(short);
            assert_eq!(got, DisplayConfig::default());
        }
    }

    #[test]
    fn longer_future_block_reads_known_prefix() {
        // A future, longer record still loads its first 3 bytes (the >= branch).
        let cfg = DisplayConfig {
            brightness: 1,
            sleep_secs: 30,
        };
        let mut b = [0u8; 6];
        b[..CONF_LEN].copy_from_slice(&cfg.encode());
        let mut got = DisplayConfig::default();
        got.apply_block(&b);
        assert_eq!(got, cfg);
    }
}
