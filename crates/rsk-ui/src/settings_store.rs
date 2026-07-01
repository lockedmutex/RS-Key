// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_DISPLAY` wire-format codec — the persisted on-device display settings the
//! trusted-display firmware reads at boot and writes when the user edits them in
//! Settings → Display.
//!
//! The block is `[brightness, sleep_secs_be(2), flags]` (4 bytes): the backlight
//! level (`1..=BRIGHTNESS_LEVELS`), the display-sleep timeout in seconds (`0` =
//! Off), and a flags byte (currently only [`FLAG_PIN_DECLINED`] — the user chose
//! "continue without a device PIN" at first-run, so the panel must not re-prompt).
//! The **touch timeout** is *not* here — it persists in the phy record's
//! `PresenceTimeout` tag (shared with `rsk hw --touch-timeout`), so it keeps one
//! source of truth.
//!
//! [`DisplayConfig::apply_block`] overlays a stored block onto a default `self`,
//! field by field, so a record written by an *older* firmware (the original
//! [`CORE_LEN`]-byte block, no flags) or read by an *older* firmware (a future,
//! longer block — only its known prefix is read) survives a firmware upgrade
//! without losing or misreading a field; anything a shorter block omits keeps its
//! current value. [`DisplayConfig::default`] mirrors the firmware's live defaults,
//! so a device with no record behaves exactly as before.
//!
//! Like `rsk-led`'s codec this crate is pure (no `embassy` / HAL), so the format is
//! unit-testable on the host; `firmware/src/display.rs` owns the live brightness
//! field and the `SLEEP_TIMEOUT_MS` atomic and marshals them through here.

/// `EF_DISPLAY` length: `[brightness, sleep_secs_be(2), flags]`.
pub const CONF_LEN: usize = 4;

/// The original layout (`[brightness, sleep_secs_be(2)]`, no flags byte). A record
/// written before the flags byte existed is exactly this long; [`DisplayConfig::apply_block`]
/// still reads its two fields and leaves the flags at their default, so an already-provisioned
/// device keeps its brightness / sleep across the upgrade that added the byte.
const CORE_LEN: usize = 3;

/// Flags-byte bit 0: the user chose "continue without a device PIN" at the
/// first-run prompt. Set, the panel never re-shows that onboarding screen (until a
/// factory reset wipes `EF_DISPLAY`); clear (the default), a PIN-less device is
/// offered the prompt once.
pub const FLAG_PIN_DECLINED: u8 = 0x01;

/// Default display-sleep timeout in seconds — mirrors the firmware's
/// `DEFAULT_SLEEP_MS` (60 s) so a device with no record blanks on the same schedule
/// it did before this record existed.
pub const DEFAULT_SLEEP_SECS: u16 = 60;

/// The persisted display settings: backlight level, the display-sleep timeout, and
/// the first-run PIN-prompt flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisplayConfig {
    /// Backlight level `1..=BRIGHTNESS_LEVELS`. Stored raw; the firmware clamps it
    /// to the valid range when it applies it to the PWM, so a corrupt or
    /// out-of-range byte can never blank or over-drive the panel.
    pub brightness: u8,
    /// Display-sleep timeout in seconds; `0` = Off (never blanks).
    pub sleep_secs: u16,
    /// The user has dismissed the first-run "set a device PIN?" prompt by choosing
    /// to continue without one — so the panel must not re-offer it. Cleared on a
    /// factory reset (which wipes the record), so a wiped device re-onboards.
    pub pin_declined: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            brightness: crate::BRIGHTNESS_LEVELS,
            sleep_secs: DEFAULT_SLEEP_SECS,
            pin_declined: false,
        }
    }
}

impl DisplayConfig {
    /// Pack into the 4-byte wire block: `[brightness, sleep_secs_be, flags]`
    /// (big-endian sleep, matching the phy record's byte order).
    pub fn encode(&self) -> [u8; CONF_LEN] {
        let s = self.sleep_secs.to_be_bytes();
        let flags = if self.pin_declined {
            FLAG_PIN_DECLINED
        } else {
            0
        };
        [self.brightness, s[0], s[1], flags]
    }

    /// Overlay a stored block onto `self`, field by field. The brightness + sleep
    /// pair is read from any block at least [`CORE_LEN`] long (so the original
    /// flags-less record still loads, keeping `pin_declined` at its default); the
    /// flags byte is read only from a full [`CONF_LEN`] block. A future, longer
    /// block is read up to its known prefix. Anything shorter than `CORE_LEN` can
    /// only be flash corruption, so those fields stay at their defaults rather than
    /// half-applied.
    pub fn apply_block(&mut self, b: &[u8]) {
        if b.len() >= CORE_LEN {
            self.brightness = b[0];
            self.sleep_secs = u16::from_be_bytes([b[1], b[2]]);
        }
        if b.len() >= CONF_LEN {
            self.pin_declined = b[3] & FLAG_PIN_DECLINED != 0;
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
            pin_declined: kani::any(),
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
        assert_eq!(CONF_LEN, 4);
        assert_eq!(CORE_LEN, 3);
    }

    #[test]
    fn default_mirrors_firmware_runtime_defaults() {
        let d = DisplayConfig::default();
        assert_eq!(d.brightness, crate::BRIGHTNESS_LEVELS);
        assert_eq!(d.sleep_secs, 60);
        assert!(!d.pin_declined);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let cfg = DisplayConfig {
            brightness: 3,
            sleep_secs: 120,
            pin_declined: true,
        };
        let mut got = DisplayConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }

    #[test]
    fn encode_layout_is_brightness_then_be_sleep_then_flags() {
        let b = DisplayConfig {
            brightness: 4,
            sleep_secs: 300,
            pin_declined: true,
        }
        .encode();
        assert_eq!(b.len(), 4);
        assert_eq!(b[0], 4);
        assert_eq!(u16::from_be_bytes([b[1], b[2]]), 300);
        assert_eq!(b[3], FLAG_PIN_DECLINED);
    }

    #[test]
    fn pin_declined_clear_encodes_zero_flags() {
        let b = DisplayConfig {
            brightness: 2,
            sleep_secs: 60,
            pin_declined: false,
        }
        .encode();
        assert_eq!(b[3], 0);
    }

    #[test]
    fn off_sentinel_roundtrips() {
        let cfg = DisplayConfig {
            brightness: 5,
            sleep_secs: 0, // Off
            pin_declined: false,
        };
        let mut got = DisplayConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }

    #[test]
    fn legacy_core_block_loads_fields_and_keeps_flag_default() {
        // A record written before the flags byte existed is exactly CORE_LEN: its
        // brightness + sleep still load, and pin_declined stays at its default
        // (false) — so an already-provisioned device survives the upgrade.
        let core = [3u8, 0x00, 0x1E]; // brightness 3, sleep 30 s, no flags
        let mut got = DisplayConfig::default();
        got.apply_block(&core);
        assert_eq!(got.brightness, 3);
        assert_eq!(got.sleep_secs, 30);
        assert!(!got.pin_declined);
    }

    #[test]
    fn unknown_flag_bits_do_not_set_pin_declined() {
        // Only bit 0 is FLAG_PIN_DECLINED; a future bit set alone must not be read
        // as a decline.
        let mut got = DisplayConfig::default();
        got.apply_block(&[5, 0x00, 0x3C, 0x02]);
        assert!(!got.pin_declined);
    }

    #[test]
    fn empty_block_keeps_defaults() {
        let mut got = DisplayConfig::default();
        got.apply_block(&[]);
        assert_eq!(got, DisplayConfig::default());
    }

    #[test]
    fn short_block_below_core_len_keeps_defaults() {
        // No sub-CORE_LEN layout was ever written, so a 1- or 2-byte block is
        // corruption: leave the fields at their defaults rather than half-apply.
        for short in [&[2u8][..], &[2u8, 0u8][..]] {
            let mut got = DisplayConfig::default();
            got.apply_block(short);
            assert_eq!(got, DisplayConfig::default());
        }
    }

    #[test]
    fn longer_future_block_reads_known_prefix() {
        // A future, longer record still loads its first CONF_LEN bytes (the >= branch).
        let cfg = DisplayConfig {
            brightness: 1,
            sleep_secs: 30,
            pin_declined: true,
        };
        let mut b = [0u8; 7];
        b[..CONF_LEN].copy_from_slice(&cfg.encode());
        let mut got = DisplayConfig::default();
        got.apply_block(&b);
        assert_eq!(got, cfg);
    }

    /// Deterministic property sweep: `apply_block` must never panic and must be
    /// idempotent on an *arbitrary* byte slice — the persisted record is attacker-
    /// or corruption-influenced flash, and `Storage::read` returns the value's *full*
    /// length (which can exceed the firmware's 4-byte read buffer), so the codec is
    /// the chokepoint that guarantees an out-of-range, truncated, all-0xFF, empty, or
    /// over-long record can only mis-load fields, never index OOB or brick the boot.
    #[test]
    fn apply_block_no_panic_and_idempotent_over_random_slices() {
        // A tiny xorshift64* PRNG: deterministic, reproducible in CI, no dev-dep.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        // Lengths from 0 up to well past CONF_LEN exercise: empty, sub-CORE_LEN,
        // CORE_LEN-only (legacy), full CONF_LEN, and the longer-than-known cases —
        // the last is what a host buffer trim (`n.min(buf.len())`) protects in
        // `Ui::build`; proving the codec itself is OOB-safe makes that defence
        // belt-and-braces, not the only thing standing between flash and a panic.
        let mut bytes = [0u8; 64];
        for _ in 0..50_000 {
            let len = (next() as usize) % (bytes.len() + 1);
            for b in bytes[..len].iter_mut() {
                *b = next() as u8;
            }
            let block = &bytes[..len];

            // (a) panic-freedom: applying onto a fresh default must not index OOB.
            let mut a = DisplayConfig::default();
            a.apply_block(block); // would panic here on any OOB bug

            // (b) idempotence: a second application of the *same* block is a no-op,
            // because apply_block is a pure field-by-field overlay (no accumulation).
            let mut b2 = a;
            b2.apply_block(block);
            assert_eq!(a, b2, "apply_block not idempotent for {block:02x?}");

            // Cross-check the documented prefix contract: a >= CORE_LEN block sets
            // brightness/sleep from the first 3 bytes; a shorter one leaves them at
            // the default (never half-applied); the flag only loads from a full block.
            if len >= CORE_LEN {
                assert_eq!(a.brightness, block[0]);
                assert_eq!(a.sleep_secs, u16::from_be_bytes([block[1], block[2]]));
            } else {
                assert_eq!(a.brightness, DisplayConfig::default().brightness);
                assert_eq!(a.sleep_secs, DisplayConfig::default().sleep_secs);
            }
            if len >= CONF_LEN {
                assert_eq!(a.pin_declined, block[3] & FLAG_PIN_DECLINED != 0);
            } else {
                assert!(!a.pin_declined); // default
            }
        }
    }

    /// The all-0xFF block (erased / never-written flash reads as 0xFF on this medium)
    /// must load cleanly, not panic: brightness 0xFF (the firmware clamps it to the
    /// valid range before driving the PWM), sleep 0xFFFF, pin_declined set.
    #[test]
    fn all_ones_block_loads_without_panic() {
        let mut got = DisplayConfig::default();
        got.apply_block(&[0xFF; CONF_LEN]);
        assert_eq!(got.brightness, 0xFF); // raw; firmware clamps to 1..=BRIGHTNESS_LEVELS
        assert_eq!(got.sleep_secs, 0xFFFF);
        assert!(got.pin_declined);
    }
}
