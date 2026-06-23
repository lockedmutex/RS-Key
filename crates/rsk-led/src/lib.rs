// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_LED_CONF` wire-format codec — the persisted LED config block shared by the
//! firmware (`firmware/src/led.rs`) and the `rsk led` host tool.
//!
//! The current block is `[steady, (effect, color, brightness, speed) × N_STATUS]`
//! (17 bytes). [`LedConfig::apply_block`] also accepts the older 13-byte
//! (pre-speed), 9-byte (pre-effect), and 2/3-byte (idle-only legacy) layouts
//! written by earlier firmware, so a flash record survives a firmware upgrade
//! without losing a field — anything the shorter block omits keeps its current
//! value.
//!
//! This crate is deliberately pure (no `embassy` / HAL dependency) so the codec
//! is unit-testable on the host. The firmware's `led.rs` owns the live atomics,
//! the effect rendering, and the PIO task, and marshals them through
//! [`LedConfig`]; nothing here touches hardware.

#![cfg_attr(not(test), no_std)]

/// Number of device statuses (idle, processing, touch, boot), in that order.
pub const N_STATUS: usize = 4;

/// `EF_LED_CONF` length: `[steady, (effect, color, brightness, speed) × N_STATUS]`.
pub const CONF_LEN: usize = 1 + 4 * N_STATUS;

/// One status's configurable look. `color` is a `0..=7` palette index (`0` = off).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatusCfg {
    pub effect: u8,
    pub color: u8,
    pub brightness: u8,
    pub speed: u8,
}

/// The whole `EF_LED_CONF` block as a plain struct: a global `steady` flag plus
/// one [`StatusCfg`] per device status.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LedConfig {
    pub steady: bool,
    pub status: [StatusCfg; N_STATUS],
}

impl LedConfig {
    /// Pack into the current 17-byte wire block. `color` is masked to its low 3
    /// bits so the encoding is canonical regardless of any stray high bits.
    pub fn encode(&self) -> [u8; CONF_LEN] {
        let mut b = [0u8; CONF_LEN];
        b[0] = self.steady as u8;
        for (i, s) in self.status.iter().enumerate() {
            b[1 + 4 * i] = s.effect;
            b[2 + 4 * i] = s.color & 0x7;
            b[3 + 4 * i] = s.brightness;
            b[4 + 4 * i] = s.speed;
        }
        b
    }

    /// Overlay a stored / `SET LED` block onto `self`. A field absent from a
    /// shorter (older-firmware) block keeps its current value, so an upgrade
    /// preserves the look. Four formats, longest first:
    ///
    /// | Length | Layout |
    /// |--------|--------|
    /// | 17+   | `[steady, (effect, color, brightness, speed) × N]` — current |
    /// | 13–16 | `[steady, (effect, color, brightness) × N]` — pre-speed |
    /// | 7–12  | `[steady, (color, brightness) × N]` — pre-effect |
    /// | 2–3   | `[brightness, idle_color[, steady]]` — idle-only legacy |
    ///
    /// A block shorter than 2 bytes is ignored (leaves `self` unchanged).
    pub fn apply_block(&mut self, b: &[u8]) {
        if b.len() >= CONF_LEN {
            // Current: [steady, (effect, color, brightness, speed) × N]
            self.steady = b[0] != 0;
            for (i, s) in self.status.iter_mut().enumerate() {
                s.effect = b[1 + 4 * i];
                s.color = b[2 + 4 * i] & 0x7;
                s.brightness = b[3 + 4 * i];
                s.speed = b[4 + 4 * i];
            }
        } else if b.len() >= 13 {
            // Pre-speed: [steady, (effect, color, brightness) × N]; speed kept.
            self.steady = b[0] != 0;
            for (i, s) in self.status.iter_mut().enumerate() {
                s.effect = b[1 + 3 * i];
                s.color = b[2 + 3 * i] & 0x7;
                s.brightness = b[3 + 3 * i];
            }
        } else if b.len() >= 7 {
            // Pre-effect: [steady, (color, brightness) × N]; effect + speed kept.
            self.steady = b[0] != 0;
            let n = (b.len() - 1) / 2;
            for (i, s) in self.status.iter_mut().enumerate().take(n.min(N_STATUS)) {
                s.color = b[1 + 2 * i] & 0x7;
                s.brightness = b[2 + 2 * i];
            }
        } else if b.len() >= 2 {
            // Idle-only legacy: [brightness, idle_color[, steady]].
            self.status[0].brightness = b[0];
            self.status[0].color = b[1] & 0x7;
            if b.len() >= 3 {
                self.steady = b[2] != 0;
            }
        }
    }
}

/// Clamp a runtime LED count to the firmware's compile-time `MAX_LEDS` ceiling.
///
/// The count originates in the host/PicoForge-writable phy record, which persists
/// across factory resets, so an over-large value must **saturate**, never panic
/// the boot path (a panic there would re-fire every reboot — an unrecoverable
/// loop). Lighting all `max` LEDs is the safe degradation. See
/// `firmware/src/led.rs::set_runtime_leds`.
pub fn clamp_leds(n: u8, max: u8) -> u8 {
    n.min(max)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `apply_block(encode()) == id` for every well-formed config (color is the
    /// only constrained field: it is a 3-bit palette index by construction).
    #[kani::proof]
    fn encode_apply_block_roundtrip() {
        let any_status = || StatusCfg {
            effect: kani::any(),
            color: kani::any::<u8>() & 0x7,
            brightness: kani::any(),
            speed: kani::any(),
        };
        let cfg = LedConfig {
            steady: kani::any(),
            status: [any_status(), any_status(), any_status(), any_status()],
        };
        let mut got = LedConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LedConfig {
        LedConfig {
            steady: true,
            status: [
                StatusCfg {
                    effect: 1,
                    color: 2,
                    brightness: 16,
                    speed: 0,
                },
                StatusCfg {
                    effect: 3,
                    color: 2,
                    brightness: 32,
                    speed: 5,
                },
                StatusCfg {
                    effect: 2,
                    color: 4,
                    brightness: 64,
                    speed: 0,
                },
                StatusCfg {
                    effect: 4,
                    color: 1,
                    brightness: 8,
                    speed: 200,
                },
            ],
        }
    }

    #[test]
    fn conf_len_matches_layout() {
        assert_eq!(CONF_LEN, 17);
        assert_eq!(CONF_LEN, 1 + 4 * N_STATUS);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let cfg = sample();
        let mut got = LedConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(got, cfg);
    }

    #[test]
    fn encode_layout_is_steady_then_quads() {
        let b = sample().encode();
        assert_eq!(b.len(), 17);
        assert_eq!(b[0], 1); // steady
        // touch (status index 2): effect, color, brightness, speed at 1+4*2 = 9..13
        assert_eq!(&b[9..13], &[2, 4, 64, 0]);
    }

    #[test]
    fn color_is_masked_to_low_three_bits() {
        let mut cfg = LedConfig::default();
        let mut b = [0u8; CONF_LEN];
        b[2] = 0xFA; // idle color slot; 0xFA & 0x7 == 2
        cfg.apply_block(&b);
        assert_eq!(cfg.status[0].color, 0x2);
        // and encode re-masks rather than leaking high bits
        cfg.status[1].color = 0xFF;
        // status 1 (processing) color byte sits at index 2 + 4 = 6
        assert_eq!(cfg.encode()[6], 0x7);
    }

    #[test]
    fn pre_speed_13_byte_block_keeps_current_speed() {
        let mut cfg = sample(); // speeds 0, 5, 0, 200
        let mut b = [0u8; 13]; // [steady, (effect, color, brightness) × 4]
        b[0] = 0;
        for i in 0..N_STATUS {
            b[1 + 3 * i] = 0; // effect legacy
            b[2 + 3 * i] = 1; // color red
            b[3 + 3 * i] = 100; // brightness
        }
        cfg.apply_block(&b);
        assert!(!cfg.steady);
        for s in &cfg.status {
            assert_eq!((s.effect, s.color, s.brightness), (0, 1, 100));
        }
        assert_eq!(cfg.status[1].speed, 5); // preserved
        assert_eq!(cfg.status[3].speed, 200); // preserved
    }

    #[test]
    fn pre_effect_9_byte_block_keeps_current_effect_and_speed() {
        let mut cfg = sample(); // effects 1,3,2,4 ; speeds 0,5,0,200
        let mut b = [0u8; 9]; // [steady, (color, brightness) × 4]
        b[0] = 1;
        for i in 0..N_STATUS {
            b[1 + 2 * i] = 3; // color blue
            b[2 + 2 * i] = 50; // brightness
        }
        cfg.apply_block(&b);
        assert!(cfg.steady);
        for s in &cfg.status {
            assert_eq!((s.color, s.brightness), (3, 50));
        }
        assert_eq!(cfg.status[0].effect, 1); // preserved
        assert_eq!(cfg.status[3].effect, 4); // preserved
        assert_eq!(cfg.status[3].speed, 200); // preserved
    }

    #[test]
    fn legacy_2_byte_block_maps_onto_idle_only() {
        let mut cfg = sample();
        let processing_before = cfg.status[1];
        cfg.apply_block(&[80, 0x0C]); // brightness 80, color 0x0C & 7 = 4 onto idle
        assert_eq!(cfg.status[0].brightness, 80);
        assert_eq!(cfg.status[0].color, 4);
        assert_eq!(cfg.status[1], processing_before); // others untouched
    }

    #[test]
    fn legacy_3_byte_block_sets_steady() {
        let mut cfg = LedConfig::default();
        cfg.apply_block(&[10, 2, 1]);
        assert!(cfg.steady);
        assert_eq!((cfg.status[0].brightness, cfg.status[0].color), (10, 2));
    }

    #[test]
    fn too_short_block_is_ignored() {
        let mut cfg = sample();
        let before = cfg;
        cfg.apply_block(&[]);
        cfg.apply_block(&[7]);
        assert_eq!(cfg, before);
    }

    #[test]
    fn block_longer_than_conf_len_reads_the_known_prefix() {
        // A future, longer block still loads its first 17 bytes (the >= branch).
        let cfg = sample();
        let mut b = [0u8; 21];
        b[..CONF_LEN].copy_from_slice(&cfg.encode());
        let mut got = LedConfig::default();
        got.apply_block(&b);
        assert_eq!(got, cfg);
    }

    #[test]
    fn clamp_leds_saturates_to_ceiling() {
        assert_eq!(clamp_leds(4, 8), 4);
        assert_eq!(clamp_leds(8, 8), 8);
        assert_eq!(clamp_leds(99, 8), 8); // the brick-fix invariant: no panic, saturate
        assert_eq!(clamp_leds(0, 8), 0);
    }
}
