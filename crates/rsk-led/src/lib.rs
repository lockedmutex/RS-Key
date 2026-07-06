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

/// The flash FID that persists the config block — outside both reset scopes
/// (sticky). Single-sourced here so the firmware LED applet and the FIDO
/// `CONFIG_WRITE`/`CONFIG_READ` LED target agree on where it lives.
pub const EF_LED_CONF: u16 = 0x1123;

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
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
