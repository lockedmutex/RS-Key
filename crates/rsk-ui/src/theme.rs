// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display colour palette — one place so every screen speaks the same
//! visual language. Tuned for the ST7789 IPS panel (true-black background, a cyan
//! accent, calm sea-green / indian-red for the affirm / deny pair). Values are
//! `Rgb565` (the panel's native format); the `#rrggbb` in each comment is the
//! 8-bit source the 5/6/5 channels are quantised from.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::{RgbColor, WebColors};

/// Panel background — true black (OLED-style, and the cheapest pixel to clear to).
pub const PANEL_BG: Rgb565 = Rgb565::BLACK;
/// A lifted card / list-row surface, just above the background. `#12151a`.
pub const ROW_BG: Rgb565 = Rgb565::new(2, 5, 3);
/// The bottom navigation bar surface. `#0b0d10`.
pub const NAV_BG: Rgb565 = Rgb565::new(1, 3, 2);
/// A tappable key / control surface (PIN-pad keys, the settings −/+ steppers) — a
/// dark **neutral** card. Kept tint-free on purpose: the panel's gamma lifts a
/// blue-ish dark grey into a too-bright blue, so the keys read neutral with
/// [`KEY_BORDER`] giving the edge. `#181818`.
pub const KEY_BG: Rgb565 = Rgb565::new(3, 6, 3);
/// The subtle edge around a key card — so a dark key still reads as pressable on the
/// black panel (the keypad look from the design mockup). `#424242`.
pub const KEY_BORDER: Rgb565 = Rgb565::new(8, 16, 8);
/// Primary text — near-white.
pub const TEXT: Rgb565 = Rgb565::WHITE;
/// Secondary / muted text and inactive glyphs. Slate gray `#708090`.
pub const MUTED: Rgb565 = Rgb565::CSS_SLATE_GRAY;
/// Brand accent: the active nav tab, headings, the "Ready" state. Cyan `#34b6d4`.
pub const ACCENT: Rgb565 = Rgb565::new(6, 45, 26);
/// Affirmative action (Approve / OK key). Sea green `#2e8b57`.
pub const APPROVE: Rgb565 = Rgb565::CSS_SEA_GREEN;
/// Destructive / refusing action (Deny / Cancel / Delete). Indian red `#cd5c5c`.
pub const DENY: Rgb565 = Rgb565::CSS_INDIAN_RED;
/// Caution — warnings and "needs review" status. Amber `#d6a23c`.
pub const WARN: Rgb565 = Rgb565::new(26, 40, 7);
/// Healthy status badge ("OK"). `#3fa86b`.
pub const OK: Rgb565 = Rgb565::new(7, 41, 13);
/// Inactive bottom-nav glyph (dimmer than `MUTED`). `#4a525c`.
pub const NAV_INACTIVE: Rgb565 = Rgb565::new(9, 20, 11);
/// Hairline separators (nav top edge, row dividers). `#1a1d22`.
pub const HAIRLINE: Rgb565 = Rgb565::new(3, 7, 4);
