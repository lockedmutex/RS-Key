// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Parsing a CST328 capacitive-touch report into a panel coordinate. Pure and
//! host-tested: the firmware's `display.rs` does the I2C transfer (read the report
//! block at register 0xD000) and hands the raw bytes here, so the bit-twiddling
//! that turns a report into the point [`crate::hit_confirm`] will judge sits under
//! test rather than buried in the driver — a wrong reconstruction maps a tap to
//! the wrong button.

use crate::Point;

/// Finger-1 status nibble (CST328 register 0xD000, low 4 bits) meaning a finger
/// is down.
const FINGER_DOWN: u8 = 0x06;

/// Parse a CST328 report block read starting at register 0xD000, returning the
/// first active finger's coordinate or `None` (no finger down, or a short block).
///
/// Byte layout returned by the controller from 0xD000: `[0]` finger-1 status,
/// `[1]` X high 8 bits, `[2]` Y high 8 bits, `[3]` X low 4 bits (upper nibble) |
/// Y low 4 bits (lower nibble). Both axes are 12-bit. The coordinate is in the
/// controller's own axes; `display.rs` applies any panel rotation/flip.
pub fn parse_cst328(report: &[u8]) -> Option<Point> {
    if report.len() < 4 || report[0] & 0x0F != FINGER_DOWN {
        return None;
    }
    let x = ((report[1] as u16) << 4) | ((report[3] as u16) >> 4);
    let y = ((report[2] as u16) << 4) | ((report[3] as u16) & 0x0F);
    Some(Point::new(x, y))
}

#[cfg(test)]
#[path = "touch_tests.rs"]
mod tests;
