// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CRC-32 with the reflected `0xEDB88320` polynomial — **standard CRC-32**
//! (zlib/PNG), not CRC-32C/Castagnoli; stored and on-the-wire values depend on
//! this exact variant.

const POLY: u32 = 0xedb8_8320;

/// CRC-32 of `buf` (init `0xFFFFFFFF`, reflected, final XOR `0xFFFFFFFF`).
pub fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in buf {
        crc ^= byte as u32;
        for _ in 0..8 {
            // `POLY & (0 - (crc & 1))`: mask is all-ones iff the low bit is set.
            crc = (crc >> 1) ^ (POLY & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
#[path = "crc_tests.rs"]
mod tests;
