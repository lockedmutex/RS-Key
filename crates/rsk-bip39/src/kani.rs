// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Every index [`entropy_to_indices`] returns is `< 2048`, so [`word`]/[`WORDS`]
/// indexing can never go out of bounds for any seed.
#[kani::proof]
fn indices_in_range() {
    let entropy: [u8; 32] = kani::any();
    // Model the checksum as an arbitrary byte: the proof is about the bit-packing,
    // not SHA-256 (whose output is some byte, already covered by `any`).
    let checksum: u8 = kani::any();
    let bit = |b: usize| -> u16 {
        let byte = if b < 256 { entropy[b / 8] } else { checksum };
        ((byte >> (7 - (b % 8))) & 1) as u16
    };
    let mut i = 0;
    while i < WORD_COUNT {
        let mut v = 0u16;
        let mut j = 0;
        while j < 11 {
            v = (v << 1) | bit(i * 11 + j);
            j += 1;
        }
        assert!((v as usize) < WORDS.len());
        i += 1;
    }
}
