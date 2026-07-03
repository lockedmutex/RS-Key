// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Every word index [`encode_share`] produces is `< 1024`, so [`word`]/[`WORDS`] indexing
/// can never go out of bounds, for any identifier / threshold / index / value.
#[kani::proof]
fn indices_in_range() {
    let identifier: u16 = kani::any();
    let threshold: u8 = kani::any();
    let index: u8 = kani::any();
    let value: [u8; SECRET_LEN] = kani::any();
    kani::assume(threshold >= 1 && threshold <= MAX_SHARES as u8);
    let w = encode_share(identifier & 0x7fff, threshold, index, &value);
    let mut i = 0;
    while i < WORDS_PER_SHARE {
        assert!((w[i] as usize) < WORDS.len());
        i += 1;
    }
}
