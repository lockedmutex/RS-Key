// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{CONFIG_SIZE, SLOT_SIZE};

/// The concrete twin of the Kani `sealed_length_never_looks_like_plaintext`
/// proof — the plaintext domain is tiny (`CONFIG_SIZE..=SLOT_SIZE`), so an
/// exhaustive check pins the migrate_seal length guard in the normal gate too.
#[test]
fn sealed_length_never_looks_like_plaintext_exhaustive() {
    for plain in CONFIG_SIZE..=SLOT_SIZE {
        let sealed = NONCE_LEN + plain + TAG_LEN;
        assert!(
            !(CONFIG_SIZE..=SLOT_SIZE).contains(&sealed),
            "sealed len {sealed} for plaintext {plain} collides with the plaintext range \
             — migrate_seal would double-seal an already-sealed slot"
        );
    }
}
