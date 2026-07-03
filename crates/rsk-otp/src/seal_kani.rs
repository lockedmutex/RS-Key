// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{CONFIG_SIZE, SLOT_SIZE};

/// Migration invariant (`crate::migrate_seal`): a stored blob whose length is
/// in `CONFIG_SIZE..=SLOT_SIZE` is taken to be legacy plaintext and re-sealed.
/// A blob this module produced is `nonce(12) ‖ ct ‖ tag(16)` over a real slot
/// plaintext (`CONFIG_SIZE..=SLOT_SIZE`), so its length must fall OUTSIDE that
/// range — otherwise the guard would double-seal (destroy) an already-sealed
/// slot. Proven for every plaintext length.
#[kani::proof]
fn sealed_length_never_looks_like_plaintext() {
    let plain: usize = kani::any();
    kani::assume((CONFIG_SIZE..=SLOT_SIZE).contains(&plain));
    let sealed = NONCE_LEN + plain + TAG_LEN;
    assert!(!(CONFIG_SIZE..=SLOT_SIZE).contains(&sealed));
}
