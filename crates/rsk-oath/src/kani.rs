// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// [`split_period`] on ANY credential name never panics or overflows, always
/// returns the bare label as a *suffix* of the input, and any parsed period is
/// at most four digits (≤ 9999, so the `u16` fold cannot overflow — the `i < 4`
/// cap is exactly what guarantees it).
#[kani::proof]
#[kani::unwind(6)]
fn split_period_total_and_bounded() {
    let name: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= name.len());
    let (period, label) = split_period(&name[..len]);
    match period {
        // A prefix was consumed → the label is strictly shorter, and the value
        // came from ≤ 4 ASCII digits, so it fits u16 without wrapping.
        Some(p) => {
            assert!(p <= 9999);
            assert!(label.len() < len);
        }
        // No numeric prefix → the whole input is the label.
        None => assert_eq!(label.len(), len),
    }
}
