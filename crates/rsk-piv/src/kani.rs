// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// [`pivman_set_protected`] on ANY prior record (up to a bound past every
/// tag/length form) never panics and always emits a well-formed, protected
/// PivmanData carrying no salt: the output is `80 <n> { 81 01 <flags> [83 ..] }`
/// with the `0x02` flag set, and the second sub-TLV (if any) is the timestamp,
/// never the `0x82` salt.
#[kani::proof]
#[kani::unwind(20)]
fn set_protected_total_and_invariant() {
    let len: usize = kani::any();
    kani::assume(len <= 18);
    let mut prior = [0u8; 18];
    for b in prior[..len].iter_mut() {
        *b = kani::any();
    }
    let mut out = [0u8; PIVMAN_MAX];
    let n = pivman_set_protected(&prior[..len], &mut out);

    // A well-formed outer object whose declared length matches what we wrote.
    assert!((5..=PIVMAN_MAX).contains(&n));
    assert_eq!(out[0], PIVMAN_TAG);
    assert_eq!(out[1] as usize, n - 2);
    let body = &out[2..n];

    // Flags TLV first, protected bit forced on.
    assert_eq!(body[0], PIVMAN_FLAGS_TAG);
    assert_eq!(body[1], 0x01);
    assert!(body[2] & PIVMAN_FLAG_MGM_PROTECTED != 0);
    // The only other sub-TLV the encoder ever emits is the timestamp — so a
    // body past the 3-byte flags TLV starts with `0x83`, never the salt `0x82`.
    if body.len() > 3 {
        assert_eq!(body[3], PIVMAN_TS_TAG);
    }
}
