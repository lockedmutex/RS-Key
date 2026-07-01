// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::{parse_ehl_body, parse_ehl_head, tag_len};
use crate::consts::{EF_PK_AUT, EF_PK_DEC, EF_PK_SIG};

/// `tag_len` never panics on any bytes/position; on success it advances `pos`
/// by the 1..=3 in-bounds bytes of the BER length field.
#[kani::proof]
fn tag_len_total() {
    const N: usize = 5;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    let start: usize = kani::any();
    kani::assume(n <= N);
    kani::assume(start <= n);
    let mut pos = start;
    if tag_len(&data[..n], &mut pos).is_some() {
        assert!(pos >= start + 1 && pos <= start + 3);
        assert!(pos <= n); // every byte it consumed was in bounds
    }
}

/// Parsing the `4D … CRT` header never panics; a success selects one of the
/// three key slots.
#[kani::proof]
fn parse_ehl_head_total() {
    const N: usize = 8;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    if let Ok((fid, _)) = parse_ehl_head(&data[..n]) {
        assert!(fid == EF_PK_SIG || fid == EF_PK_DEC || fid == EF_PK_AUT);
    }
}

/// Walking the `7F48` template + `5F48` key data never panics and always
/// terminates, for any start position and any bytes.
#[kani::proof]
#[kani::unwind(12)]
fn parse_ehl_body_total() {
    const N: usize = 14;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    let pos: usize = kani::any();
    kani::assume(n <= N);
    kani::assume(pos <= n);
    let _ = parse_ehl_body(&data[..n], pos);
}
