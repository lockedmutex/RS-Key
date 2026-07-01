// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Walking ANY byte sequence (up to 16 bytes — past every tag/length form
/// with room for several nested objects) never panics, never overflows, and
/// always terminates; every yielded value lies inside the input.
#[kani::proof]
#[kani::unwind(18)]
fn walk_any_input() {
    const N: usize = 16;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    for (_tag, value) in Tlv::new(&data[..n]) {
        assert!(value.len() <= n);
    }
}

/// `format_len` writes exactly `format_len_size` bytes, and the encoding
/// decodes back to `len` under the same rules `Tlv::next` uses — for EVERY
/// `u16` length.
#[kani::proof]
fn format_len_roundtrip() {
    let len: u16 = kani::any();
    let mut buf = [0u8; 3];
    let n = format_len(len, &mut buf);
    assert_eq!(n, format_len_size(len));
    let (decoded, consumed) = match buf[0] {
        0x82 => (((buf[1] as usize) << 8) | buf[2] as usize, 3),
        0x81 => (buf[1] as usize, 2),
        b => (b as usize, 1),
    };
    assert_eq!(consumed, n);
    assert_eq!(decoded, len as usize);
}
