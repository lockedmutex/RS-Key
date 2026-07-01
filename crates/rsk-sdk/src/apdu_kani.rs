// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Parsing ANY buffer up to 20 bytes (long enough to reach every of the
/// ISO-7816 case-1..4 branches, short and extended, with a few body bytes
/// past the extended Lc/Le markers) never panics, and a successful parse
/// upholds the struct's invariants: `data` is the `nc` bytes it claims to
/// be, and `ne` never exceeds the extended-length ceiling. Extended bodies
/// longer than the bound are exercised by the fuzz target instead.
#[kani::proof]
fn parse_any_buffer() {
    const N: usize = 20;
    let buf: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    if let Ok(a) = Apdu::parse(&buf[..n]) {
        assert_eq!(a.nc, a.data.len());
        assert!(a.nc <= n);
        assert!(a.ne <= 65536);
    }
}
