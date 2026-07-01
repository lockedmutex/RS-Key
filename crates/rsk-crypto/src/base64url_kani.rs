// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `decoded_len` never panics (the `out - pad` cannot underflow), rejects
/// exactly the malformed `n % 4 == 1` lengths, and never claims more output
/// than input — for every char count up to 64 KiB.
#[kani::proof]
fn decoded_len_safe() {
    let n: usize = kani::any();
    kani::assume(n <= (1 << 16));
    match decoded_len(n) {
        Ok(out) => assert!(out <= n),
        Err(_) => assert!(n % 4 == 1),
    }
}

/// `encoded_len` never overflows, always expands, and is the exact inverse
/// of `decoded_len` — for every byte count up to 64 KiB.
#[kani::proof]
fn encoded_len_roundtrips() {
    let n: usize = kani::any();
    kani::assume(n <= (1 << 16));
    let e = encoded_len(n);
    assert!(e >= n);
    assert_eq!(decoded_len(e), Ok(n));
}

/// `encode` then `decode` is the identity for EVERY input up to 9 bytes
/// (three full chunks — every `len % 3` tail, preceded by both none and
/// some full chunks), and `encode` returns exactly `encoded_len`. The
/// successful decode doubles as proof that `encode` only emits the URL
/// alphabet — `decode` rejects anything else.
#[kani::proof]
#[kani::unwind(14)]
fn encode_decode_roundtrip() {
    const N: usize = 9;
    let src: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    let mut enc = [0u8; 12]; // encoded_len(9)
    let en = encode(&mut enc, &src[..n]).unwrap();
    assert_eq!(en, encoded_len(n));
    let mut dec = [0u8; N];
    let dn = decode(&mut dec, &enc[..en]).unwrap();
    assert_eq!(dn, n);
    assert_eq!(&dec[..dn], &src[..n]);
}

/// `decode` over EVERY byte string up to 8 chars: never panics (the
/// output index stays inside the buffer for any mix of valid chars and
/// `=`), and what it writes never exceeds `decoded_len`.
#[kani::proof]
#[kani::unwind(10)]
fn decode_any_input_safe() {
    const N: usize = 8;
    let src: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    let mut dst = [0u8; 6]; // decoded_len(8)
    if let Ok(w) = decode(&mut dst, &src[..n]) {
        assert!(w <= decoded_len(n).unwrap());
    }
}
