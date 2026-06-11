// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the HMAC-DRBG: arbitrary seeds / reseeds / output lengths must terminate
//! without panicking, fully fill the request, and stay deterministic for a fixed
//! seed — the property the keygen / signing-nonce randomness relies on.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::HmacDrbg;

fuzz_target!(|data: &[u8]| {
    // First byte picks an output length 0..=255; the rest is the seed.
    let (len, seed) = data
        .split_first()
        .map_or((0usize, data), |(n, s)| (*n as usize, s));

    // Determinism: two instances from the same seed yield the same stream.
    let mut a = HmacDrbg::new(seed);
    let mut b = HmacDrbg::new(seed);
    let mut out_a = [0u8; 256];
    let mut out_b = [0u8; 256];
    a.fill(&mut out_a[..len]);
    b.fill(&mut out_b[..len]);
    assert_eq!(out_a[..len], out_b[..len]);

    // Reseed with the same material and keep drawing — must not panic.
    a.reseed(seed);
    let mut more = [0u8; 64];
    a.fill(&mut more);
});
