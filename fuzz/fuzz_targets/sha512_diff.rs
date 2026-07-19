// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Differential fuzz: `rsk-sha512`'s fast rolled compression must stay
//! byte-identical to the vetted `sha2` soft backend on ANY input — that identity
//! is the whole license for swapping it into the FIDO key-derivation ratchet. We
//! check the one-shot digest for both widths and a fuzzer-chunked streaming run
//! against the reference (a block-buffer bug would diverge only across a
//! block/padding boundary the chunk split straddles).

use libfuzzer_sys::fuzz_target;
use sha2::Digest;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        rsk_sha512::Sha512::digest(data)[..],
        sha2::Sha512::digest(data)[..],
    );
    assert_eq!(
        rsk_sha512::Sha384::digest(data)[..],
        sha2::Sha384::digest(data)[..],
    );

    // Streaming in fuzzer-chosen chunk sizes must equal the one-shot digest.
    let mut ours = rsk_sha512::Sha512::new();
    let mut reff = sha2::Sha512::new();
    let mut rest = data;
    let mut guard = 0u32;
    while !rest.is_empty() && guard < 8192 {
        let step = (1 + rest[0] as usize % 200).min(rest.len());
        ours.update(&rest[..step]);
        reff.update(&rest[..step]);
        rest = &rest[step..];
        guard += 1;
    }
    assert_eq!(ours.finalize()[..], reff.finalize()[..]);
});
