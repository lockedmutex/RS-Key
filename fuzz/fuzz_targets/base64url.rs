// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz base64url: decoding arbitrary input must never panic, and any byte string
//! must survive an encode → decode round-trip unchanged.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::base64url;

fuzz_target!(|data: &[u8]| {
    // Decode arbitrary (attacker-controlled) input — must not panic.
    let mut dbuf = [0u8; 8192];
    let _ = base64url::decode(&mut dbuf, data);

    // Round-trip: encode a bounded prefix, then decode it back.
    let src = &data[..data.len().min(1024)];
    let mut ebuf = [0u8; 1400]; // encoded_len(1024) = 1366
    let en = base64url::encode(&mut ebuf, src).expect("dst large enough");
    let mut back = [0u8; 1024];
    let dn = base64url::decode(&mut back, &ebuf[..en]).expect("self-encoded is valid");
    assert_eq!(&back[..dn], src);
});
