// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the ISO-7816 APDU parser — it sees untrusted host input over
//! CTAPHID/CCID and must never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rsk_sdk::Apdu::parse(data);
});
