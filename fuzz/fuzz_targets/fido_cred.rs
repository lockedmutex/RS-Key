// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the credential-box parser: an arbitrary cred_id (attacker-controlled in
//! getAssertion / excludeList) must never panic in verify/decrypt/length logic.
//! Unauthenticated input must not decode to a credential.

use libfuzzer_sys::fuzz_target;
use rsk_fido::credential::credential_load;

fuzz_target!(|data: &[u8]| {
    let seed = [0x42u8; 32];
    let rp_hash = [0x99u8; 32];
    let mut scratch = [0u8; 2048];
    // Arbitrary bytes are not a valid AEAD box, so this must return None, never panic.
    assert!(credential_load(&seed, data, &rp_hash, &mut scratch).is_none());
});
