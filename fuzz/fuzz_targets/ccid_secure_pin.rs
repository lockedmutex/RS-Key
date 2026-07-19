// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CCID secure-PIN codec (`rsk_usb::secure_pin`): `parse_secure` over a
//! host-controlled `abPINDataStructure`, then `assemble_verify` building the
//! plaintext VERIFY APDU beside the (trusted, on-pad) PIN. The host bytes are
//! untrusted, so beyond not-panicking the decoded lengths must stay
//! self-consistent and in-bounds: the parsed template is the fixed-offset suffix,
//! and the assembled length equals its own encoded `Lc` plus the 5-byte header.

use libfuzzer_sys::fuzz_target;
use rsk_usb::secure_pin::{MAX_PIN, assemble_verify, parse_secure};

fuzz_target!(|data: &[u8]| {
    // First byte = PIN length; the rest is the host `abPINDataStructure`.
    let Some((&plen, abdata)) = data.split_first() else {
        return;
    };
    let plen = (plen as usize).min(abdata.len()).min(MAX_PIN);
    let pin = &abdata[..plen];

    if let Some(req) = parse_secure(abdata) {
        // parse_secure only returns a template of at least a 4-byte APDU header.
        assert!(req.apdu_template.len() >= 4);

        // Assemble into a fuzzer-varied buffer that straddles the `5 + body > out`
        // guard (min length 5, so an empty-PIN OpenPGP VERIFY still just fits).
        let out_cap = 5 + abdata.len() % 130;
        let mut out = [0u8; 5 + 129];
        if let Some(n) = assemble_verify(req.apdu_template, pin, &mut out[..out_cap]) {
            assert!(n <= out_cap);
            assert_eq!(n, out[4] as usize + 5); // n == Lc + header
            assert!(pin.len() <= out[4] as usize); // body is padded, never truncated
        }
    }
});
