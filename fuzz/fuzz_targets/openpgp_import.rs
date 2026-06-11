// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the OpenPGP IMPORT extended-header-list parser (`cmd_import_data`): the
//! command body is attacker-controlled TLV with explicit lengths, so the parser
//! must never panic — it can only return a status word. We drive both halves
//! (`parse_ehl_head`, then `parse_ehl_body` from the head's end position).

use libfuzzer_sys::fuzz_target;
use rsk_openpgp::importdata::{parse_ehl_body, parse_ehl_head};

fuzz_target!(|data: &[u8]| {
    if let Ok((_fid, pos)) = parse_ehl_head(data) {
        let _ = parse_ehl_body(data, pos);
    }
});
