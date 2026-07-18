// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the PIV trusted-display readers (`rsk_piv::info`) over a HOSTILE flash:
//! crafted per-slot metadata, certificates and an `EF_RETRIES` blob an attacker
//! could plant via a flash snapshot. These run PIN-free for the on-device screen,
//! so they must never panic on arbitrary stored bytes, and the slot count they
//! report must stay bounded (`populated <= 4`, `read_extra <= MAX_EXTRA_SLOTS`).

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_piv::files::{EF_RETRIES, cert_fid_for_slot, key_fid};
use rsk_piv::info::{MAX_EXTRA_SLOTS, PRIMARY_SLOTS, PivSlot, read_extra, read_info, read_slot};

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();

    // Walk the input as [slot][flags][meta_len][meta…] records: plant a key
    // (making `has_key` true, per info_tests), a crafted meta side-record, and/or
    // a cert for arbitrary slot references.
    let mut rest = data;
    while rest.len() >= 3 {
        let slot = rest[0];
        let flags = rest[1];
        let mlen = (rest[2] as usize).min(rest.len() - 3).min(8);
        let meta = &rest[3..3 + mlen];
        if flags & 1 == 1 {
            let _ = fs.put(key_fid(slot).get(), &[0xAB; 8]);
        }
        if flags & 2 == 2 {
            let _ = fs.meta_add(key_fid(slot).get(), meta);
        }
        if flags & 4 == 4
            && let Some(cf) = cert_fid_for_slot(slot)
        {
            let _ = fs.put(cf, &[0x30, 0x00]);
        }
        rest = &rest[3 + mlen..];
    }
    if let Some(&b) = data.first() {
        let _ = fs.put(EF_RETRIES, &[b, b, b, b]);
    }

    let info = read_info(&mut fs);
    assert!(info.populated() as usize <= PRIMARY_SLOTS.len());
    for &s in &PRIMARY_SLOTS {
        let _ = read_slot(&mut fs, s);
    }
    let mut extra = [PivSlot::default(); MAX_EXTRA_SLOTS];
    let n = read_extra(&mut fs, &mut extra);
    assert!(n <= MAX_EXTRA_SLOTS);
});
