// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `rebuild_meta` walks persisted — possibly corrupt — flash contents.
/// For ANY blob up to 16 bytes (several records' worth, every truncation),
/// any record to drop, and any record to append into a too-small output:
/// no panic, no out-of-bounds write, and the reported length fits.
#[kani::proof]
#[kani::unwind(6)]
fn rebuild_meta_any_blob() {
    const B: usize = 16;
    let blob: [u8; B] = kani::any();
    let bn: usize = kani::any();
    kani::assume(bn <= B);
    let fid: u16 = kani::any();
    let data: [u8; 4] = kani::any();
    let dn: usize = kani::any();
    kani::assume(dn <= 4);
    let with_new: bool = kani::any();
    let new = if with_new { Some(&data[..dn]) } else { None };
    // Smaller than the worst-case rebuild → the NoMemory arms are reachable.
    let mut out = [0u8; 8];
    if let Ok(w) = rebuild_meta(&blob[..bn], fid, new, &mut out) {
        assert!(w <= out.len());
    }
}
