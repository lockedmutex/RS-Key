// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `xfr_apdu` / `secure_apdu` never panic on any host message and always return
/// a range *inside* the message — `HEADER <= start <= end <= msg.len()` — so the
/// caller can slice `msg[start..end]` (the untrusted APDU payload) without its
/// own bounds check. The `dw.min(msg.len() - HEADER)` clamp is what guarantees it.
#[kani::proof]
fn xfr_and_secure_apdu_ranges_stay_in_bounds() {
    let buf: [u8; HEADER + 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let msg = &buf[..len];
    if let Some((s, e)) = xfr_apdu(msg) {
        assert_eq!(s, HEADER);
        assert!(s <= e && e <= len);
    }
    if let Some((s, e)) = secure_apdu(msg) {
        assert_eq!(s, HEADER);
        assert!(s <= e && e <= len);
    }
}
