// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// [`assemble_verify`] never panics and, on success, writes a self-consistent
/// APDU wholly inside `out`: the returned length is `5 + Lc`, within `out`, and
/// `out[4]` (Lc) equals the body length — for any template / PIN / buffer sizes.
#[kani::proof]
fn assemble_verify_never_writes_out_of_bounds() {
    let tbuf: [u8; 5] = kani::any();
    let tlen: usize = kani::any();
    kani::assume(tlen <= tbuf.len());
    let pbuf: [u8; 8] = kani::any();
    let plen: usize = kani::any();
    kani::assume(plen <= pbuf.len());
    let mut obuf = [0u8; 16];
    let olen: usize = kani::any();
    kani::assume(olen <= obuf.len());

    if let Some(n) = assemble_verify(&tbuf[..tlen], &pbuf[..plen], &mut obuf[..olen]) {
        assert!((5..=olen).contains(&n));
        assert_eq!(n, obuf[4] as usize + 5);
    }
}

/// [`parse_secure`] never panics on host bytes; a parsed template is a suffix of
/// the input at least 4 bytes long (a bare `CLA INS P1 P2`).
#[kani::proof]
fn parse_secure_is_total() {
    let buf: [u8; APDU_TEMPLATE_OFFSET + 5] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    if let Some(req) = parse_secure(&buf[..len]) {
        assert!(req.apdu_template.len() >= 4);
        assert!(req.apdu_template.len() <= len);
    }
}
