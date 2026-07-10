// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// The `--once` path prints device-controlled getInfo/identity text raw (no
// ratatui cell grid to neutralise it), so `sanitize` is the one boundary
// between a counterfeit device and the operator's terminal.

#[test]
fn sanitize_strips_ansi_osc_escapes() {
    // ESC (0x1b) + BEL (0x07): OSC window-title, CSI clear, OSC-52 clipboard.
    let out = sanitize("\u{1b}]0;pwn\u{07}\u{1b}[2Jok\u{1b}]52;c;AAAA\u{07}");
    assert!(!out.contains('\u{1b}') && !out.contains('\u{07}'));
    assert!(out.ends_with("ok\u{fffd}]52;c;AAAA\u{fffd}"));
}

#[test]
fn sanitize_strips_bidi_override() {
    // U+202E RIGHT-TO-LEFT OVERRIDE and the isolates are Cf, not Cc, so
    // `char::is_control()` alone would let this Trojan-Source reorder pass.
    for c in ['\u{202E}', '\u{202A}', '\u{2066}', '\u{2069}', '\u{200F}'] {
        assert_eq!(sanitize(&c.to_string()), "\u{fffd}");
    }
}

#[test]
fn sanitize_preserves_benign_text() {
    assert_eq!(sanitize("FIDO_2_0, U2F_V2"), "FIDO_2_0, U2F_V2");
}
