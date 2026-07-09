// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fuzz the trusted-display trust boundary — 100% unfuzzed until now. `Label`
//! turns attacker-controlled relying-party text (rpId, account name) into the
//! printable ASCII shown on the on-device Allow/Deny screen. `Label::clamp` /
//! `clamp_domain` must be total (no input panics) and emit ONLY bytes in
//! `0x20..=0x7E` — the invariant that defeats terminal escapes and bidi /
//! homoglyph spoofing (audit run-11/run-12). Then rendering a `Screen::Confirm`
//! built from those labels must not panic — that drives the head/tail
//! `text_*_ellipsized` byte-index math run-11 touched.

#![no_main]

use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::Rgb565,
};
use libfuzzer_sys::fuzz_target;
use rsk_ui::{ConfirmPrompt, LABEL_MAX, Label, PANEL_H, PANEL_W, Screen};

/// A `DrawTarget` that discards pixels and silently clips out-of-bounds, like the
/// real panel — so any panic comes from the renderer's layout math, not us.
struct Sink;
impl OriginDimensions for Sink {
    fn size(&self) -> Size {
        Size::new(PANEL_W as u32, PANEL_H as u32)
    }
}
impl DrawTarget for Sink {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for _ in pixels {}
        Ok(())
    }
}

/// The sanitizer's post-condition: printable ASCII only, and bounded.
fn assert_sanitized(l: &Label) {
    assert!(l.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
    assert!(l.as_str().len() <= LABEL_MAX);
}

fuzz_target!(|data: &[u8]| {
    let (primary, secondary) = data.split_at(data.len() / 2);

    // 1) The sanitizer invariants: ASCII-only, bounded, exact length + truncated.
    let head = Label::clamp(primary);
    assert_sanitized(&head);
    assert_eq!(head.truncated, primary.len() > LABEL_MAX);
    assert_eq!(head.as_str().len(), primary.len().min(LABEL_MAX));

    let dom = Label::clamp_domain(primary);
    assert_sanitized(&dom);
    assert_eq!(dom.truncated, primary.len() > LABEL_MAX);
    assert_eq!(dom.as_str().len(), primary.len().min(LABEL_MAX));

    // 2) The confirm screen built from both untrusted fields must render clean.
    let prompt = ConfirmPrompt::new("Approve?", primary, secondary);
    assert_sanitized(&prompt.primary);
    assert_sanitized(&prompt.secondary);
    let mut sink = Sink;
    let _ = rsk_ui::render::render(&mut sink, &Screen::Confirm(prompt));
});
