// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Painting a [`Screen`] onto an ST7789-class panel. Pure and generic over
//! `embedded_graphics::DrawTarget<Color = Rgb565>`, so the security-relevant
//! layout — above all that the word "Allow" is painted inside [`ALLOW_RECT`], the
//! exact region [`crate::hit_confirm`] approves — is decided here and unit-tested
//! on the host against a recording target, with the firmware's `display.rs` only
//! supplying the real panel. There is no retained framebuffer (240×320×2 would not
//! fit the heap): [`render`] paints the whole frame and the caller repaints on a
//! state change.

use embedded_graphics::{
    Drawable,
    draw_target::DrawTarget,
    geometry::{Point as EgPoint, Size},
    mono_font::{
        MonoFont, MonoTextStyle,
        ascii::{FONT_6X13, FONT_9X15_BOLD, FONT_10X20},
    },
    pixelcolor::Rgb565,
    prelude::{RgbColor, WebColors},
    primitives::{Circle, Primitive, PrimitiveStyle, Rectangle},
    text::{Alignment, Baseline, Text, TextStyle, TextStyleBuilder},
};

use crate::{ALLOW_RECT, ConfirmPrompt, DENY_RECT, PANEL_W, Rect, Screen, StatusKind};

const BG: Rgb565 = Rgb565::BLACK;
const FG: Rgb565 = Rgb565::WHITE;
const MUTED: Rgb565 = Rgb565::CSS_SLATE_GRAY;
/// Allow on the right is green, Deny on the left is red — the colors back up the
/// fixed left/right geometry so the *meaning* of a tap is doubly unambiguous.
const ALLOW_FILL: Rgb565 = Rgb565::CSS_DARK_GREEN;
const DENY_FILL: Rgb565 = Rgb565::CSS_DARK_RED;

/// Center the screen horizontally on a half-pixel-free integer midline.
const MIDX: i32 = PANEL_W as i32 / 2;

/// Render `screen` as a full frame. Clears to the background first, so the caller
/// need not track dirty regions — it repaints when the model changes.
pub fn render<D>(target: &mut D, screen: &Screen) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    target.clear(BG)?;
    match screen {
        Screen::Splash => splash(target),
        Screen::Status(kind) => status(target, *kind),
        Screen::Confirm(prompt) => confirm(target, prompt),
    }
}

fn splash<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    text(t, "RS-Key", EgPoint::new(MIDX, 140), &FONT_10X20, FG)?;
    text(
        t,
        "trusted display",
        EgPoint::new(MIDX, 175),
        &FONT_6X13,
        MUTED,
    )
}

fn status<D: DrawTarget<Color = Rgb565>>(t: &mut D, kind: StatusKind) -> Result<(), D::Error> {
    let color = status_color(kind);
    text(t, "RS-Key", EgPoint::new(MIDX, 24), &FONT_6X13, MUTED)?;
    Circle::new(EgPoint::new(MIDX - 12, 120), 24)
        .into_styled(PrimitiveStyle::with_fill(color))
        .draw(t)?;
    text(t, kind.label(), EgPoint::new(MIDX, 210), &FONT_10X20, color)
}

fn confirm<D: DrawTarget<Color = Rgb565>>(t: &mut D, p: &ConfirmPrompt) -> Result<(), D::Error> {
    text(
        t,
        p.operation.title(),
        EgPoint::new(MIDX, 40),
        &FONT_9X15_BOLD,
        FG,
    )?;
    // The relying-party fields, already sanitized to short printable ASCII by
    // `Label::clamp`. Phase 2 wraps a long rp id across lines + marks truncation;
    // for now one centered line each, clipped at the panel edge by the target.
    if !p.primary.is_empty() {
        text(
            t,
            p.primary.as_str(),
            EgPoint::new(MIDX, 96),
            &FONT_6X13,
            FG,
        )?;
    }
    if !p.secondary.is_empty() {
        text(
            t,
            p.secondary.as_str(),
            EgPoint::new(MIDX, 124),
            &FONT_6X13,
            MUTED,
        )?;
    }
    button(t, DENY_RECT, "Deny", DENY_FILL)?;
    button(t, ALLOW_RECT, "Allow", ALLOW_FILL)
}

/// Fill a button rect and center its caption — the fill and the caption share the
/// one [`Rect`] the hit-test uses, so paint and hit-test can never disagree.
fn button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    fill: Rgb565,
) -> Result<(), D::Error> {
    eg_rect(r)
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    text(t, label, center(r), &FONT_9X15_BOLD, FG)
}

fn status_color(kind: StatusKind) -> Rgb565 {
    match kind {
        StatusKind::Boot => Rgb565::RED,
        StatusKind::Idle => Rgb565::GREEN,
        StatusKind::Processing => Rgb565::YELLOW,
        StatusKind::Touch => Rgb565::CSS_ORANGE,
    }
}

/// Draw `s` centered on `at` (horizontal center, vertical middle).
fn text<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    font: &'static MonoFont<'static>,
    color: Rgb565,
) -> Result<(), D::Error> {
    Text::with_text_style(s, at, MonoTextStyle::new(font, color), centered()).draw(t)?;
    Ok(())
}

fn centered() -> TextStyle {
    TextStyleBuilder::new()
        .alignment(Alignment::Center)
        .baseline(Baseline::Middle)
        .build()
}

fn center(r: Rect) -> EgPoint {
    EgPoint::new(r.x as i32 + r.w as i32 / 2, r.y as i32 + r.h as i32 / 2)
}

fn eg_rect(r: Rect) -> Rectangle {
    Rectangle::new(
        EgPoint::new(r.x as i32, r.y as i32),
        Size::new(r.w as u32, r.h as u32),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operation, PANEL_H};
    use embedded_graphics::{Pixel, geometry::OriginDimensions};

    /// A `DrawTarget` that records into a 240×320 buffer and, like a real panel,
    /// clips out-of-bounds pixels — but flags that it had to (`oob`), so a test can
    /// assert a screen stayed inside the panel.
    struct Rec {
        px: std::vec::Vec<Rgb565>,
        oob: bool,
    }

    impl Rec {
        fn new() -> Self {
            Self {
                px: std::vec![BG; PANEL_W as usize * PANEL_H as usize],
                oob: false,
            }
        }
        fn at(&self, x: u16, y: u16) -> Rgb565 {
            self.px[y as usize * PANEL_W as usize + x as usize]
        }
        fn any_non_bg_in(&self, r: Rect) -> bool {
            (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| self.at(x, y) != BG))
        }
        fn drew_anything(&self) -> bool {
            self.px.iter().any(|&c| c != BG)
        }
    }

    impl OriginDimensions for Rec {
        fn size(&self) -> Size {
            Size::new(PANEL_W as u32, PANEL_H as u32)
        }
    }

    impl DrawTarget for Rec {
        type Color = Rgb565;
        type Error = core::convert::Infallible;
        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Rgb565>>,
        {
            for Pixel(p, c) in pixels {
                if p.x >= 0
                    && p.y >= 0
                    && (p.x as u32) < PANEL_W as u32
                    && (p.y as u32) < PANEL_H as u32
                {
                    self.px[p.y as usize * PANEL_W as usize + p.x as usize] = c;
                } else {
                    self.oob = true;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn splash_fits_and_draws() {
        let mut d = Rec::new();
        render(&mut d, &Screen::Splash).unwrap();
        assert!(!d.oob, "splash drew outside the panel");
        assert!(d.drew_anything());
    }

    #[test]
    fn every_status_fits_and_draws() {
        for kind in [
            StatusKind::Boot,
            StatusKind::Idle,
            StatusKind::Processing,
            StatusKind::Touch,
        ] {
            let mut d = Rec::new();
            render(&mut d, &Screen::Status(kind)).unwrap();
            assert!(!d.oob, "status {kind:?} drew outside the panel");
            assert!(d.drew_anything(), "status {kind:?} drew nothing");
        }
    }

    /// The core security property: the *Allow* control is painted in `ALLOW_RECT`
    /// and *Deny* in `DENY_RECT` — exactly the regions `hit_confirm` maps a tap to —
    /// each in its own color, with the operation title above the button band.
    #[test]
    fn confirm_paints_allow_and_deny_in_their_hit_rects() {
        let p = ConfirmPrompt::new(Operation::GetAssertion, b"github.com", b"alice");
        let mut d = Rec::new();
        render(&mut d, &Screen::Confirm(p)).unwrap();
        assert!(!d.oob, "confirm drew outside the panel");

        // Each button region carries its fill (sampled at a corner, away from the
        // centered caption) and some non-background content overall.
        assert_eq!(d.at(ALLOW_RECT.x + 2, ALLOW_RECT.y + 2), ALLOW_FILL);
        assert_eq!(d.at(DENY_RECT.x + 2, DENY_RECT.y + 2), DENY_FILL);
        assert!(d.any_non_bg_in(ALLOW_RECT));
        assert!(d.any_non_bg_in(DENY_RECT));
        // The title sits in the prompt area above the button band, in foreground.
        assert!((0..crate::BTN_BAND_TOP).any(|y| (0..PANEL_W).any(|x| d.at(x, y) == FG)));
    }

    #[test]
    fn confirm_button_band_does_not_intrude_on_the_prompt_area() {
        // Nothing of the (filled) buttons is painted above the reserved band, so a
        // stray prompt-area tap can never land on button paint.
        let p = ConfirmPrompt::new(Operation::MakeCredential, b"example.org", b"");
        let mut d = Rec::new();
        render(&mut d, &Screen::Confirm(p)).unwrap();
        let row = crate::BTN_BAND_TOP - 1;
        assert!((0..PANEL_W).all(|x| {
            let c = d.at(x, row);
            c != ALLOW_FILL && c != DENY_FILL
        }));
    }
}
