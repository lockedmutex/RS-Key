// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Proportional 1-bit text for the high-fidelity redesign. The design is set in IBM
//! Plex Sans/Mono; on the panel we substitute the closest u8g2 bitmap faces — bold
//! `helvB**` for the 600/700 weights, regular `helvR**` for 400/500, and `profont`
//! for the monospaced version/caption labels. Each [`Role`] pins one face so the px
//! sizes in the handoff map to a single place. All faces are the `_tr` (reduced,
//! transparent, 7-bit ASCII) variants — our text is already ASCII-sanitised
//! ([`crate::Label::clamp`]), so the larger glyph tables would only cost flash.
//!
//! Text is drawn [`FontColor::Transparent`] (glyph pixels only, no rectangle behind),
//! which suits the no-framebuffer partial repaints: a label can be overdrawn on top of
//! an already-painted card without first clearing it.

use embedded_graphics::{draw_target::DrawTarget, geometry::Point as EgPoint, pixelcolor::Rgb565};
use u8g2_fonts::{
    FontRenderer, fonts,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

/// A typographic role from the handoff's "Типографика" table, mapped to one face.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// The main "Ready" status — 30px, 600. `helvB24` (the largest bold helv).
    Ready,
    /// Screen titles (19px) and success / "Locked" headings (20–21px), 600. `helvB18`.
    Heading,
    /// The large service name inside the request/approve modals — 17–18px, 600. `helvB14`.
    Strong,
    /// Body text and list rows at 400 weight, and 13px sublabels. `helvR12`.
    Body,
    /// Body text / list rows at 600 weight (active row, emphasised value). `helvB12`.
    BodyStrong,
    /// Monospaced labels — UV+PIN tags, "OK", the version string, captions. `profont12`.
    Mono,
    /// The smallest monospaced label — "USB" in the status bar (11px). `profont11`.
    MonoSmall,
}

/// The `FontRenderer` for `role`. `const` so the call sites pay nothing at runtime.
const fn renderer(role: Role) -> FontRenderer {
    match role {
        Role::Ready => FontRenderer::new::<fonts::u8g2_font_helvB24_tr>(),
        Role::Heading => FontRenderer::new::<fonts::u8g2_font_helvB18_tr>(),
        Role::Strong => FontRenderer::new::<fonts::u8g2_font_helvB14_tr>(),
        Role::Body => FontRenderer::new::<fonts::u8g2_font_helvR12_tr>(),
        Role::BodyStrong => FontRenderer::new::<fonts::u8g2_font_helvB12_tr>(),
        Role::Mono => FontRenderer::new::<fonts::u8g2_font_profont12_tr>(),
        Role::MonoSmall => FontRenderer::new::<fonts::u8g2_font_profont11_tr>(),
    }
}

/// The workhorse: render `s` in `role`/`color`, aligned `h` horizontally and centred
/// vertically on `at`. A panel write error is surfaced; a glyph-table miss (impossible
/// on ASCII-sanitised input) is swallowed so a single odd byte can't abort a frame.
fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    h: HorizontalAlignment,
) -> Result<(), D::Error> {
    match renderer(role).render_aligned(
        s,
        at,
        VerticalPosition::Center,
        h,
        FontColor::Transparent(color),
        t,
    ) {
        Ok(_) => Ok(()),
        Err(u8g2_fonts::Error::DisplayError(e)) => Err(e),
        Err(_) => Ok(()),
    }
}

/// Horizontally-centred, vertically-centred text (titles, button captions, status).
pub fn centered<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    draw(t, s, at, role, color, HorizontalAlignment::Center)
}

/// Left-aligned, vertically-centred text (row labels, header titles).
pub fn left<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    draw(t, s, at, role, color, HorizontalAlignment::Left)
}

/// Right-aligned, vertically-centred text (trailing row values / status).
pub fn right<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    draw(t, s, at, role, color, HorizontalAlignment::Right)
}

/// Pixel width `s` occupies in `role` — for laying a trailing element flush against a
/// variable-width (proportional) label. `None` only on the impossible glyph-miss.
pub fn width(s: &str, role: Role) -> Option<u32> {
    renderer(role)
        .get_rendered_dimensions(s, EgPoint::zero(), VerticalPosition::Center)
        .ok()
        .map(|d| d.bounding_box.map_or(0, |b| b.size.width))
}
