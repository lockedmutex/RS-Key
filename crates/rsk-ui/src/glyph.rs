// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Vector icons drawn from `embedded-graphics` primitives — no bitmap assets, no
//! icon font. Each glyph is laid out on an integer 16×16 grid scaled to the
//! requested pixel size, so the same icon is crisp at a 14px list-row marker or a
//! 20px nav tab. Keeping them here (pure, generic over `DrawTarget`) makes them
//! host-testable like the rest of the UI model: a test renders each into a
//! recording target and asserts it paints inside its box.
//!
//! The set is deliberately small and abstract. Per-relying-party brand logos are
//! **not** drawable — the device only knows the rp *string* (and its hash), not the
//! brand — so a relying party gets the generic [`Glyph::Globe`] plus its rpId text.

use embedded_graphics::{
    Drawable,
    draw_target::DrawTarget,
    geometry::{Angle, Point as EgPoint, Size},
    pixelcolor::Rgb565,
    primitives::{
        Arc, Circle, Ellipse, Line, Polyline, Primitive, PrimitiveStyle, Rectangle, Triangle,
    },
};

use crate::Point;

/// A drawable icon. Abstract, not brand-specific (see the module note on logos).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Glyph {
    /// USB plug — the "connected / powered" status (replaces a battery icon: this is
    /// a bus-powered device, it has no battery).
    Usb,
    /// A bare check mark — the PIN pad's OK / commit key.
    Check,
    /// A backspace key (left-pointing tag with an ×) — the PIN pad's Del key.
    Backspace,
    /// A check inside a ring — the big idle "Ready" indicator.
    CheckCircle,
    /// A closed padlock — PIN set / locked.
    Lock,
    /// A key — passkeys / credentials, and the Passkeys nav tab.
    Key,
    /// A house — the Home nav tab.
    Home,
    /// A cog — settings / the Settings nav tab.
    Gear,
    /// A right chevron — "this row drills in".
    Chevron,
    /// A left chevron — the service-detail "back to the list" affordance.
    Back,
    /// A shield — the trusted-approval prompt.
    Shield,
    /// A globe — the generic relying-party marker.
    Globe,
    /// A warning triangle — caution text.
    Warn,
    /// A sun — the brightness setting.
    Sun,
    /// A clock — the touch-timeout setting.
    Clock,
    /// A crescent moon — the display-sleep setting.
    Moon,
    /// An "i" in a ring — the device-info setting.
    Info,
    /// A counter-clockwise refresh ring — the post-factory-reset "erased / restarting"
    /// indicator (the design's grey rotate icon, distinct from the green success check).
    Rotate,
}

/// Draw `g` into the square box at `at` (top-left) of side `s` pixels, stroked in
/// `color`. Pure and generic; the caller positions the box. Stroke thickens to 2px
/// at nav size (≥20px) for legibility.
pub fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    g: Glyph,
    at: Point,
    s: u16,
    color: Rgb565,
) -> Result<(), D::Error> {
    let sw: u32 = if s >= 20 { 2 } else { 1 };
    let stroke = PrimitiveStyle::with_stroke(color, sw);
    let fill = PrimitiveStyle::with_fill(color);
    // Grid point: grid coords 0..=16 mapped into the box.
    let gp = |gx: i32, gy: i32| {
        EgPoint::new(
            at.x as i32 + (gx * s as i32) / 16,
            at.y as i32 + (gy * s as i32) / 16,
        )
    };
    // Pixel length of a grid span (for circle/ellipse/rect sizes).
    let glen = |span: i32| ((span * s as i32) / 16).max(1) as u32;
    // Circle centred on grid (cx,cy) with grid radius r.
    let circ = |cx: i32, cy: i32, r: i32| Circle::new(gp(cx - r, cy - r), glen(2 * r));

    match g {
        Glyph::Chevron => Polyline::new(&[gp(6, 3), gp(11, 8), gp(6, 13)])
            .into_styled(stroke)
            .draw(t),
        Glyph::Back => Polyline::new(&[gp(11, 3), gp(6, 8), gp(11, 13)])
            .into_styled(stroke)
            .draw(t),
        Glyph::Check => Polyline::new(&[gp(3, 9), gp(7, 13), gp(13, 4)])
            .into_styled(stroke)
            .draw(t),
        Glyph::Backspace => {
            // Left-pointing tag outline + an × in the body.
            Polyline::new(&[
                gp(6, 4),
                gp(14, 4),
                gp(14, 12),
                gp(6, 12),
                gp(2, 8),
                gp(6, 4),
            ])
            .into_styled(stroke)
            .draw(t)?;
            Line::new(gp(8, 6), gp(12, 10))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(12, 6), gp(8, 10)).into_styled(stroke).draw(t)
        }
        Glyph::CheckCircle => {
            circ(8, 8, 7).into_styled(stroke).draw(t)?;
            Polyline::new(&[gp(5, 8), gp(7, 11), gp(12, 5)])
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Lock => {
            Rectangle::new(gp(4, 8), Size::new(glen(8), glen(6)))
                .into_styled(stroke)
                .draw(t)?;
            Polyline::new(&[gp(6, 8), gp(6, 5), gp(10, 5), gp(10, 8)])
                .into_styled(stroke)
                .draw(t)?;
            circ(8, 11, 1).into_styled(fill).draw(t)
        }
        Glyph::Key => {
            circ(5, 11, 3).into_styled(stroke).draw(t)?;
            Line::new(gp(7, 9), gp(14, 2)).into_styled(stroke).draw(t)?;
            Line::new(gp(12, 4), gp(13, 5))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 3), gp(14, 4)).into_styled(stroke).draw(t)
        }
        Glyph::Home => {
            Polyline::new(&[gp(2, 8), gp(8, 2), gp(14, 8)])
                .into_styled(stroke)
                .draw(t)?;
            Polyline::new(&[gp(4, 7), gp(4, 14), gp(12, 14), gp(12, 7)])
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Gear => {
            circ(8, 8, 4).into_styled(stroke).draw(t)?;
            circ(8, 8, 1).into_styled(fill).draw(t)?;
            Line::new(gp(8, 1), gp(8, 3)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 13), gp(8, 15))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(1, 8), gp(3, 8)).into_styled(stroke).draw(t)?;
            Line::new(gp(13, 8), gp(15, 8)).into_styled(stroke).draw(t)
        }
        Glyph::Shield => Polyline::new(&[
            gp(8, 2),
            gp(14, 5),
            gp(14, 9),
            gp(8, 15),
            gp(2, 9),
            gp(2, 5),
            gp(8, 2),
        ])
        .into_styled(stroke)
        .draw(t),
        Glyph::Globe => {
            circ(8, 8, 6).into_styled(stroke).draw(t)?;
            Ellipse::new(gp(5, 2), Size::new(glen(6), glen(12)))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(2, 8), gp(14, 8)).into_styled(stroke).draw(t)
        }
        Glyph::Usb => {
            Line::new(gp(8, 2), gp(8, 14)).into_styled(stroke).draw(t)?;
            circ(8, 14, 1).into_styled(fill).draw(t)?;
            Line::new(gp(8, 6), gp(5, 9)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 8), gp(11, 5)).into_styled(stroke).draw(t)?;
            Rectangle::new(gp(10, 3), Size::new(glen(2), glen(2)))
                .into_styled(fill)
                .draw(t)?;
            circ(5, 9, 1).into_styled(fill).draw(t)
        }
        Glyph::Warn => {
            Triangle::new(gp(8, 2), gp(14, 14), gp(2, 14))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(8, 6), gp(8, 10)).into_styled(stroke).draw(t)?;
            circ(8, 12, 1).into_styled(fill).draw(t)
        }
        Glyph::Sun => {
            circ(8, 8, 3).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 1), gp(8, 3)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 13), gp(8, 15))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(1, 8), gp(3, 8)).into_styled(stroke).draw(t)?;
            Line::new(gp(13, 8), gp(15, 8))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(3, 3), gp(4, 4)).into_styled(stroke).draw(t)?;
            Line::new(gp(12, 12), gp(13, 13))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 3), gp(12, 4))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(3, 13), gp(4, 12)).into_styled(stroke).draw(t)
        }
        Glyph::Clock => {
            circ(8, 8, 6).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 8), gp(8, 4)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 8), gp(11, 9)).into_styled(stroke).draw(t)
        }
        Glyph::Moon => {
            // A crescent: a C-shaped arc with a wide opening to the right — clearly a
            // moon, not the full-circle Clock above it in the settings list.
            Arc::new(
                gp(2, 2),
                glen(12),
                Angle::from_degrees(80.0),
                Angle::from_degrees(200.0),
            )
            .into_styled(stroke)
            .draw(t)
        }
        Glyph::Info => {
            circ(8, 8, 6).into_styled(stroke).draw(t)?;
            circ(8, 5, 1).into_styled(fill).draw(t)?;
            Line::new(gp(8, 7), gp(8, 11)).into_styled(stroke).draw(t)
        }
        Glyph::Rotate => {
            // A near-full ring with a gap at the top, plus an arrowhead at the gap —
            // the universal "reset / restart" mark for the wiped screen.
            Arc::new(
                gp(2, 2),
                glen(12),
                Angle::from_degrees(300.0),
                Angle::from_degrees(300.0),
            )
            .into_styled(stroke)
            .draw(t)?;
            Polyline::new(&[gp(7, 2), gp(11, 4), gp(8, 7)])
                .into_styled(stroke)
                .draw(t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::{Pixel, geometry::OriginDimensions, prelude::RgbColor};

    /// A tiny recording target: tracks whether anything was drawn and whether any
    /// pixel fell outside its bounds (a glyph must stay inside its box).
    struct Rec {
        w: i32,
        h: i32,
        drew: bool,
        oob: bool,
    }

    impl OriginDimensions for Rec {
        fn size(&self) -> Size {
            Size::new(self.w as u32, self.h as u32)
        }
    }

    impl DrawTarget for Rec {
        type Color = Rgb565;
        type Error = core::convert::Infallible;
        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Rgb565>>,
        {
            for Pixel(p, _) in pixels {
                if p.x < 0 || p.y < 0 || p.x >= self.w || p.y >= self.h {
                    self.oob = true;
                } else {
                    self.drew = true;
                }
            }
            Ok(())
        }
    }

    const ALL: [Glyph; 18] = [
        Glyph::Usb,
        Glyph::Check,
        Glyph::Backspace,
        Glyph::CheckCircle,
        Glyph::Lock,
        Glyph::Key,
        Glyph::Home,
        Glyph::Gear,
        Glyph::Chevron,
        Glyph::Back,
        Glyph::Shield,
        Glyph::Globe,
        Glyph::Warn,
        Glyph::Sun,
        Glyph::Clock,
        Glyph::Moon,
        Glyph::Info,
        Glyph::Rotate,
    ];

    #[test]
    fn every_glyph_paints_inside_its_box() {
        // Box at (4,4) size 16 inside a 24×24 target: every glyph must paint and
        // never spill outside the 24×24 bounds.
        for g in ALL {
            let mut d = Rec {
                w: 24,
                h: 24,
                drew: false,
                oob: false,
            };
            draw(&mut d, g, Point::new(4, 4), 16, Rgb565::WHITE).unwrap();
            assert!(d.drew, "{g:?} drew nothing");
            assert!(!d.oob, "{g:?} drew outside its 24×24 box");
        }
    }

    #[test]
    fn nav_size_glyphs_also_fit() {
        // The bottom-nav tabs render at 20px (2px stroke) — still inside the box.
        for g in [Glyph::Home, Glyph::Key, Glyph::Gear] {
            let mut d = Rec {
                w: 28,
                h: 28,
                drew: false,
                oob: false,
            };
            draw(&mut d, g, Point::new(4, 4), 20, Rgb565::WHITE).unwrap();
            assert!(d.drew && !d.oob, "{g:?} did not fit at nav size");
        }
    }
}
