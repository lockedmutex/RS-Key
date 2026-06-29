// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Vector icons drawn from `embedded-graphics` primitives — no bitmap assets, no
//! icon font. Each glyph is laid out on an integer 16×16 grid scaled to the
//! requested pixel size, so the same icon is crisp at a 14px list-row marker, a
//! 20px nav tab, or a 36px headline. Keeping them here (pure, generic over
//! `DrawTarget`) makes them host-testable like the rest of the UI model: a test
//! renders each into a recording target and asserts it paints inside its box, and
//! a second test asserts each is mirror-symmetric about the axes it claims.
//!
//! Symmetry is built in, not bolted on: every glyph is drawn from primitives that are
//! already mirror-symmetric (a centred [`Circle`]/[`Triangle`], a centred stroke, or
//! paired strokes placed by hand on both sides). No generic "mirror the buffer" pass —
//! that either fills a ring solid (union) or erases a centred axis stroke (copy) on an
//! even box. The only post-processing is [`Glyph::Back`], the [`Glyph::Chevron`]
//! rasterized and flipped left–right.
//!
//! The set is deliberately small and abstract. Per-relying-party brand logos are
//! **not** drawable — the device only knows the rp *string* (and its hash), not the
//! brand — so a relying party gets the generic [`Glyph::Globe`] plus its rpId text.

use embedded_graphics::{
    Drawable, Pixel,
    draw_target::DrawTarget,
    geometry::{Angle, OriginDimensions, Point as EgPoint, Size},
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
    /// A counter-clockwise refresh ring — the post-factory-reset "erased / restarting"
    /// indicator (the design's grey rotate icon, distinct from the green success check).
    Rotate,
    /// A pencil — the service-detail "rename" affordance (sets a device-local nickname).
    Edit,
    /// An eye (lens outline + pupil) — the confirm-delete "reveal PIN" toggle.
    Eye,
    /// A lifebuoy (outer ring + inner hub + four diagonal spokes) — the seed-backup /
    /// recovery marker on the Backup screen.
    Lifebuoy,
    /// A microchip — a square die with a smaller core and two pins per side. The
    /// installed-firmware marker on the Firmware screen / its settings row.
    Cpu,
    /// A 2×2 grid of tiles — the unified "Apps" nav tab (the applet launcher:
    /// OpenPGP / PIV / OATH).
    Apps,
    /// A command prompt — a ">" caret and an underscore cursor: the marker for an SSH
    /// relying party (a shell host) on the Passkeys list, distinct from the web globe.
    Terminal,
    /// A person (head + shoulders) — the OpenPGP "card holder" identity row.
    User,
}

/// 1-bit scratch a glyph rasterizes into so the renderer can impose mirror symmetry before
/// blitting. The bit for column `x` of row `y` is `rows[y] & (1 << x)`.
struct Mask<'a> {
    n: usize,
    rows: &'a mut [u64],
}
impl OriginDimensions for Mask<'_> {
    fn size(&self) -> Size {
        Size::new(self.n as u32, self.n as u32)
    }
}
impl DrawTarget for Mask<'_> {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, _) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as usize) < self.n && (p.y as usize) < self.n {
                self.rows[p.y as usize] |= 1u64 << (p.x as usize);
            }
        }
        Ok(())
    }
}

/// The mirror axes a glyph is drawn symmetric about, asserted by the symmetry test: `v` =
/// left–right (about the vertical centre line), `h` = top–bottom (about the horizontal). A
/// directional glyph that still has a symmetric skeleton lists only the axis it keeps (the
/// chevron's `>` is top–bottom symmetric); a glyph with a directional mark on top of a
/// symmetric base (the check in a ring, the clock hands, the rotate arrow) claims neither, so
/// the test does not flag the mark.
struct Sym {
    v: bool,
    h: bool,
}

/// Which axes a glyph is made exactly symmetric about by [`draw`]'s symmetry pass. A glyph
/// listed here is drawn *fully* symmetric (no asymmetric mark); glyphs that carry a directional
/// mark (the check in a ring, the clock hands, the rotate arrow, the USB trident, the key, the
/// pencil, the crescent) claim no axis and are drawn as-is — their symmetric parts are already
/// symmetric eg primitives (a centred circle), so they need no pass.
fn sym(g: Glyph) -> Sym {
    use Glyph::*;
    match g {
        Chevron | Backspace => Sym { v: false, h: true },
        Lock | Home | Shield | Warn | Usb | User => Sym { v: true, h: false },
        Sun | Globe | Gear | Eye | Lifebuoy | Cpu | Apps => Sym { v: true, h: true },
        _ => Sym { v: false, h: false },
    }
}

/// Reverse the low `n` bits of `r` (column mirror of one row).
fn rev_bits(r: u64, n: usize) -> u64 {
    let mut o = 0u64;
    let mut b = r;
    while b != 0 {
        let x = b.trailing_zeros() as usize;
        o |= 1u64 << (n - 1 - x);
        b &= b - 1;
    }
    o
}

/// Draw `g` into the square box at `at` (top-left) of side `s` pixels, stroked in `color`.
/// Rasterizes into a 1-bit scratch then blits, so a glyph is one atomic draw_iter. The only
/// transform is [`Glyph::Back`] = the [`Glyph::Chevron`] flipped left–right; every other glyph
/// is drawn already symmetric by [`paths`]. Pure and generic.
pub fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    g: Glyph,
    at: Point,
    s: u16,
    color: Rgb565,
) -> Result<(), D::Error> {
    const CAP: usize = 48;
    let n = (s as usize).min(CAP);
    let mut rows = [0u64; CAP];
    // Back is the Chevron mirrored left–right: draw the chevron, then flip at the end.
    let base = if g == Glyph::Back { Glyph::Chevron } else { g };
    let _ = paths(&mut Mask { n, rows: &mut rows }, base, s);
    // Symmetry pass: mirror the canonical half onto the other, then OR the centre band back
    // from the original. The copy makes a ring / diagonal pair *exactly* symmetric (eg draws
    // diagonals direction-dependently, off by a pixel) without filling it solid (a union
    // would); the centre restore keeps a 1px centred stroke an even box can't mirror-place.
    let sy = sym(base);
    if sy.v {
        let half = n.div_ceil(2);
        let left_mask = if half >= 64 {
            u64::MAX
        } else {
            (1u64 << half) - 1
        };
        let center = (1u64 << (n / 2)) | (1u64 << ((n - 1) / 2));
        for r in rows.iter_mut().take(n) {
            let o = *r;
            let left = o & left_mask;
            *r = left | rev_bits(left, n) | (o & center);
        }
    }
    if sy.h {
        let (c0, c1) = (rows[(n - 1) / 2], rows[n / 2]);
        for y in 0..n / 2 {
            rows[n - 1 - y] = rows[y];
        }
        rows[(n - 1) / 2] |= c0;
        rows[n / 2] |= c1;
    }
    if g == Glyph::Back {
        for r in rows.iter_mut().take(n) {
            *r = rev_bits(*r, n);
        }
    }
    // Auto-centre the ink: shift the rasterized bounding box to equal margins on every side.
    // The symmetry pass already centres a claimed axis (a v-symmetric glyph is left–right
    // centred), but the off-axis can sit high/low and an asymmetric glyph (check, key, pencil)
    // anywhere; an integer shift preserves whatever symmetry was imposed.
    let (mut minx, mut maxx, mut miny, mut maxy) = (n, 0usize, n, 0usize);
    for (y, &r) in rows.iter().enumerate().take(n) {
        if r != 0 {
            miny = miny.min(y);
            maxy = y;
            minx = minx.min(r.trailing_zeros() as usize);
            maxx = maxx.max(63 - r.leading_zeros() as usize);
        }
    }
    if maxx >= minx {
        let dx = (n as i32 - 1 - maxx as i32 - minx as i32) / 2;
        let dy = (n as i32 - 1 - maxy as i32 - miny as i32) / 2;
        if dx > 0 {
            rows[..n].iter_mut().for_each(|r| *r <<= dx);
        } else if dx < 0 {
            rows[..n].iter_mut().for_each(|r| *r >>= -dx);
        }
        if dy > 0 {
            for y in (0..n).rev() {
                rows[y] = if y >= dy as usize {
                    rows[y - dy as usize]
                } else {
                    0
                };
            }
        } else if dy < 0 {
            let d = (-dy) as usize;
            for y in 0..n {
                rows[y] = if y + d < n { rows[y + d] } else { 0 };
            }
        }
    }
    t.draw_iter((0..n).flat_map(|y| {
        let r = rows[y];
        let ax = at.x as i32;
        let ay = at.y as i32 + y as i32;
        (0..n)
            .filter(move |x| r & (1u64 << x) != 0)
            .map(move |x| Pixel(EgPoint::new(ax + x as i32, ay), color))
    }))
}

/// Rasterize `g`'s strokes at the origin into `t`; [`draw`] handles position, the [`Glyph::Back`]
/// flip, and colour (the mask ignores colour — it only records set pixels). Coordinates are a
/// 16×16 grid scaled to `s` and rounded to the nearest pixel. Each glyph is drawn already
/// symmetric (centred primitives + strokes placed in mirror pairs), so no mirror pass is needed.
fn paths<D: DrawTarget<Color = Rgb565>>(t: &mut D, g: Glyph, s: u16) -> Result<(), D::Error> {
    let sw: u32 = if s >= 20 { 2 } else { 1 };
    let ink = Rgb565::new(0x1f, 0x3f, 0x1f);
    let stroke = PrimitiveStyle::with_stroke(ink, sw);
    let fill = PrimitiveStyle::with_fill(ink);
    // Map a 16-grid coord to a pixel, rounded; grid 0..=16 spans the full box 0..=s-1.
    let g1 = (s as i32 - 1).max(1);
    let gp = |gx: i32, gy: i32| EgPoint::new((gx * g1 + 8) / 16, (gy * g1 + 8) / 16);
    let glen = |span: i32| ((span * g1 + 8) / 16).max(1) as u32;
    let circ = |cx: i32, cy: i32, r: i32| Circle::new(gp(cx - r, cy - r), glen(2 * r));

    match g {
        Glyph::Chevron => Polyline::new(&[gp(5, 4), gp(11, 8), gp(5, 12)])
            .into_styled(stroke)
            .draw(t),
        // Back is rendered from Chevron's base + a final left–right flip (see `draw`).
        Glyph::Back => Polyline::new(&[gp(5, 4), gp(11, 8), gp(5, 12)])
            .into_styled(stroke)
            .draw(t),
        Glyph::Check => Polyline::new(&[gp(4, 9), gp(7, 12), gp(13, 4)])
            .into_styled(stroke)
            .draw(t),
        Glyph::Backspace => {
            // Left-pointing tag outline + a centred, symmetric × in the body.
            Polyline::new(&[
                gp(6, 4),
                gp(15, 4),
                gp(15, 12),
                gp(6, 12),
                gp(2, 8),
                gp(6, 4),
            ])
            .into_styled(stroke)
            .draw(t)?;
            Line::new(gp(9, 6), gp(13, 10))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 6), gp(9, 10)).into_styled(stroke).draw(t)
        }
        Glyph::CheckCircle => {
            // A ring with a check inside. Both drawn here (no mirror pass), so the check
            // reads as a single mark, not a doubled one.
            circ(8, 8, 7).into_styled(stroke).draw(t)?;
            Polyline::new(&[gp(5, 8), gp(7, 11), gp(12, 5)])
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Lock => {
            // Body + a slim rounded shackle (two short uprights joined by a flat top) +
            // a keyhole slot. The shackle is narrower than the body so it reads delicate.
            Rectangle::new(gp(4, 8), Size::new(glen(8), glen(6)))
                .into_styled(stroke)
                .draw(t)?;
            Polyline::new(&[gp(6, 8), gp(6, 5), gp(8, 4), gp(10, 5), gp(10, 8)])
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(8, 10), gp(8, 12)).into_styled(stroke).draw(t)
        }
        Glyph::Key => {
            // A round bow (ring) at the lower-left, a shaft up to the top-right, and two
            // teeth on the underside of the shaft near the tip.
            circ(4, 12, 3).into_styled(stroke).draw(t)?;
            Line::new(gp(6, 10), gp(14, 2))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(11, 5), gp(13, 7))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 3), gp(15, 5)).into_styled(stroke).draw(t)
        }
        Glyph::Home => {
            // A triangle roof (its base is the eave line) over rectangular walls, with a
            // centred door. Drawing the roof base + the wall top on the same row joins them
            // cleanly instead of leaving a 1px notch where a diagonal eave meets a wall.
            Line::new(gp(8, 3), gp(3, 8)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 3), gp(13, 8)).into_styled(stroke).draw(t)?;
            Rectangle::new(gp(4, 8), Size::new(glen(8), glen(6)))
                .into_styled(stroke)
                .draw(t)?;
            Polyline::new(&[gp(7, 14), gp(7, 11), gp(9, 11), gp(9, 14)])
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Gear => {
            // A ring + an open bore + eight short radial teeth (four on the axes, four on the
            // diagonals). The open bore (vs the Sun's solid core) tells them apart.
            circ(8, 8, 4).into_styled(stroke).draw(t)?;
            circ(8, 8, 2).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 4), gp(8, 1)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 12), gp(8, 15))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(4, 8), gp(1, 8)).into_styled(stroke).draw(t)?;
            Line::new(gp(12, 8), gp(15, 8))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(11, 5), gp(13, 3))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(5, 5), gp(3, 3)).into_styled(stroke).draw(t)?;
            Line::new(gp(11, 11), gp(13, 13))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(5, 11), gp(3, 13)).into_styled(stroke).draw(t)
        }
        Glyph::Shield => Polyline::new(&[
            gp(4, 3),
            gp(12, 3),
            gp(12, 8),
            gp(8, 14),
            gp(4, 8),
            gp(4, 3),
        ])
        .into_styled(stroke)
        .draw(t),
        Glyph::Globe => {
            // A disc with a straight equator and a single elliptic meridian — the lat/long
            // pair that reads as a globe rather than a crosshair.
            circ(8, 8, 6).into_styled(stroke).draw(t)?;
            Line::new(gp(3, 8), gp(13, 8)).into_styled(stroke).draw(t)?;
            Ellipse::new(gp(6, 2), Size::new(glen(4), glen(12)))
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Usb => {
            // The design's USB indicator: a plug head with two contact pins and a cable —
            // "powered over USB". Symmetric, so it stays clean at the 14px status-row size.
            Rectangle::new(gp(5, 2), Size::new(glen(6), glen(6)))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(7, 4), gp(7, 6)).into_styled(stroke).draw(t)?;
            Line::new(gp(9, 4), gp(9, 6)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 8), gp(8, 14)).into_styled(stroke).draw(t)
        }
        Glyph::Warn => {
            // A roomy triangle with the exclamation kept high and short so it never merges
            // into the lower edge.
            Triangle::new(gp(8, 2), gp(2, 14), gp(14, 14))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(8, 6), gp(8, 9)).into_styled(stroke).draw(t)?;
            circ(8, 11, 1).into_styled(fill).draw(t)
        }
        Glyph::Sun => {
            // A small SOLID core + eight rays (four on the axes, four on the diagonals). The
            // filled core (vs the Gear's open bore) tells them apart.
            circ(8, 8, 2).into_styled(fill).draw(t)?;
            Line::new(gp(8, 3), gp(8, 1)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 13), gp(8, 15))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(3, 8), gp(1, 8)).into_styled(stroke).draw(t)?;
            Line::new(gp(13, 8), gp(15, 8))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(11, 5), gp(13, 3))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(5, 5), gp(3, 3)).into_styled(stroke).draw(t)?;
            Line::new(gp(11, 11), gp(13, 13))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(5, 11), gp(3, 13)).into_styled(stroke).draw(t)
        }
        Glyph::Clock => {
            // A ring + an hour hand (up) and a minute hand (right) meeting at the centre.
            circ(8, 8, 6).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 8), gp(8, 5)).into_styled(stroke).draw(t)?;
            Line::new(gp(8, 8), gp(11, 8)).into_styled(stroke).draw(t)
        }
        Glyph::Moon => {
            // A crescent built as the gap between a disc and an overlapping disc would be
            // awkward in 1-bit, so it is a thick C-arc opening up-right — a clear moon.
            Arc::new(
                gp(2, 2),
                glen(12),
                Angle::from_degrees(60.0),
                Angle::from_degrees(240.0),
            )
            .into_styled(stroke)
            .draw(t)
        }
        Glyph::Rotate => {
            // A ring broken at the top-right with a counter-clockwise arrow head — "restarting".
            circ(8, 8, 6).into_styled(stroke).draw(t)?;
            Triangle::new(gp(9, 1), gp(13, 2), gp(11, 5))
                .into_styled(fill)
                .draw(t)
        }
        Glyph::Edit => {
            // A solid diagonal pencil: a filled slanted body (eraser end top-right) and a
            // pointed nib at the lower-left. A 1-bit outline of a thin diagonal bar reads as
            // two stray lines, so the body is filled.
            Triangle::new(gp(10, 3), gp(13, 6), gp(6, 13))
                .into_styled(fill)
                .draw(t)?;
            Triangle::new(gp(10, 3), gp(6, 13), gp(3, 10))
                .into_styled(fill)
                .draw(t)?;
            Triangle::new(gp(6, 13), gp(3, 10), gp(3, 15))
                .into_styled(fill)
                .draw(t)
        }
        Glyph::Eye => {
            // An almond lens (two arcs meeting at the corners) with a centred pupil.
            Arc::new(
                gp(1, 1),
                glen(14),
                Angle::from_degrees(20.0),
                Angle::from_degrees(140.0),
            )
            .into_styled(stroke)
            .draw(t)?;
            Arc::new(
                gp(1, 1),
                glen(14),
                Angle::from_degrees(200.0),
                Angle::from_degrees(140.0),
            )
            .into_styled(stroke)
            .draw(t)?;
            circ(8, 8, 2).into_styled(stroke).draw(t)?;
            circ(8, 8, 1).into_styled(fill).draw(t)
        }
        Glyph::Lifebuoy => {
            // Outer ring + a round inner ring (the hole edge) joined by four diagonal spokes
            // that cross the band, drawn on each diagonal so all four match.
            circ(8, 8, 7).into_styled(stroke).draw(t)?;
            circ(8, 8, 3).into_styled(stroke).draw(t)?;
            Line::new(gp(3, 3), gp(6, 6)).into_styled(stroke).draw(t)?;
            Line::new(gp(13, 3), gp(10, 6))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(3, 13), gp(6, 10))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 13), gp(10, 10))
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Cpu => {
            // A die outline + a small core + two pins on each of the four sides.
            Rectangle::new(gp(3, 3), Size::new(glen(10), glen(10)))
                .into_styled(stroke)
                .draw(t)?;
            Rectangle::new(gp(6, 6), Size::new(glen(4), glen(4)))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(6, 3), gp(6, 1)).into_styled(stroke).draw(t)?;
            Line::new(gp(10, 3), gp(10, 1))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(6, 13), gp(6, 15))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(10, 13), gp(10, 15))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(3, 6), gp(1, 6)).into_styled(stroke).draw(t)?;
            Line::new(gp(3, 10), gp(1, 10))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 6), gp(15, 6))
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(13, 10), gp(15, 10))
                .into_styled(stroke)
                .draw(t)
        }
        Glyph::Apps => {
            // Four equal tiles in a 2×2 grid — the unified applet launcher.
            for (gx, gy) in [(3, 3), (9, 3), (3, 9), (9, 9)] {
                Rectangle::new(gp(gx, gy), Size::new(glen(4), glen(4)))
                    .into_styled(fill)
                    .draw(t)?;
            }
            Ok(())
        }
        Glyph::Terminal => {
            // A shell prompt: a ">" caret over an underscore cursor (design's polyline +
            // line). Asymmetric (claims no axis), so it is drawn as-is.
            Polyline::new(&[gp(3, 4), gp(8, 8), gp(3, 12)])
                .into_styled(stroke)
                .draw(t)?;
            Line::new(gp(9, 13), gp(13, 13)).into_styled(stroke).draw(t)
        }
        Glyph::User => {
            // A person: a solid round head over a trapezoidal bust. Filled, not outlined —
            // a 1-bit outline of a head+shoulders at 16px reads as stray strokes; a solid
            // silhouette stays crisp. Left–right symmetric (the sym pass mirrors the left
            // half), so the bust is drawn as a centred trapezoid (two triangles).
            circ(8, 5, 3).into_styled(fill).draw(t)?;
            Triangle::new(gp(3, 14), gp(6, 9), gp(13, 14))
                .into_styled(fill)
                .draw(t)?;
            Triangle::new(gp(6, 9), gp(10, 9), gp(13, 14))
                .into_styled(fill)
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

    const ALL: [Glyph; 24] = [
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
        Glyph::Rotate,
        Glyph::Edit,
        Glyph::Eye,
        Glyph::Lifebuoy,
        Glyph::Cpu,
        Glyph::Apps,
        Glyph::Terminal,
        Glyph::User,
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

    struct Grid {
        n: usize,
        px: std::vec::Vec<bool>,
    }
    impl Grid {
        fn new(n: usize) -> Self {
            Self {
                n,
                px: std::vec![false; n * n],
            }
        }
    }
    impl OriginDimensions for Grid {
        fn size(&self) -> Size {
            Size::new(self.n as u32, self.n as u32)
        }
    }
    impl DrawTarget for Grid {
        type Color = Rgb565;
        type Error = core::convert::Infallible;
        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Rgb565>>,
        {
            for Pixel(p, _) in pixels {
                if p.x >= 0 && p.y >= 0 && (p.x as usize) < self.n && (p.y as usize) < self.n {
                    self.px[p.y as usize * self.n + p.x as usize] = true;
                }
            }
            Ok(())
        }
    }

    /// Each glyph must render mirror-symmetric about the axes [`sym`] claims for it, at the
    /// sizes the UI actually uses — this is what guards against the "crooked" look. On an even
    /// box there is no true centre column, so a 1px centred stroke can't be mirror-exact; the
    /// centre band (the column/row that maps to its own neighbour) is exempt. Glyphs with a
    /// directional mark or flip claim no axis, so the mark is not flagged.
    #[test]
    fn glyphs_respect_their_symmetry_axes() {
        for g in ALL {
            let sy = sym(g);
            if !sy.v && !sy.h {
                continue;
            }
            for s in [14usize, 16, 18, 20, 28, 36] {
                let mut grid = Grid::new(s);
                draw(&mut grid, g, Point::new(0, 0), s as u16, Rgb565::WHITE).unwrap();
                let center = |a: usize| (a as i32 - (s as i32 - 1 - a as i32)).abs() <= 1;
                for y in 0..s {
                    for x in 0..s {
                        if sy.v && !center(x) {
                            assert_eq!(
                                grid.px[y * s + x],
                                grid.px[y * s + (s - 1 - x)],
                                "{g:?} at {s}px not left-right symmetric (row {y}, col {x})"
                            );
                        }
                        if sy.h && !center(y) {
                            assert_eq!(
                                grid.px[y * s + x],
                                grid.px[(s - 1 - y) * s + x],
                                "{g:?} at {s}px not top-bottom symmetric (row {y}, col {x})"
                            );
                        }
                    }
                }
            }
        }
    }
}
