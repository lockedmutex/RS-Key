// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The hardware-agnostic UI model for the trusted-display build (`--features
//! display`): what to show on the ST7789 panel and how to interpret a CST328
//! touch. It owns no hardware — the firmware's `display.rs` (the ST7789/CST328
//! task) drives the panel and asks this crate *what* to draw and *which* button a
//! tap landed on. Keeping the model here (pure, no `embassy`/HAL) makes the
//! security-critical parts — above all the untrusted-string [`Label::clamp`] that
//! sanitizes relying-party text before it reaches the framebuffer — unit-testable
//! on the host and provable under Kani, exactly like `rsk-led`'s codec.
//!
//! The button geometry ([`ALLOW_RECT`] / [`DENY_RECT`] and [`hit_confirm`]) is the
//! single source of truth shared by the renderer and the hit-test, so a tap can
//! never approve a region the screen didn't actually paint as "Allow".

#![cfg_attr(not(test), no_std)]

pub mod render;
pub mod touch;
pub use render::render;

/// Panel geometry (Waveshare RP2350-Touch-LCD-2.8, ST7789T3, portrait).
pub const PANEL_W: u16 = 240;
/// Panel height in pixels.
pub const PANEL_H: u16 = 320;

/// A touch coordinate in panel pixels (CST328 reports the same axes the ST7789 is
/// addressed in; the firmware driver normalizes any rotation before it gets here).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Point {
    pub x: u16,
    pub y: u16,
}

impl Point {
    pub const fn new(x: u16, y: u16) -> Self {
        Self { x, y }
    }
}

/// An axis-aligned rectangle in panel pixels. Used both to paint a control and to
/// hit-test a tap against it, so the two can never disagree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    /// Is `p` inside this rectangle? Left/top inclusive, right/bottom exclusive,
    /// so abutting rectangles never both claim a point. Saturating arithmetic
    /// keeps an absurd `x+w` from wrapping.
    pub const fn contains(&self, p: Point) -> bool {
        p.x >= self.x
            && p.y >= self.y
            && p.x < self.x.saturating_add(self.w)
            && p.y < self.y.saturating_add(self.h)
    }
}

/// Maximum sanitized label length (bytes == printable-ASCII chars) kept for a
/// relying-party id or account name. Sized so the renderer can wrap it across at
/// most a couple of lines on the 240px-wide panel; anything longer is truncated
/// (with [`Label::truncated`] set) so a padded look-alike id can't push the real
/// suffix off-screen unnoticed.
pub const LABEL_MAX: usize = 48;

/// A relying-party-supplied string, sanitized for safe display. RP text is
/// **untrusted**: it can carry control bytes, terminal escapes, non-UTF-8, or be
/// arbitrarily long. [`Label::clamp`] reduces it to bounded printable 7-bit ASCII
/// before it can ever reach the framebuffer, so the renderer only handles a known,
/// fixed alphabet and [`as_str`](Label::as_str) is always valid UTF-8.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Label {
    buf: [u8; LABEL_MAX],
    len: usize,
    /// The source was longer than [`LABEL_MAX`] and got cut — the renderer should
    /// mark it so a padded look-alike can't hide its tail.
    pub truncated: bool,
}

impl Default for Label {
    fn default() -> Self {
        Self {
            buf: [0; LABEL_MAX],
            len: 0,
            truncated: false,
        }
    }
}

impl Label {
    /// Sanitize untrusted bytes into a bounded printable-ASCII label. Every byte
    /// outside `0x20..=0x7E` (controls, DEL, the whole high half — including
    /// UTF-8 continuation bytes) becomes `'?'`, so terminal escapes and bidi /
    /// homoglyph tricks can't survive. The result is at most [`LABEL_MAX`] bytes;
    /// a longer source sets [`truncated`](Label::truncated). Total function — no
    /// input panics.
    pub fn clamp(src: &[u8]) -> Self {
        let mut out = Label::default();
        for &b in src.iter() {
            if out.len == LABEL_MAX {
                out.truncated = true;
                break;
            }
            out.buf[out.len] = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
            out.len += 1;
        }
        out
    }

    /// The sanitized text. Always valid UTF-8 (it is 7-bit ASCII by construction),
    /// so this never returns the error branch — but we fall back to empty rather
    /// than `unwrap` to stay panic-free even if the invariant were ever broken.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    /// Is the label empty (no source text)?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The content of a trusted Allow/Deny prompt: the device-controlled operation
/// title plus up to two sanitized relying-party fields (e.g. rp id and account).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfirmPrompt {
    /// Trusted, device-controlled prompt header (e.g. `"Sign in?"`), supplied by
    /// the firmware applet via `rsk_sdk::Confirm`. Never relying-party text — that
    /// goes in the sanitized [`Label`]s below.
    pub title: &'static str,
    /// Primary subject — the relying-party id for FIDO, or a key label.
    pub primary: Label,
    /// Secondary subject — the account / user name, when the request carries one.
    pub secondary: Label,
}

impl ConfirmPrompt {
    /// Build a prompt from a trusted title, sanitizing both untrusted fields. Pass
    /// empty slices for fields the request doesn't carry.
    pub fn new(title: &'static str, primary: &[u8], secondary: &[u8]) -> Self {
        Self {
            title,
            primary: Label::clamp(primary),
            secondary: Label::clamp(secondary),
        }
    }
}

/// The two outcomes a confirmation tap can select.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Button {
    Allow,
    Deny,
}

/// Floating-button geometry: the two large Allow/Deny targets sit inset from the
/// panel edges with a gap between them, rather than filling the screen edge-to-
/// edge. The dead space this leaves is deliberate security margin — a tap in a
/// margin or in the centre gap selects *nothing* ([`hit_confirm`] returns `None`),
/// so a careless edge tap can't approve. The buttons are still large (96×64) so a
/// deliberate press is easy.
pub const BTN_W: u16 = 96;
/// Button height.
pub const BTN_H: u16 = 64;
/// Inset from the left/right panel edges.
const BTN_SIDE: u16 = 16;
/// Gap between the Deny and Allow buttons.
const BTN_GAP: u16 = 16;
/// Float above the bottom panel edge.
const BTN_BOTTOM: u16 = 28;
/// Top of the button row; the prompt text fills the space above it.
pub const BTN_BAND_TOP: u16 = PANEL_H - BTN_H - BTN_BOTTOM;
/// Deny on the left (the safe default), floating.
pub const DENY_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, BTN_W, BTN_H);
/// Allow on the right, floating; a full [`BTN_GAP`] separates it from Deny.
pub const ALLOW_RECT: Rect = Rect::new(BTN_SIDE + BTN_W + BTN_GAP, BTN_BAND_TOP, BTN_W, BTN_H);

// Compile-time layout invariants (paint and hit-test share these rects): the two
// floating buttons are disjoint with a real gap between them, and both sit fully
// inside the panel below the prompt area. A bad edit to the geometry fails the build.
const _: () = {
    assert!(DENY_RECT.x + DENY_RECT.w < ALLOW_RECT.x);
    assert!(DENY_RECT.x > 0 && ALLOW_RECT.x + ALLOW_RECT.w < PANEL_W);
    assert!(DENY_RECT.y > BTN_BAND_TOP - 1 && ALLOW_RECT.y + ALLOW_RECT.h < PANEL_H);
};

/// Which button, if any, a tap at `p` selects on the confirm screen. A tap in the
/// prompt area above the button band returns `None` (no accidental approval from a
/// stray touch). The two rectangles are disjoint by construction, so at most one
/// matches.
pub fn hit_confirm(p: Point) -> Option<Button> {
    if ALLOW_RECT.contains(p) {
        Some(Button::Allow)
    } else if DENY_RECT.contains(p) {
        Some(Button::Deny)
    } else {
        None
    }
}

/// The device's current status, mirrored from the LED status engine so the panel
/// can show the same idle/working/touch state the onboard LED would.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusKind {
    Boot,
    Idle,
    Processing,
    Touch,
}

impl StatusKind {
    /// A short status caption for the idle screen.
    pub const fn label(self) -> &'static str {
        match self {
            StatusKind::Boot => "Starting...",
            StatusKind::Idle => "Ready",
            StatusKind::Processing => "Working...",
            StatusKind::Touch => "Touch to confirm",
        }
    }
}

/// Top-level screen the display task renders. Phase 0 covers the boot splash, the
/// idle/status screen, and the trusted confirm prompt; the PIN pad, settings menu,
/// and lock screen land in later phases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// One-time boot splash.
    Splash,
    /// Idle/working indicator.
    Status(StatusKind),
    /// A pending Allow/Deny decision.
    Confirm(ConfirmPrompt),
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// `clamp` is total and its output is always bounded and printable 7-bit
    /// ASCII — and since printable ASCII is a subset of UTF-8, that is exactly
    /// what makes `as_str` infallible (verified concretely in the unit tests; we
    /// keep `from_utf8` out of the proof, where CBMC would unwind its validation
    /// loop unboundedly). Proven over a symbolic source one byte longer than the
    /// cap, which exercises both the in-bounds copy and the truncation edge.
    #[kani::proof]
    fn clamp_sanitizes_and_bounds() {
        let src: [u8; LABEL_MAX + 1] = kani::any();
        let label = Label::clamp(&src);
        assert!(label.len <= LABEL_MAX);
        // Every kept byte is printable 7-bit ASCII.
        let mut i = 0;
        while i < label.len {
            assert!((0x20..=0x7E).contains(&label.buf[i]));
            i += 1;
        }
        // A source past the cap is flagged and cut exactly at the cap.
        assert!(label.truncated);
        assert!(label.len == LABEL_MAX);
    }

    /// The Allow and Deny hit regions are disjoint, so no tap can select both.
    #[kani::proof]
    fn confirm_buttons_disjoint() {
        let p = Point::new(kani::any(), kani::any());
        assert!(!(ALLOW_RECT.contains(p) && DENY_RECT.contains(p)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_passes_printable_ascii() {
        let l = Label::clamp(b"github.com");
        assert_eq!(l.as_str(), "github.com");
        assert!(!l.truncated);
    }

    #[test]
    fn clamp_replaces_control_and_high_bytes() {
        // tab, newline, DEL, a high byte, and a UTF-8 lead byte all become '?'.
        let l = Label::clamp(b"a\tb\nc\x7fd\xffe\xc3\xa9");
        assert_eq!(l.as_str(), "a?b?c?d?e??");
    }

    #[test]
    fn clamp_strips_terminal_escape() {
        // An ANSI escape sequence must not survive to the renderer.
        let l = Label::clamp(b"\x1b[31mevil\x1b[0m");
        assert_eq!(l.as_str(), "?[31mevil?[0m");
    }

    #[test]
    fn clamp_truncates_and_flags() {
        let src = [b'a'; LABEL_MAX + 10];
        let l = Label::clamp(&src);
        assert_eq!(l.as_str().len(), LABEL_MAX);
        assert!(l.truncated);
    }

    #[test]
    fn clamp_empty_is_empty() {
        let l = Label::clamp(b"");
        assert!(l.is_empty());
        assert_eq!(l.as_str(), "");
        assert!(!l.truncated);
    }

    #[test]
    fn clamp_exactly_max_not_truncated() {
        let src = [b'x'; LABEL_MAX];
        let l = Label::clamp(&src);
        assert_eq!(l.as_str().len(), LABEL_MAX);
        assert!(!l.truncated);
    }

    #[test]
    fn confirm_prompt_sanitizes_both_fields() {
        let p = ConfirmPrompt::new("Sign in?", b"login.example\x00", b"al\x1bice");
        assert_eq!(p.primary.as_str(), "login.example?");
        assert_eq!(p.secondary.as_str(), "al?ice");
        assert_eq!(p.title, "Sign in?");
    }

    #[test]
    fn hit_centres_of_each_button() {
        let deny_c = Point::new(DENY_RECT.x + BTN_W / 2, DENY_RECT.y + BTN_H / 2);
        let allow_c = Point::new(ALLOW_RECT.x + BTN_W / 2, ALLOW_RECT.y + BTN_H / 2);
        assert_eq!(hit_confirm(deny_c), Some(Button::Deny));
        assert_eq!(hit_confirm(allow_c), Some(Button::Allow));
    }

    #[test]
    fn taps_off_the_floating_buttons_select_nothing() {
        let mid_h = BTN_BAND_TOP + BTN_H / 2;
        // Above the button row (the prompt area).
        assert_eq!(hit_confirm(Point::new(PANEL_W / 2, BTN_BAND_TOP - 1)), None);
        assert_eq!(hit_confirm(Point::new(0, 0)), None);
        // The centre gap between the two floating buttons.
        assert_eq!(hit_confirm(Point::new(PANEL_W / 2, mid_h)), None);
        // The left and right side margins, at button height.
        assert_eq!(hit_confirm(Point::new(2, mid_h)), None);
        assert_eq!(hit_confirm(Point::new(PANEL_W - 2, mid_h)), None);
        // Below the floating buttons (the bottom margin).
        assert_eq!(hit_confirm(Point::new(PANEL_W / 2, PANEL_H - 1)), None);
    }

    #[test]
    fn rect_contains_edges() {
        let r = Rect::new(10, 20, 30, 40);
        assert!(r.contains(Point::new(10, 20))); // top-left inclusive
        assert!(!r.contains(Point::new(40, 20))); // right exclusive (10+30)
        assert!(!r.contains(Point::new(10, 60))); // bottom exclusive (20+40)
        assert!(r.contains(Point::new(39, 59)));
    }
}
