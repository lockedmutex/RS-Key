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

pub mod font;
pub mod glyph;
pub mod render;
pub mod theme;
pub mod touch;
pub use glyph::Glyph;
pub use render::{
    render, render_add_passkey, render_audit_log, render_backup, render_backup_format,
    render_confirm_delete, render_confirm_factory_reset, render_erasing, render_firmware,
    render_hold_button, render_hold_fill, render_passkeys_list, render_pin_blocked,
    render_pin_dots, render_rebooting, render_rename, render_reveal_warning, render_seal_confirm,
    render_seed_phrase, render_service, render_share_picker, render_slip39_share, render_success,
    render_success_circle,
};

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

/// Approve-screen button geometry: a narrow **Deny** on the left (a single tap, the
/// safe default) and a wider **Hold-to-approve** on the right (a deliberate sustained
/// press — the firmware fills it as you hold, so a brush can't approve). Both float
/// above the bottom edge; the space around them is security margin, so a tap in a
/// margin or the gap selects *nothing* ([`hit_confirm`] → `None`).
pub const BTN_H: u16 = 56;
/// Inset from the left/right panel edges.
const BTN_SIDE: u16 = 14;
/// Gap between the Deny and Hold-to-approve buttons.
const BTN_GAP: u16 = 12;
/// Float above the bottom panel edge.
const BTN_BOTTOM: u16 = 16;
/// Deny button width (narrow — the safe action needs no emphasis; the design makes
/// the hold the wider of the two). Sized to fit "Cancel"; the rest of the row goes to
/// the hold so "Hold to approve" sits comfortably inside it.
const DENY_W: u16 = 72;
/// Hold-to-approve width (the rest of the row — the wider, deliberate action).
const ALLOW_W: u16 = PANEL_W - 2 * BTN_SIDE - DENY_W - BTN_GAP;
/// Top of the button row; the trusted prompt fills the space above it.
pub const BTN_BAND_TOP: u16 = PANEL_H - BTN_H - BTN_BOTTOM;
/// Deny on the left (the safe default), a single tap.
pub const DENY_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, DENY_W, BTN_H);
/// Hold-to-approve on the right, wider; a full [`BTN_GAP`] separates it from Deny.
pub const ALLOW_RECT: Rect = Rect::new(BTN_SIDE + DENY_W + BTN_GAP, BTN_BAND_TOP, ALLOW_W, BTN_H);

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

// --- PIN pad (built-in user verification) ----------------------------------

/// A key on the on-screen numeric PIN pad (the trusted-display built-in-UV input).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinKey {
    /// A digit 0–9.
    Digit(u8),
    /// Backspace — drop the last entered digit.
    Del,
    /// Commit the entered PIN.
    Ok,
    /// Abandon entry — a deliberate decline.
    Cancel,
    /// Toggle the entry between masked dots and the typed digits — so the user can check
    /// what they typed before committing.
    Reveal,
}

/// The line shown under the pad: either a danger-coloured rejection (a wrong PIN is not
/// a silent re-prompt) or a muted informational hint (the design's `enterpin` /
/// `createpin` / `confirmpin` sub-labels). Distinct from the header `title`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinCaption {
    /// The entered PIN was wrong; `retries_left` attempts remain before the hard lock.
    WrongPin { retries_left: u8 },
    /// The two new-PIN entries didn't match (the set/change confirm step).
    Mismatch,
    /// Up-front on the unlock pad: how many attempts remain before the hard lock
    /// (the design's `enterpin` "N tries remaining"). Muted, not a rejection.
    TriesRemaining { left: u8 },
    /// The set flow's first step (`createpin`): a muted "Choose a PIN" prompt.
    ChoosePin,
    /// The set flow's second step (`confirmpin`): a muted "Re-enter to confirm" prompt.
    Reenter,
}

impl PinCaption {
    /// Whether this caption is a rejection (danger-coloured) rather than an informational
    /// hint (muted) — the renderer colours the line by this.
    pub const fn is_rejection(self) -> bool {
        matches!(self, Self::WrongPin { .. } | Self::Mismatch)
    }
}

/// What the PIN screen shows: how many digits have been entered (rendered as masked
/// dots — never the digits themselves, which the firmware keeps and never paints), a
/// short header naming the step ("Enter PIN", "New PIN", "Confirm PIN", …) so the same
/// pad serves built-in UV, the unlock/delete gates, and the on-device set/change flow,
/// an `expected` count of placeholder dots (the policy minimum, so the row reads as the
/// design's fixed indicator rather than a growing run), and an optional [`PinCaption`]
/// feedback / hint line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PinPad {
    /// Count of digits entered so far (shown masked).
    pub entered: usize,
    /// The header caption — a trusted, firmware-supplied `&'static str`, never RP data.
    pub title: &'static str,
    /// Placeholder dots to outline before any are filled (the minimum PIN length). `0`
    /// shows only the filled dots — a growing run with no placeholders.
    pub expected: u8,
    /// Feedback / hint under the pad; `None` on a bare prompt.
    pub caption: Option<PinCaption>,
}

impl PinPad {
    /// The default pad header ("Enter PIN") — built-in UV and the local verify gates.
    pub const fn new(entered: usize) -> Self {
        Self::with_title(entered, "Enter PIN")
    }

    /// A pad with a custom header (the set/change flow's "New PIN" / "Confirm PIN" /
    /// "Current PIN" steps). `title` must be a trusted constant, not untrusted RP text.
    pub const fn with_title(entered: usize, title: &'static str) -> Self {
        Self {
            entered,
            title,
            expected: 0,
            caption: None,
        }
    }

    /// A pad with a header and a feedback / hint caption.
    pub const fn with_caption(
        entered: usize,
        title: &'static str,
        caption: Option<PinCaption>,
    ) -> Self {
        Self {
            entered,
            title,
            expected: 0,
            caption,
        }
    }

    /// Set the number of placeholder dots (the policy minimum), so the entry row reads as
    /// the design's fixed indicator. The filled dots still grow past it for a longer PIN.
    pub const fn expecting(mut self, expected: u8) -> Self {
        self.expected = expected;
        self
    }
}

/// PIN-pad grid: 3 columns. The bottom row is Del / 0 / OK.
pub const PIN_COLS: u16 = 3;
/// PIN-pad grid rows (1–9, then Del / 0 / OK).
pub const PIN_ROWS: u16 = 4;
/// Key width.
pub const PIN_KEY_W: u16 = 64;
/// Key height.
pub const PIN_KEY_H: u16 = 48;
const PIN_GRID_X0: u16 = 12;
const PIN_GRID_Y0: u16 = 84;
const PIN_GAP_X: u16 = 12;
const PIN_GAP_Y: u16 = 8;
/// Cancel target, in the header above the grid — kept clear of the digit keys so a
/// digit tap can never abandon entry.
pub const PIN_CANCEL_RECT: Rect = Rect::new(8, 6, 40, 34);

/// The reveal (eye) toggle, at the right of the masked-entry band — between the header
/// and the grid, so it can never be confused with a digit, Cancel, or OK. Tapping it
/// flips the entry between dots and the typed digits, on every PIN screen (the entry pad
/// is shared by built-in UV, the unlock/delete/factory-reset gates, and set/change PIN).
/// `y` is chosen so the glyph centres on the dot row (centre y 60), not 2px below it.
pub const PIN_EYE_RECT: Rect = Rect::new(204, 42, 36, 36);

/// The rectangle of the key at grid position `(col, row)` — the single source of
/// truth shared by the renderer and [`hit_pin`], so paint and hit-test can never
/// disagree (the Allow/Deny contract, extended to the pad).
pub const fn pin_key_rect(col: u16, row: u16) -> Rect {
    Rect::new(
        PIN_GRID_X0 + col * (PIN_KEY_W + PIN_GAP_X),
        PIN_GRID_Y0 + row * (PIN_KEY_H + PIN_GAP_Y),
        PIN_KEY_W,
        PIN_KEY_H,
    )
}

/// The key at grid position `(col, row)`: rows 0–2 hold digits 1–9 in reading
/// order; the bottom row is Del / 0 / OK.
pub const fn pin_grid_key(col: u16, row: u16) -> PinKey {
    match (col, row) {
        (0, 3) => PinKey::Del,
        (1, 3) => PinKey::Digit(0),
        (2, 3) => PinKey::Ok,
        _ => PinKey::Digit((row * PIN_COLS + col + 1) as u8),
    }
}

// Compile-time layout invariants: positive gaps (rows/columns disjoint), the whole
// grid fits below the header, and the Cancel target sits entirely above the grid.
// A bad geometry edit fails the build.
const _: () = {
    assert!(PIN_GAP_X > 0 && PIN_GAP_Y > 0);
    let last = pin_key_rect(PIN_COLS - 1, PIN_ROWS - 1);
    assert!(last.x + last.w <= PANEL_W && last.y + last.h <= PANEL_H);
    assert!(PIN_CANCEL_RECT.y + PIN_CANCEL_RECT.h <= PIN_GRID_Y0);
    assert!(PIN_CANCEL_RECT.x + PIN_CANCEL_RECT.w <= PANEL_W);
    // The eye toggle sits in the band between the header and the grid, inside the panel.
    assert!(PIN_EYE_RECT.x + PIN_EYE_RECT.w <= PANEL_W);
    assert!(PIN_EYE_RECT.y >= PIN_CANCEL_RECT.y + PIN_CANCEL_RECT.h);
    assert!(PIN_EYE_RECT.y + PIN_EYE_RECT.h <= PIN_GRID_Y0);
};

/// Which PIN-pad key, if any, a tap at `p` selects. Cancel (header) is tested first,
/// then the 3×4 grid. The rects are disjoint by construction, so at most one matches;
/// a tap in a gap or margin selects nothing.
pub fn hit_pin(p: Point) -> Option<PinKey> {
    if PIN_CANCEL_RECT.contains(p) {
        return Some(PinKey::Cancel);
    }
    if PIN_EYE_RECT.contains(p) {
        return Some(PinKey::Reveal);
    }
    let mut row = 0;
    while row < PIN_ROWS {
        let mut col = 0;
        while col < PIN_COLS {
            if pin_key_rect(col, row).contains(p) {
                return Some(pin_grid_key(col, row));
            }
            col += 1;
        }
        row += 1;
    }
    None
}

// --- Settings menu (interactive idle) --------------------------------------

/// Which settings page is on screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsPage {
    /// The top-level list: Brightness / Touch timeout / Display sleep / Firmware / Lock now /
    /// Security (the title-bar back chevron exits — there is no "Close" row).
    Root,
    /// Backlight-level adjust (−/+/Back).
    Brightness,
    /// Touch-timeout adjust (−/+/Back).
    Timeout,
    /// Display-sleep timeout adjust (−/+/Back) — blanks the panel after inactivity to
    /// stop image retention on the IPS glass.
    Sleep,
    /// The Security sub-page: device + FIDO PIN, the audit log, the backup status, and the
    /// (danger) Factory reset. Reached from the Root "Security" row; the title-bar back
    /// chevron returns to Root.
    Security,
}

/// Discrete backlight steps the brightness page cycles through (1 = dimmest kept on,
/// never 0 — the menu never blanks the panel you're navigating).
pub const BRIGHTNESS_LEVELS: u8 = 5;
/// Touch-timeout choices in seconds the timeout page steps between.
pub const TIMEOUT_CHOICES: [u16; 5] = [10, 20, 30, 60, 120];
/// Display-sleep choices in seconds the sleep page steps between; the final `0` is the
/// "Off" sentinel (never blank). Kept ascending by wake-awake time so `+` lengthens it
/// up to Off.
pub const SLEEP_CHOICES: [u16; 6] = [15, 30, 60, 120, 300, 0];

/// The settings view model: the current page plus the live values its pages show.
/// Carried in [`Screen::Settings`] so the renderer paints the current brightness
/// level, timeout and device identity without reaching into the firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SettingsView {
    pub page: SettingsPage,
    /// Backlight level `1..=BRIGHTNESS_LEVELS`.
    pub brightness: u8,
    /// Current presence/touch timeout, seconds.
    pub timeout_secs: u16,
    /// Current display-sleep timeout, seconds (`0` = Off, never blanks).
    pub sleep_secs: u16,
    /// bcdDevice firmware build counter, shown in hex on the Firmware row + screen.
    pub version: u16,
    /// RP2350 chip serial, shown in hex on the Firmware screen.
    pub chipid: u64,
    /// Whether the device PIN is set — the Security page's Device-PIN row shows "Change
    /// PIN" if so, else "Set PIN". The device PIN gates the on-device UI (lock, delete,
    /// factory reset), independent of the FIDO clientPIN.
    pub device_pin_set: bool,
    /// Whether the FIDO clientPIN is set — the Security page's FIDO-PIN row label.
    pub fido_pin_set: bool,
    /// Whether the seed-backup export window is sealed — the Security page's Backup row
    /// shows "Sealed" (the seed is backed up) or "Review" (the window is still open).
    pub backup_sealed: bool,
}

/// An entry on the settings Root list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RootEntry {
    Brightness,
    Timeout,
    /// Display-sleep timeout — blank the panel after inactivity (image-retention guard).
    Sleep,
    /// The Firmware screen: the installed build version and the (hold-to-confirm)
    /// reboot-to-update-over-USB action. A drill-in that runs its own hold sub-flow.
    Firmware,
    /// Lock the on-device UI now — show the [`Screen::Locked`] screen so the passkeys
    /// browser and settings need the device PIN to reopen (no-op if no PIN is set).
    LockNow,
    /// Drill into the Security sub-page ([`SettingsPage::Security`]) — device + FIDO PIN,
    /// the audit log, the backup status, and the (danger) Factory reset.
    Security,
}

/// An entry on the Security sub-page list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityEntry {
    /// Set / change the **device PIN** — gates the on-device UI (unlock, delete, factory
    /// reset). A change verifies the current device PIN first.
    DevicePin,
    /// Set / change the **FIDO clientPIN** — the WebAuthn/built-in-UV PIN, independent of
    /// the device PIN. A change verifies the current FIDO PIN first.
    FidoPin,
    /// Open the read-only on-device audit log (the recent journal events).
    AuditLog,
    /// Open the read-only seed-backup status screen (whether the recovery seed is present
    /// and the export window has been sealed).
    Backup,
    /// Erase every applet's data and return to a fresh device (danger-styled, gated by a
    /// hold-to-confirm and the device PIN if one is set).
    FactoryReset,
}

/// A control on an adjust page (brightness / timeout / sleep).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdjustKey {
    Minus,
    Plus,
    Back,
}

/// Root list: six full-width rows (Brightness / Touch timeout / Display sleep / Info /
/// Lock now / Security) — the title-bar back chevron exits the menu, so there is no
/// "Close" row. Sized so all six fit below the chrome and above the panel bottom (a
/// const-assert validates it) at a touch-comfortable row height.
const ROW_X: u16 = 16;
const ROW_W: u16 = PANEL_W - 2 * ROW_X;
const ROW_H: u16 = 38;
const ROW_GAP: u16 = 6;
const ROW_Y0: u16 = CONTENT_TOP + 2;
/// Number of Root list rows.
pub const SETTINGS_ROWS: u16 = 6;

/// The rectangle of Root list row `i` — single source of truth for the renderer and
/// [`hit_settings_root`].
pub const fn settings_row_rect(i: u16) -> Rect {
    Rect::new(ROW_X, ROW_Y0 + i * (ROW_H + ROW_GAP), ROW_W, ROW_H)
}

/// The Root entry painted on row `i`, in list order.
pub const fn settings_row_entry(i: u16) -> RootEntry {
    match i {
        0 => RootEntry::Brightness,
        1 => RootEntry::Timeout,
        2 => RootEntry::Sleep,
        3 => RootEntry::Firmware,
        4 => RootEntry::LockNow,
        _ => RootEntry::Security,
    }
}

/// Number of Security sub-page rows (Device PIN, FIDO PIN, Audit log, Backup, Factory
/// reset). They reuse the first [`settings_row_rect`] slots, so they inherit the Root
/// list's proven-disjoint geometry (a const-assert keeps them within the Root row count).
pub const SECURITY_ROWS: u16 = 5;
const _: () = assert!(SECURITY_ROWS <= SETTINGS_ROWS);

/// The Security entry on row `i`, in list order (the danger Factory reset stays last).
pub const fn security_row_entry(i: u16) -> SecurityEntry {
    match i {
        0 => SecurityEntry::DevicePin,
        1 => SecurityEntry::FidoPin,
        2 => SecurityEntry::AuditLog,
        3 => SecurityEntry::Backup,
        _ => SecurityEntry::FactoryReset,
    }
}

/// Which Security entry, if any, a tap at `p` selects. Reuses [`settings_row_rect`] for
/// the first [`SECURITY_ROWS`] rows (disjoint by construction).
pub fn hit_security(p: Point) -> Option<SecurityEntry> {
    let mut i = 0;
    while i < SECURITY_ROWS {
        if settings_row_rect(i).contains(p) {
            return Some(security_row_entry(i));
        }
        i += 1;
    }
    None
}

/// Adjust-page controls: a big −/+ pair and a full-width Back below them.
const ADJ_W: u16 = 88;
const ADJ_H: u16 = 80;
const ADJ_Y: u16 = 150;
/// Decrement target (left).
pub const ADJ_MINUS_RECT: Rect = Rect::new(16, ADJ_Y, ADJ_W, ADJ_H);
/// Increment target (right).
pub const ADJ_PLUS_RECT: Rect = Rect::new(PANEL_W - 16 - ADJ_W, ADJ_Y, ADJ_W, ADJ_H);
/// Back/Close target, full-width along the bottom — shared by every sub-page.
pub const BACK_RECT: Rect = Rect::new(16, 262, PANEL_W - 32, 46);

// Compile-time layout invariants (paint and hit-test share these rects): the Root
// rows fit on-panel with a real gap; the −/+ controls are disjoint with a gap and
// sit above Back. A bad geometry edit fails the build. NB the Root page intentionally
// paints no bottom nav bar (its title-bar back chevron is the exit), so the rows are
// allowed to extend past `NAV_TOP` — the bound here is `PANEL_H`, not `NAV_TOP`.
const _: () = {
    assert!(ROW_GAP > 0);
    // At least one brightness step (the level-bar math would underflow at 0).
    assert!(BRIGHTNESS_LEVELS >= 1);
    let last = settings_row_rect(SETTINGS_ROWS - 1);
    assert!(last.x + last.w <= PANEL_W && last.y + last.h <= PANEL_H);
    assert!(ADJ_MINUS_RECT.x + ADJ_MINUS_RECT.w < ADJ_PLUS_RECT.x);
    assert!(ADJ_PLUS_RECT.x + ADJ_PLUS_RECT.w <= PANEL_W);
    assert!(ADJ_MINUS_RECT.y + ADJ_MINUS_RECT.h <= BACK_RECT.y);
    assert!(BACK_RECT.x + BACK_RECT.w <= PANEL_W && BACK_RECT.y + BACK_RECT.h <= PANEL_H);
};

/// Which Root entry, if any, a tap at `p` selects. Rows are disjoint by
/// construction, so at most one matches; a tap in a gap selects nothing.
pub fn hit_settings_root(p: Point) -> Option<RootEntry> {
    let mut i = 0;
    while i < SETTINGS_ROWS {
        if settings_row_rect(i).contains(p) {
            return Some(settings_row_entry(i));
        }
        i += 1;
    }
    None
}

/// Which adjust control, if any, a tap at `p` selects on the brightness / timeout / sleep
/// adjust pages (−/+/Back). Disjoint by construction.
pub fn hit_adjust(p: Point) -> Option<AdjustKey> {
    if ADJ_MINUS_RECT.contains(p) {
        Some(AdjustKey::Minus)
    } else if ADJ_PLUS_RECT.contains(p) {
        Some(AdjustKey::Plus)
    } else if BACK_RECT.contains(p) {
        Some(AdjustKey::Back)
    } else {
        None
    }
}

/// Step the brightness level by `delta` (+1/−1), clamped to `1..=BRIGHTNESS_LEVELS`.
/// The display task applies the result to the backlight PWM; the menu only models it.
pub fn step_brightness(level: u8, delta: i8) -> u8 {
    (level as i16 + delta as i16).clamp(1, BRIGHTNESS_LEVELS as i16) as u8
}

/// Step the touch timeout to the next/previous [`TIMEOUT_CHOICES`] entry by `delta`
/// (+1/−1), snapping a non-listed current value (e.g. a phy-record override that
/// isn't one of the menu's choices) to the nearest choice first. Returns seconds.
pub fn step_timeout(cur_secs: u16, delta: i8) -> u16 {
    let mut idx = 0;
    let mut best = u16::MAX;
    let mut i = 0;
    while i < TIMEOUT_CHOICES.len() {
        let d = cur_secs.abs_diff(TIMEOUT_CHOICES[i]);
        if d < best {
            best = d;
            idx = i;
        }
        i += 1;
    }
    let ni = (idx as i32 + delta as i32).clamp(0, TIMEOUT_CHOICES.len() as i32 - 1) as usize;
    TIMEOUT_CHOICES[ni]
}

/// Step the display-sleep timeout to the next/previous [`SLEEP_CHOICES`] entry by
/// `delta` (+1/−1). The trailing `0` ("Off") sentinel sits at the top, so `+` from the
/// longest duration reaches Off and `−` from Off returns to the longest; a current value
/// not in the list snaps to the nearest real duration first. Returns seconds (`0` = Off).
pub fn step_sleep(cur_secs: u16, delta: i8) -> u16 {
    let real = SLEEP_CHOICES.len() - 1; // index of the "Off" sentinel
    let idx = if cur_secs == 0 {
        real
    } else {
        let mut best = u16::MAX;
        let mut bi = 0;
        let mut i = 0;
        while i < real {
            let d = cur_secs.abs_diff(SLEEP_CHOICES[i]);
            if d < best {
                best = d;
                bi = i;
            }
            i += 1;
        }
        bi
    };
    let ni = (idx as i32 + delta as i32).clamp(0, SLEEP_CHOICES.len() as i32 - 1) as usize;
    SLEEP_CHOICES[ni]
}

/// Lowercase-hex nibble (`0-9a-f`).
const fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

/// Lowercase-hex a `u16` into a fixed 4-byte buffer — no alloc, for the Info screen.
/// Always printable ASCII, so [`core::str::from_utf8`] on it never fails.
pub fn hex_u16(v: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    let mut i = 0;
    while i < 4 {
        out[i] = hex_nibble(((v >> ((3 - i) * 4)) & 0xF) as u8);
        i += 1;
    }
    out
}

/// Lowercase-hex a `u64` into a fixed 16-byte buffer — no alloc, for the Info screen.
pub fn hex_u64(v: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = hex_nibble(((v >> ((15 - i) * 4)) & 0xF) as u8);
        i += 1;
    }
    out
}

// --- Design-system widgets (the re-skin layout) ----------------------------

/// Legacy single-strip header height — still used by the full-screen approve modal
/// ([`Screen::Confirm`]); the tab screens use the two-tier chrome below instead.
pub const HEADER_H: u16 = 30;

/// The persistent top **status bar**: a mono "RS-Key" wordmark at the left and the USB
/// power indicator at the right. Present on every tab screen (the design's framing
/// chrome).
pub const STATUS_BAR_H: u16 = 24;
/// The **title bar** below the status bar: an optional back chevron plus the screen
/// title.
pub const TITLE_BAR_H: u16 = 30;
/// Top of a tab screen's content, below both chrome strips.
pub const CONTENT_TOP: u16 = STATUS_BAR_H + TITLE_BAR_H;

/// The title-bar back affordance (a pushed screen's "return to parent" chevron), in the
/// title bar below the status bar. Distinct from [`PK_BACK_RECT`] — the chrome-less
/// destructive modals keep their chevron in the very top-left, but a tab screen's status
/// bar occupies that corner, so its back moves one strip down.
pub const TITLE_BACK_RECT: Rect = Rect::new(4, STATUS_BAR_H, 44, TITLE_BAR_H);

/// Did a tap at `p` hit the title-bar back chevron?
pub fn hit_title_back(p: Point) -> bool {
    TITLE_BACK_RECT.contains(p)
}

/// The title-bar **edit** affordance — the service detail's pencil, mirroring the back
/// chevron at the right edge of the title strip. A tap here opens the rename screen.
pub const TITLE_EDIT_RECT: Rect = Rect::new(PANEL_W - 4 - 44, STATUS_BAR_H, 44, TITLE_BAR_H);

/// Did a tap at `p` hit the title-bar edit (rename) affordance?
pub fn hit_title_edit(p: Point) -> bool {
    TITLE_EDIT_RECT.contains(p)
}

// Compile-time: the edit affordance sits in the title strip, clear of (right of) the
// back chevron, so a back tap and a rename tap can never collide.
const _: () = {
    assert!(TITLE_EDIT_RECT.y >= STATUS_BAR_H);
    assert!(TITLE_EDIT_RECT.y + TITLE_EDIT_RECT.h <= CONTENT_TOP);
    assert!(TITLE_BACK_RECT.x + TITLE_BACK_RECT.w < TITLE_EDIT_RECT.x);
    assert!(TITLE_EDIT_RECT.x + TITLE_EDIT_RECT.w <= PANEL_W);
};

/// Bottom navigation-bar height.
pub const NAV_H: u16 = 38;
/// Top edge of the bottom nav bar.
pub const NAV_TOP: u16 = PANEL_H - NAV_H;

/// A bottom-nav destination (the three top-level tabs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NavTab {
    Home,
    Passkeys,
    Settings,
}

/// The nav tabs in display (left-to-right) order.
pub const NAV_TABS: [NavTab; 3] = [NavTab::Home, NavTab::Passkeys, NavTab::Settings];
const NAV_CELL_W: u16 = PANEL_W / 3;

/// The rect of nav tab `i` (`0..3`) — single source of truth for the renderer and
/// [`hit_nav`].
pub const fn nav_tab_rect(i: u16) -> Rect {
    Rect::new(i * NAV_CELL_W, NAV_TOP, NAV_CELL_W, NAV_H)
}

/// Which nav tab a tap selects, or `None` if it lands above the nav bar.
pub fn hit_nav(p: Point) -> Option<NavTab> {
    if p.y < NAV_TOP {
        return None;
    }
    let i = (p.x / NAV_CELL_W).min(NAV_TABS.len() as u16 - 1);
    Some(NAV_TABS[i as usize])
}

/// List-row height (a lifted card holding icon + label + trailing + chevron).
pub const LIST_ROW_H: u16 = 30;
const LIST_ROW_GAP: u16 = 6;
const LIST_ROW_X: u16 = 10;
/// List-row width, inset from both panel edges.
pub const LIST_ROW_W: u16 = PANEL_W - 2 * LIST_ROW_X;

/// The rect of list row `i`, for a list whose first row starts at `y0`. Screen-
/// supplied `y0` lets Home (rows low, under the status block) and Settings (rows
/// from the top) share one row geometry. Single source of truth for paint + hit.
pub const fn row_rect(y0: u16, i: u16) -> Rect {
    Rect::new(
        LIST_ROW_X,
        y0 + i * (LIST_ROW_H + LIST_ROW_GAP),
        LIST_ROW_W,
        LIST_ROW_H,
    )
}

/// Which list row (`0..n`) a tap selects, for a list of `n` rows starting at `y0`.
/// Rows are disjoint by construction, so at most one matches.
pub fn hit_list(p: Point, y0: u16, n: u16) -> Option<u16> {
    let mut i = 0;
    while i < n {
        if row_rect(y0, i).contains(p) {
            return Some(i);
        }
        i += 1;
    }
    None
}

// Compile-time: the nav tiles the width and sits on-panel; rows keep a real gap; the
// two chrome strips stack inside the top of the panel and the title-bar back chevron
// sits entirely within the title strip, clear of (above) any content.
const _: () = {
    assert!(NAV_CELL_W * 3 <= PANEL_W);
    assert!(NAV_TOP + NAV_H <= PANEL_H);
    assert!(LIST_ROW_GAP > 0 && LIST_ROW_X > 0 && HEADER_H < NAV_TOP);
    assert!(TITLE_BACK_RECT.y >= STATUS_BAR_H);
    assert!(TITLE_BACK_RECT.y + TITLE_BACK_RECT.h <= CONTENT_TOP);
    assert!(CONTENT_TOP <= PK_LIST_TOP && CONTENT_TOP <= ROW_Y0);
};

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

/// What the Home tab shows: the device status, mirrored from the LED engine. Info
/// rows backed by live data (PIN set, passkey count) land in a later wave.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HomeView {
    pub status: StatusKind,
}

// --- Passkeys list + service detail ----------------------------------------

/// Rows shown per page on a scrollable list (Passkeys, accounts, audit log). A longer
/// set is paged — the [pager band](PAGER_PREV_RECT) sits in the row slot just below
/// these, so the count must leave room for it above the nav bar. The footer shows the
/// true total on a single page; the pager shows "page / pages" when there is more.
pub const PK_ROWS_MAX: usize = 5;
/// Top of the first passkey row — below the status + title bars, clear of the nav bar
/// and footer.
pub const PK_LIST_TOP: u16 = CONTENT_TOP + 4;

/// One relying-party row on the Passkeys list: a sanitized rpId, an optional device-local
/// nickname ([`render_passkeys_list`] shows it instead of the rpId when set), and how many
/// resident credentials it holds. The firmware fills these from `rsk_fido::passkeys`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RpRow {
    pub id: Label,
    /// The device-local nickname, or empty for none (then the rpId `id` shows).
    pub nick: Label,
    pub accounts: u8,
}

impl RpRow {
    /// The label to show: the nickname if one is set, else the rpId.
    pub fn shown(&self) -> &str {
        if self.nick.is_empty() {
            self.id.as_str()
        } else {
            self.nick.as_str()
        }
    }
}

/// One account row on the per-RP service detail: a sanitized account label and whether
/// the credential is UV-gated (credProtect ≥ 2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AccountRow {
    pub name: Label,
    pub protected: bool,
}

/// The service-detail back affordance: the header's top-left, so a tap there returns
/// to the Passkeys list. In the header strip, clear of the rows and the nav bar.
pub const PK_BACK_RECT: Rect = Rect::new(8, 6, 42, 34);

// Compile-time: the back chevron sits in the header above the first row, and the
// visible rows *plus the pager band* (one more slot) fit between the list top and the
// nav bar.
const _: () = {
    assert!(PK_BACK_RECT.y + PK_BACK_RECT.h <= PK_LIST_TOP);
    assert!(PK_LIST_TOP + (PK_ROWS_MAX as u16 + 1) * (LIST_ROW_H + LIST_ROW_GAP) <= NAV_TOP);
};

// --- List pager (Prev / Next, for any list longer than one page) -----------

/// The pager band: the row slot directly below the last list row ([`PK_ROWS_MAX`]), so
/// a paged list keeps its row geometry and the band still clears the nav bar.
const PAGER_BAND: Rect = row_rect(PK_LIST_TOP, PK_ROWS_MAX as u16);
/// Width of each pager arrow tap target (the centre is the non-tappable page indicator).
const PAGER_BTN_W: u16 = 64;
/// Previous-page tap target (left end of the band).
pub const PAGER_PREV_RECT: Rect = Rect::new(PAGER_BAND.x, PAGER_BAND.y, PAGER_BTN_W, PAGER_BAND.h);
/// Next-page tap target (right end of the band).
pub const PAGER_NEXT_RECT: Rect = Rect::new(
    PAGER_BAND.x + PAGER_BAND.w - PAGER_BTN_W,
    PAGER_BAND.y,
    PAGER_BTN_W,
    PAGER_BAND.h,
);

// Compile-time: the two arrows are disjoint with a real gap (the indicator) between
// them, and the whole band clears the nav bar.
const _: () = {
    assert!(PAGER_PREV_RECT.x + PAGER_PREV_RECT.w < PAGER_NEXT_RECT.x);
    assert!(PAGER_BAND.y + PAGER_BAND.h <= NAV_TOP);
};

/// A pager arrow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PagerKey {
    Prev,
    Next,
}

/// Which pager arrow, if any, a tap at `p` selects. The firmware clamps the resulting
/// page to `0..page_count`, so a tap on a dimmed end-arrow is a harmless no-op.
pub fn hit_pager(p: Point) -> Option<PagerKey> {
    if PAGER_PREV_RECT.contains(p) {
        Some(PagerKey::Prev)
    } else if PAGER_NEXT_RECT.contains(p) {
        Some(PagerKey::Next)
    } else {
        None
    }
}

/// Number of pages for `total` items at [`PK_ROWS_MAX`] per page — always ≥ 1, so an
/// empty list is "page 1 / 1". Single source of truth for the renderer and the firmware
/// modals, so a Next tap and the painted indicator can never disagree.
pub fn page_count(total: u16) -> u16 {
    total.max(1).div_ceil(PK_ROWS_MAX as u16)
}

/// Did a tap at `p` hit the service-detail back chevron?
pub fn hit_pk_back(p: Point) -> bool {
    PK_BACK_RECT.contains(p)
}

// --- Confirm-delete (a destructive Passkeys mutation) ----------------------

/// The full-width **Hold to delete** button on the Confirm-Delete screen. There is
/// no tap-able Deny — the header [`PK_BACK_RECT`] chevron cancels, and the delete
/// itself is a single deliberate hold (the firmware fills it as you hold, so a brush
/// can't delete). It shares the approve-screen button band so the destructive action
/// sits where the eye expects the primary control, but spans the full width (it is
/// alone there) and is painted / filled in [`theme::DENY`].
pub const DEL_HOLD_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, PANEL_W - 2 * BTN_SIDE, BTN_H);

// Compile-time: the hold button sits fully inside the panel and below the header
// back chevron, so a cancel tap and a delete hold can never overlap.
const _: () = {
    assert!(DEL_HOLD_RECT.x > 0 && DEL_HOLD_RECT.x + DEL_HOLD_RECT.w <= PANEL_W);
    assert!(DEL_HOLD_RECT.y > PK_BACK_RECT.y + PK_BACK_RECT.h);
    assert!(DEL_HOLD_RECT.y + DEL_HOLD_RECT.h <= PANEL_H);
};

/// Did a tap at `p` hit the Confirm-Delete hold button?
pub fn hit_del_hold(p: Point) -> bool {
    DEL_HOLD_RECT.contains(p)
}

// --- Rename (set a device-local RP nickname via a character wheel) ----------

/// The character set the rename wheel cycles through: lowercase, digits, and a few
/// punctuation marks plus a trailing space. A deliberately small printable-ASCII
/// alphabet — the stored nickname is sanitized by [`Label`] regardless, but cycling a
/// known set keeps the wheel legible and the entry predictable.
pub const RENAME_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-_. ";

/// A key on the rename character wheel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RenameKey {
    /// Cycle the candidate character up (next in [`RENAME_CHARSET`]).
    Up,
    /// Cycle the candidate character down (previous).
    Down,
    /// Append the current candidate to the nickname.
    Insert,
    /// Delete the last character of the nickname.
    Backspace,
    /// Commit the nickname.
    Save,
}

/// The nickname value field (shows the current text + a caret).
pub const RN_FIELD_RECT: Rect = Rect::new(12, CONTENT_TOP + 22, 216, 34);
/// Cycle-up button (top of the centre column).
pub const RN_UP_RECT: Rect = Rect::new(94, 122, 52, 36);
/// Cycle-down button (bottom of the centre column).
pub const RN_DOWN_RECT: Rect = Rect::new(94, 196, 52, 36);
/// Backspace key (left of the wheel).
pub const RN_BKSP_RECT: Rect = Rect::new(16, 160, 56, 56);
/// Insert key (right of the wheel) — appends the candidate.
pub const RN_INS_RECT: Rect = Rect::new(168, 160, 56, 56);
/// The full-width **Save** button, in the shared bottom button band.
pub const RN_SAVE_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, PANEL_W - 2 * BTN_SIDE, BTN_H);

/// Which rename-wheel key, if any, a tap at `p` selects. The rects are disjoint by
/// construction (proven below), so at most one matches; the title-bar back chevron
/// (handled separately) cancels.
pub fn hit_rename(p: Point) -> Option<RenameKey> {
    if RN_UP_RECT.contains(p) {
        Some(RenameKey::Up)
    } else if RN_DOWN_RECT.contains(p) {
        Some(RenameKey::Down)
    } else if RN_BKSP_RECT.contains(p) {
        Some(RenameKey::Backspace)
    } else if RN_INS_RECT.contains(p) {
        Some(RenameKey::Insert)
    } else if RN_SAVE_RECT.contains(p) {
        Some(RenameKey::Save)
    } else {
        None
    }
}

// Compile-time: every wheel control is on-panel, the field clears the status/title
// chrome, the wheel sits above the Save band, and the five tap targets are pairwise
// disjoint (so no tap is ambiguous). The centre column (Up/Down) is separated from the
// side keys (Backspace/Insert) by x; Up/Down/Save are separated from each other by y.
const _: () = {
    assert!(RN_FIELD_RECT.y >= CONTENT_TOP);
    assert!(RN_UP_RECT.y > RN_FIELD_RECT.y + RN_FIELD_RECT.h);
    assert!(RN_UP_RECT.y + RN_UP_RECT.h <= RN_DOWN_RECT.y); // Up above Down
    assert!(RN_DOWN_RECT.y + RN_DOWN_RECT.h <= RN_SAVE_RECT.y); // wheel above Save
    assert!(RN_SAVE_RECT.y + RN_SAVE_RECT.h <= PANEL_H);
    // Side keys are clear of the centre column by x.
    assert!(RN_BKSP_RECT.x + RN_BKSP_RECT.w <= RN_UP_RECT.x);
    assert!(RN_UP_RECT.x + RN_UP_RECT.w <= RN_INS_RECT.x);
    assert!(RN_INS_RECT.x + RN_INS_RECT.w <= PANEL_W);
};

// --- Success screens (the design's "pop" confirmation moments) --------------

/// Which celebratory success screen to paint — a successful approve, an on-device
/// passkey delete, or a completed factory wipe. Each has its own glyph, colour, and
/// wording (a green check for approve/delete; the grey [`Glyph::Rotate`] for the
/// wipe, which restarts the device). The screen is a full-frame standalone like
/// [`render_confirm_delete`] / [`render_pin_blocked`], not a `Screen` variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuccessKind {
    /// A host ceremony's trusted approval was granted (any applet).
    Approved,
    /// A resident passkey was deleted on-device.
    Deleted,
    /// The device was factory-wiped (about to reboot into a fresh state).
    Wiped,
}

/// Did a tap at `p` hit the success screen's **Done** button? It shares the
/// destructive-flow button band ([`DEL_HOLD_RECT`]), so no new geometry is
/// introduced — the same disjointness invariants apply.
pub fn hit_success_done(p: Point) -> bool {
    DEL_HOLD_RECT.contains(p)
}

// --- Audit log (read-only journal viewer) ----------------------------------

/// The class of a journal event, for the on-device audit log — it sets the row's
/// status-dot colour and label. The firmware maps each `rsk_fido::journal::EV_*` code
/// onto one of these at the boundary (rsk-ui has no dependency on rsk-fido), the way it
/// clamps an rpId into a [`Label`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AuditKind {
    /// A credential was used to sign in (FIDO getAssertion / U2F auth) — green dot.
    Login,
    /// A credential was created (FIDO makeCredential / U2F register) — blue dot.
    Register,
    /// The device PIN was set or changed — grey dot.
    Pin,
    /// A PIN lockout: too many wrong PINs — red dot.
    Denied,
    /// A power-cycle boundary (the first entry of each boot) — grey dot.
    Boot,
    /// A factory reset — red dot.
    Reset,
    /// The operation-lock was engaged or released — grey dot.
    Lock,
    /// A configuration change (minPINLength, alwaysUv, enterprise attestation) — grey dot.
    Config,
    /// A seed-backup export / load / finalize — blue dot.
    Backup,
    /// Any other recorded event — grey dot.
    #[default]
    Other,
}

impl AuditKind {
    /// The row label — static, so it is decided (and host-tested) here, not in the
    /// firmware glue.
    pub const fn label(self) -> &'static str {
        match self {
            AuditKind::Login => "Signed in",
            AuditKind::Register => "Passkey added",
            AuditKind::Pin => "PIN changed",
            AuditKind::Denied => "PIN blocked",
            AuditKind::Boot => "Powered on",
            AuditKind::Reset => "Factory reset",
            AuditKind::Lock => "Lock changed",
            AuditKind::Config => "Setting changed",
            AuditKind::Backup => "Backup",
            AuditKind::Other => "Event",
        }
    }
}

/// One row of the on-device audit log: the event class (its dot colour + label) and how
/// long ago it happened, if known. `secs_ago` is `None` for entries from an earlier
/// power cycle — there is no wall clock, so cross-boot deltas are not computed and the
/// row then shows no time. Firmware builds these from `rsk_fido::journal::EventView`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AuditRow {
    pub kind: AuditKind,
    pub secs_ago: Option<u32>,
}

/// The seed-backup status the read-only Backup screen ([`render_backup`]) paints —
/// the bits the device genuinely tracks, mirroring `rsk_fido`'s `BackupStatus`. There
/// is no fictional "N of M shares" state: backup is a one-time seed export over USB,
/// then sealed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackupView {
    /// The one-time export *window* has been sealed (a `BACKUP_FINALIZE` closed it). This is
    /// a window-state fact, **not** proof a recovery copy exists — the device cannot verify an
    /// export happened — so the screen states the window state, not "backed up". A factory
    /// reset / host authenticatorReset reopens it.
    pub sealed: bool,
    /// A device master seed is present (something to back up / recover).
    pub has_seed: bool,
    /// This build can export the seed at all — `false` on a `fips-profile` device, where
    /// the seed is non-exportable and recovery is restore-only.
    pub exportable: bool,
    /// The on-device recovery-phrase reveal + seal actions are offered — true only while the
    /// backup window is open and the seed is readable (`has_seed && exportable && !sealed &&
    /// !locked`). When false the screen is status-only.
    pub can_reveal: bool,
}

/// A tappable action on the Backup screen, present only when [`BackupView::can_reveal`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackupKey {
    /// Show the 24-word recovery phrase on the trusted display (device-PIN + hold gated).
    Reveal,
    /// Seal the backup window — close it so the seed can no longer be exported or shown
    /// (hold gated). A factory reset reopens it.
    Seal,
}

/// The primary "Show recovery phrase" button on the Backup screen (shown only when
/// [`BackupView::can_reveal`]).
pub const BACKUP_REVEAL_RECT: Rect = Rect::new(16, 224, PANEL_W - 32, 40);
/// The "Seal backup" button below it.
pub const BACKUP_SEAL_RECT: Rect = Rect::new(16, 268, PANEL_W - 32, 40);

const _: () = {
    // Both action buttons sit in the content area, below the fact rows, disjoint, on-panel.
    assert!(BACKUP_REVEAL_RECT.y > CONTENT_TOP);
    assert!(BACKUP_REVEAL_RECT.y + BACKUP_REVEAL_RECT.h <= BACKUP_SEAL_RECT.y);
    assert!(BACKUP_SEAL_RECT.y + BACKUP_SEAL_RECT.h <= PANEL_H);
    assert!(BACKUP_REVEAL_RECT.x + BACKUP_REVEAL_RECT.w <= PANEL_W);
    // Clear of the title-bar back chevron (the screen's other tap target).
    assert!(BACKUP_REVEAL_RECT.y > TITLE_BACK_RECT.y + TITLE_BACK_RECT.h);
};

/// Which Backup action, if any, a tap at `p` selects. Only meaningful when the screen was
/// drawn with [`BackupView::can_reveal`]; the caller gates on that.
pub fn hit_backup(p: Point) -> Option<BackupKey> {
    if BACKUP_REVEAL_RECT.contains(p) {
        Some(BackupKey::Reveal)
    } else if BACKUP_SEAL_RECT.contains(p) {
        Some(BackupKey::Seal)
    } else {
        None
    }
}

// === Recovery reveal: format chooser, SLIP-39 T/N picker, share display ===

/// The recovery format chosen on [`render_backup_format`] — a single BIP-39 phrase, or
/// SLIP-39 Shamir shares. Both reveal the master secret on the trusted screen (never USB).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackupFormat {
    /// One 24-word BIP-39 phrase.
    Phrase,
    /// `T`-of-`N` SLIP-39 Shamir shares.
    Shares,
}

/// The "Single phrase" choice card on the format chooser.
pub const FMT_PHRASE_RECT: Rect = Rect::new(16, 92, PANEL_W - 32, 60);
/// The "Shamir shares" choice card, below it.
pub const FMT_SHARES_RECT: Rect = Rect::new(16, 164, PANEL_W - 32, 60);

const _: () = {
    // Both cards sit below the chrome-less back chevron, stacked and disjoint, on-panel.
    assert!(FMT_PHRASE_RECT.y > PK_BACK_RECT.y + PK_BACK_RECT.h);
    assert!(FMT_PHRASE_RECT.y + FMT_PHRASE_RECT.h <= FMT_SHARES_RECT.y);
    assert!(FMT_SHARES_RECT.y + FMT_SHARES_RECT.h <= PANEL_H);
};

/// Which recovery-format card a tap at `p` selects; the chrome-less [`PK_BACK_RECT`] chevron
/// cancels (handled by [`hit_pk_back`]).
pub fn hit_backup_format(p: Point) -> Option<BackupFormat> {
    if FMT_PHRASE_RECT.contains(p) {
        Some(BackupFormat::Phrase)
    } else if FMT_SHARES_RECT.contains(p) {
        Some(BackupFormat::Shares)
    } else {
        None
    }
}

/// The smallest / largest share counts the on-device picker offers. A meaningful Shamir
/// split needs ≥ 2 shares (1-of-1 is just the seed); 5 keeps the written-down set practical
/// on paper, while the crate itself supports up to `rsk_slip39::MAX_SHARES`.
pub const SHARE_MIN: u8 = 2;
/// See [`SHARE_MIN`].
pub const SHARE_MAX: u8 = 5;

/// A control on the SLIP-39 share picker ([`render_share_picker`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShareAdjust {
    /// Lower the recovery threshold `T`.
    TMinus,
    /// Raise the recovery threshold `T`.
    TPlus,
    /// Lower the total share count `N`.
    NMinus,
    /// Raise the total share count `N`.
    NPlus,
    /// Proceed to reveal the shares.
    Continue,
}

const PICK_STEP: u16 = 46;
/// Threshold `T` stepper (decrement / increment).
pub const PICK_T_MINUS_RECT: Rect = Rect::new(16, 86, PICK_STEP, PICK_STEP);
/// See [`PICK_T_MINUS_RECT`].
pub const PICK_T_PLUS_RECT: Rect = Rect::new(PANEL_W - 16 - PICK_STEP, 86, PICK_STEP, PICK_STEP);
/// Total `N` stepper (decrement / increment).
pub const PICK_N_MINUS_RECT: Rect = Rect::new(16, 162, PICK_STEP, PICK_STEP);
/// See [`PICK_N_MINUS_RECT`].
pub const PICK_N_PLUS_RECT: Rect = Rect::new(PANEL_W - 16 - PICK_STEP, 162, PICK_STEP, PICK_STEP);
/// The full-width Continue button (shares the destructive-band geometry).
pub const PICK_CONTINUE_RECT: Rect =
    Rect::new(BTN_SIDE, BTN_BAND_TOP, PANEL_W - 2 * BTN_SIDE, BTN_H);

const _: () = {
    // Each stepper's −/+ are disjoint with a gap; the two rows and the Continue button stack
    // on-panel below the chrome.
    assert!(PICK_T_MINUS_RECT.x + PICK_T_MINUS_RECT.w < PICK_T_PLUS_RECT.x);
    assert!(PICK_N_MINUS_RECT.x + PICK_N_MINUS_RECT.w < PICK_N_PLUS_RECT.x);
    assert!(PICK_T_MINUS_RECT.y > CONTENT_TOP);
    assert!(PICK_T_MINUS_RECT.y + PICK_T_MINUS_RECT.h <= PICK_N_MINUS_RECT.y);
    assert!(PICK_N_MINUS_RECT.y + PICK_N_MINUS_RECT.h <= PICK_CONTINUE_RECT.y);
    assert!(PICK_CONTINUE_RECT.y + PICK_CONTINUE_RECT.h <= PANEL_H);
    assert!(SHARE_MIN >= 2 && SHARE_MAX <= rsk_slip39_max());
};

/// `rsk_slip39::MAX_SHARES` as a const, kept local so the picker bound can be const-asserted
/// without a cross-crate const dependency (the two are pinned equal by the firmware's use).
const fn rsk_slip39_max() -> u8 {
    16
}

/// Which picker control a tap at `p` selects; the chrome-less top-left [`PK_BACK_RECT`] chevron
/// ([`hit_pk_back`]) returns to the format chooser.
pub fn hit_share_picker(p: Point) -> Option<ShareAdjust> {
    if PICK_T_MINUS_RECT.contains(p) {
        Some(ShareAdjust::TMinus)
    } else if PICK_T_PLUS_RECT.contains(p) {
        Some(ShareAdjust::TPlus)
    } else if PICK_N_MINUS_RECT.contains(p) {
        Some(ShareAdjust::NMinus)
    } else if PICK_N_PLUS_RECT.contains(p) {
        Some(ShareAdjust::NPlus)
    } else if PICK_CONTINUE_RECT.contains(p) {
        Some(ShareAdjust::Continue)
    } else {
        None
    }
}

/// Apply a `±1` step to the `(threshold, total)` pair, preserving `SHARE_MIN ≤ T ≤ N ≤
/// SHARE_MAX`: raising `T` past `N` raises `N` with it; lowering `N` below `T` lowers `T`
/// with it — so the pair is always a valid `T`-of-`N` split. [`ShareAdjust::Continue`] is a
/// no-op here (the caller acts on it).
pub fn step_share_params(threshold: u8, total: u8, key: ShareAdjust) -> (u8, u8) {
    let (mut t, mut n) = (threshold, total);
    match key {
        ShareAdjust::TMinus => t = t.saturating_sub(1).max(SHARE_MIN),
        ShareAdjust::TPlus => {
            t = t.saturating_add(1).min(SHARE_MAX);
            if t > n {
                n = t;
            }
        }
        ShareAdjust::NMinus => {
            n = n.saturating_sub(1).max(SHARE_MIN);
            if t > n {
                t = n;
            }
        }
        ShareAdjust::NPlus => n = n.saturating_add(1).min(SHARE_MAX),
        ShareAdjust::Continue => {}
    }
    (t, n)
}

/// What the [`render_reveal_warning`] gate is about to show, so its copy names the right
/// secret (a phrase, or shares).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevealKind {
    /// The 24-word BIP-39 phrase.
    Phrase,
    /// The SLIP-39 Shamir shares.
    Shares,
}

/// Top-level screen the display task renders. The three top-level **tabs** (Home,
/// Passkeys, Settings) carry the bottom nav bar and are shown by the idle loop; the
/// **modals** (Splash, Confirm, Pin) are full-screen and shown by the worker.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// One-time boot splash.
    Splash,
    /// The device-locked screen: a padlock, "Locked", and a "touch to unlock" hint. The
    /// whole screen is the unlock affordance (any tap starts the on-screen PIN entry).
    /// Gates only the on-device UI — host CTAP ceremonies are unaffected.
    Locked,
    /// The Home tab — status indicator + bottom nav.
    Home(HomeView),
    /// A pending trusted Deny / Hold-to-approve decision.
    Confirm(ConfirmPrompt),
    /// The built-in-UV PIN pad, showing how many digits have been entered (masked).
    Pin(PinPad),
    /// The on-device settings menu (Root list or one of its sub-pages) + bottom nav.
    Settings(SettingsView),
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

    /// No tap selects two PIN-pad keys at once: the Cancel target is disjoint from
    /// every grid key, and any two distinct grid cells are disjoint — so `hit_pin`
    /// maps a tap to at most one key (a stray touch can't enter a digit *and*
    /// commit).
    #[kani::proof]
    fn pin_keys_disjoint() {
        let p = Point::new(kani::any(), kani::any());
        let mut r = 0;
        while r < PIN_ROWS {
            let mut c = 0;
            while c < PIN_COLS {
                assert!(!(PIN_CANCEL_RECT.contains(p) && pin_key_rect(c, r).contains(p)));
                c += 1;
            }
            r += 1;
        }
        let (c1, r1): (u16, u16) = (kani::any(), kani::any());
        let (c2, r2): (u16, u16) = (kani::any(), kani::any());
        kani::assume(c1 < PIN_COLS && r1 < PIN_ROWS && c2 < PIN_COLS && r2 < PIN_ROWS);
        kani::assume((c1, r1) != (c2, r2));
        assert!(!(pin_key_rect(c1, r1).contains(p) && pin_key_rect(c2, r2).contains(p)));
        // The reveal (eye) toggle never overlaps Cancel or any grid key, so peeking at the
        // PIN can't enter a digit, commit, or cancel.
        assert!(!(PIN_EYE_RECT.contains(p) && PIN_CANCEL_RECT.contains(p)));
        let (c, r): (u16, u16) = (kani::any(), kani::any());
        kani::assume(c < PIN_COLS && r < PIN_ROWS);
        assert!(!(PIN_EYE_RECT.contains(p) && pin_key_rect(c, r).contains(p)));
    }

    /// No tap selects two settings controls at once: any two distinct Root rows are
    /// disjoint, and the −/+/Back adjust controls are mutually disjoint — so a stray
    /// touch can't, say, both decrement and go Back.
    #[kani::proof]
    fn settings_keys_disjoint() {
        let p = Point::new(kani::any(), kani::any());
        let (i, j): (u16, u16) = (kani::any(), kani::any());
        kani::assume(i < SETTINGS_ROWS && j < SETTINGS_ROWS && i != j);
        assert!(!(settings_row_rect(i).contains(p) && settings_row_rect(j).contains(p)));
        assert!(!(ADJ_MINUS_RECT.contains(p) && ADJ_PLUS_RECT.contains(p)));
        assert!(!(ADJ_MINUS_RECT.contains(p) && BACK_RECT.contains(p)));
        assert!(!(ADJ_PLUS_RECT.contains(p) && BACK_RECT.contains(p)));
    }

    /// No tap selects two nav tabs at once, and no tap selects two list rows at once
    /// (for any first-row offset) — so the design-system navigation can't misfire.
    #[kani::proof]
    fn nav_and_rows_disjoint() {
        let p = Point::new(kani::any(), kani::any());
        let (i, j): (u16, u16) = (kani::any(), kani::any());
        kani::assume(i < 3 && j < 3 && i != j);
        assert!(!(nav_tab_rect(i).contains(p) && nav_tab_rect(j).contains(p)));

        let y0: u16 = kani::any();
        kani::assume(y0 <= PANEL_H);
        let (a, b): (u16, u16) = (kani::any(), kani::any());
        kani::assume(a < 8 && b < 8 && a != b);
        assert!(!(row_rect(y0, a).contains(p) && row_rect(y0, b).contains(p)));
    }

    /// The service-detail back chevron can't be confused with a passkey row tap or a
    /// nav-bar tap, so returning to the list never collides with selecting one.
    #[kani::proof]
    fn passkeys_back_clear_of_rows_and_nav() {
        let p = Point::new(kani::any(), kani::any());
        let i: u16 = kani::any();
        kani::assume((i as usize) < PK_ROWS_MAX);
        assert!(!(hit_pk_back(p) && row_rect(PK_LIST_TOP, i).contains(p)));
        assert!(!(hit_pk_back(p) && p.y >= NAV_TOP));
    }

    /// The title-bar back chevron (a pushed tab screen's "return" affordance) can't be
    /// confused with a content row tap or a nav-bar tap, so returning to the parent
    /// screen never collides with selecting a row or switching tabs.
    #[kani::proof]
    fn title_back_clear_of_rows_and_nav() {
        let p = Point::new(kani::any(), kani::any());
        let i: u16 = kani::any();
        kani::assume((i as usize) < PK_ROWS_MAX);
        assert!(!(hit_title_back(p) && row_rect(PK_LIST_TOP, i).contains(p)));
        assert!(!(hit_title_back(p) && p.y >= NAV_TOP));
    }

    /// On the Confirm-Delete screen the destructive hold button and the cancel
    /// (back) chevron are disjoint, so no tap can both cancel and start a delete.
    #[kani::proof]
    fn del_hold_clear_of_back() {
        let p = Point::new(kani::any(), kani::any());
        assert!(!(hit_del_hold(p) && hit_pk_back(p)));
    }

    /// The pager arrows are mutually exclusive and never collide with a list row or the
    /// nav bar, so paging can't be mistaken for selecting a row or switching tabs.
    #[kani::proof]
    fn pager_clear_of_rows_and_nav() {
        let p = Point::new(kani::any(), kani::any());
        let i: u16 = kani::any();
        kani::assume((i as usize) < PK_ROWS_MAX);
        assert!(!(PAGER_PREV_RECT.contains(p) && PAGER_NEXT_RECT.contains(p)));
        assert!(!(hit_pager(p).is_some() && row_rect(PK_LIST_TOP, i).contains(p)));
        assert!(!(hit_pager(p).is_some() && p.y >= NAV_TOP));
    }

    /// On the rename screen no tap maps to two wheel keys, and a wheel tap never also
    /// hits the back chevron (cancel) — so committing, editing, and cancelling can't be
    /// confused for one another.
    #[kani::proof]
    fn rename_keys_are_unambiguous() {
        let p = Point::new(kani::any(), kani::any());
        let hits = [
            RN_UP_RECT.contains(p),
            RN_DOWN_RECT.contains(p),
            RN_BKSP_RECT.contains(p),
            RN_INS_RECT.contains(p),
            RN_SAVE_RECT.contains(p),
        ];
        assert!(hits.iter().filter(|&&b| b).count() <= 1);
        assert!(!(hit_rename(p).is_some() && hit_title_back(p)));
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
        let deny_c = Point::new(DENY_RECT.x + DENY_RECT.w / 2, DENY_RECT.y + BTN_H / 2);
        let allow_c = Point::new(ALLOW_RECT.x + ALLOW_RECT.w / 2, ALLOW_RECT.y + BTN_H / 2);
        assert_eq!(hit_confirm(deny_c), Some(Button::Deny));
        assert_eq!(hit_confirm(allow_c), Some(Button::Allow));
    }

    #[test]
    fn taps_off_the_floating_buttons_select_nothing() {
        let mid_h = BTN_BAND_TOP + BTN_H / 2;
        // Above the button row (the prompt area).
        assert_eq!(hit_confirm(Point::new(PANEL_W / 2, BTN_BAND_TOP - 1)), None);
        assert_eq!(hit_confirm(Point::new(0, 0)), None);
        // The gap between Deny and the (wider) Hold-to-approve button.
        let gap_x = DENY_RECT.x + DENY_RECT.w + 2;
        assert_eq!(hit_confirm(Point::new(gap_x, mid_h)), None);
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

    #[test]
    fn pin_key_centers_hit_their_keys() {
        // Every grid key's center hits exactly that key.
        for row in 0..PIN_ROWS {
            for col in 0..PIN_COLS {
                let r = pin_key_rect(col, row);
                let c = Point::new(r.x + PIN_KEY_W / 2, r.y + PIN_KEY_H / 2);
                assert_eq!(hit_pin(c), Some(pin_grid_key(col, row)));
            }
        }
        // Layout: rows 0–2 are digits 1–9 in reading order; the bottom row is Del/0/OK.
        assert_eq!(pin_grid_key(0, 0), PinKey::Digit(1));
        assert_eq!(pin_grid_key(2, 2), PinKey::Digit(9));
        assert_eq!(pin_grid_key(0, 3), PinKey::Del);
        assert_eq!(pin_grid_key(1, 3), PinKey::Digit(0));
        assert_eq!(pin_grid_key(2, 3), PinKey::Ok);
    }

    #[test]
    fn pin_cancel_hits_and_gaps_select_nothing() {
        let c = PIN_CANCEL_RECT;
        assert_eq!(
            hit_pin(Point::new(c.x + c.w / 2, c.y + c.h / 2)),
            Some(PinKey::Cancel)
        );
        // The gap between column 0 and column 1 selects nothing.
        let k = pin_key_rect(0, 0);
        assert_eq!(hit_pin(Point::new(k.x + PIN_KEY_W + 1, k.y + 2)), None);
        // Below the grid (bottom-left margin) selects nothing.
        assert_eq!(hit_pin(Point::new(0, PANEL_H - 1)), None);
        // The eye toggle, between the header and the grid, maps to Reveal.
        let e = PIN_EYE_RECT;
        assert_eq!(
            hit_pin(Point::new(e.x + e.w / 2, e.y + e.h / 2)),
            Some(PinKey::Reveal)
        );
    }

    #[test]
    fn settings_root_rows_map_in_order() {
        let want = [
            RootEntry::Brightness,
            RootEntry::Timeout,
            RootEntry::Sleep,
            RootEntry::Firmware,
            RootEntry::LockNow,
            RootEntry::Security,
        ];
        for (i, &e) in want.iter().enumerate() {
            let r = settings_row_rect(i as u16);
            let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
            assert_eq!(hit_settings_root(c), Some(e));
            assert_eq!(settings_row_entry(i as u16), e);
        }
        // The gap between two rows selects nothing.
        let r0 = settings_row_rect(0);
        assert_eq!(
            hit_settings_root(Point::new(r0.x + r0.w / 2, r0.y + r0.h + 1)),
            None
        );
        // Above the list (header area) selects nothing.
        assert_eq!(hit_settings_root(Point::new(PANEL_W / 2, 10)), None);
    }

    #[test]
    fn security_rows_map_in_order() {
        let want = [
            SecurityEntry::DevicePin,
            SecurityEntry::FidoPin,
            SecurityEntry::AuditLog,
            SecurityEntry::Backup,
            SecurityEntry::FactoryReset,
        ];
        for (i, &e) in want.iter().enumerate() {
            let r = settings_row_rect(i as u16);
            let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
            assert_eq!(hit_security(c), Some(e));
            assert_eq!(security_row_entry(i as u16), e);
        }
        // A tap past the Security rows (a later Root slot) selects no Security entry.
        let beyond = settings_row_rect(SECURITY_ROWS);
        assert_eq!(
            hit_security(Point::new(beyond.x + beyond.w / 2, beyond.y + beyond.h / 2)),
            None
        );
    }

    fn ctr(r: Rect) -> Point {
        Point::new(r.x + r.w / 2, r.y + r.h / 2)
    }

    #[test]
    fn backup_format_cards_map() {
        assert_eq!(
            hit_backup_format(ctr(FMT_PHRASE_RECT)),
            Some(BackupFormat::Phrase)
        );
        assert_eq!(
            hit_backup_format(ctr(FMT_SHARES_RECT)),
            Some(BackupFormat::Shares)
        );
        // The gap between the two cards selects neither.
        let gap = Point::new(FMT_PHRASE_RECT.x, FMT_PHRASE_RECT.y + FMT_PHRASE_RECT.h + 1);
        assert_eq!(hit_backup_format(gap), None);
    }

    #[test]
    fn share_picker_controls_map_to_their_rects() {
        for (r, k) in [
            (PICK_T_MINUS_RECT, ShareAdjust::TMinus),
            (PICK_T_PLUS_RECT, ShareAdjust::TPlus),
            (PICK_N_MINUS_RECT, ShareAdjust::NMinus),
            (PICK_N_PLUS_RECT, ShareAdjust::NPlus),
            (PICK_CONTINUE_RECT, ShareAdjust::Continue),
        ] {
            assert_eq!(hit_share_picker(ctr(r)), Some(k));
        }
        // The centre of the panel (between the two steppers) hits no control.
        assert_eq!(hit_share_picker(Point::new(PANEL_W / 2, 130)), None);
    }

    #[test]
    fn step_share_params_keeps_a_valid_split() {
        // Default 2-of-3 is reachable and a valid split.
        let (t, n) = (2u8, 3u8);
        assert!(SHARE_MIN <= t && t <= n && n <= SHARE_MAX);

        // Raising T past N drags N up with it; never exceeds SHARE_MAX.
        let mut p = (3u8, 3u8);
        p = step_share_params(p.0, p.1, ShareAdjust::TPlus);
        assert_eq!(p, (4, 4));
        // Lowering N below T drags T down with it.
        let mut q = (3u8, 4u8);
        q = step_share_params(q.0, q.1, ShareAdjust::NMinus);
        assert_eq!(q, (3, 3));

        // Clamps: T floors at SHARE_MIN, N ceils at SHARE_MAX.
        assert_eq!(
            step_share_params(SHARE_MIN, 3, ShareAdjust::TMinus),
            (SHARE_MIN, 3)
        );
        assert_eq!(
            step_share_params(2, SHARE_MAX, ShareAdjust::NPlus),
            (2, SHARE_MAX)
        );

        // Exhaustive: every step from every valid (T,N) yields a valid (T,N).
        for t in SHARE_MIN..=SHARE_MAX {
            for n in t..=SHARE_MAX {
                for k in [
                    ShareAdjust::TMinus,
                    ShareAdjust::TPlus,
                    ShareAdjust::NMinus,
                    ShareAdjust::NPlus,
                    ShareAdjust::Continue,
                ] {
                    let (rt, rn) = step_share_params(t, n, k);
                    assert!(
                        SHARE_MIN <= rt && rt <= rn && rn <= SHARE_MAX,
                        "step {k:?} from ({t},{n}) -> ({rt},{rn}) is not a valid split"
                    );
                }
            }
        }
    }

    #[test]
    fn adjust_controls_hit_their_keys() {
        let centers = [
            (ADJ_MINUS_RECT, AdjustKey::Minus),
            (ADJ_PLUS_RECT, AdjustKey::Plus),
            (BACK_RECT, AdjustKey::Back),
        ];
        for (r, key) in centers {
            assert_eq!(
                hit_adjust(Point::new(r.x + r.w / 2, r.y + r.h / 2)),
                Some(key)
            );
        }
        // The gap between − and + selects nothing.
        let gap_x = ADJ_MINUS_RECT.x + ADJ_MINUS_RECT.w + 1;
        assert_eq!(hit_adjust(Point::new(gap_x, ADJ_Y + ADJ_H / 2)), None);
    }

    #[test]
    fn hex_helpers_are_lowercase_ascii() {
        assert_eq!(core::str::from_utf8(&hex_u16(0x078A)).unwrap(), "078a");
        assert_eq!(core::str::from_utf8(&hex_u16(0)).unwrap(), "0000");
        assert_eq!(core::str::from_utf8(&hex_u16(0xFFFF)).unwrap(), "ffff");
        assert_eq!(
            core::str::from_utf8(&hex_u64(0x0123_4567_89ab_cdef)).unwrap(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn timeout_choices_are_sorted_and_nonzero() {
        // The timeout page steps through these; a non-monotone or zero entry would
        // make −/+ misbehave.
        assert!(TIMEOUT_CHOICES.windows(2).all(|w| w[0] < w[1]));
        assert!(TIMEOUT_CHOICES.iter().all(|&s| s > 0));
        // BRIGHTNESS_LEVELS >= 1 is a compile-time invariant (the const block above),
        // so it needs no runtime assert here.
    }

    #[test]
    fn step_brightness_clamps_at_both_ends() {
        assert_eq!(step_brightness(1, -1), 1);
        assert_eq!(step_brightness(BRIGHTNESS_LEVELS, 1), BRIGHTNESS_LEVELS);
        assert_eq!(step_brightness(3, 1), 4);
        assert_eq!(step_brightness(3, -1), 2);
    }

    #[test]
    fn step_timeout_steps_clamps_and_snaps() {
        // An exact-listed value steps to its neighbour.
        assert_eq!(step_timeout(30, 1), 60);
        assert_eq!(step_timeout(30, -1), 20);
        // Clamps at both ends of the choice list.
        let last = TIMEOUT_CHOICES[TIMEOUT_CHOICES.len() - 1];
        assert_eq!(step_timeout(TIMEOUT_CHOICES[0], -1), TIMEOUT_CHOICES[0]);
        assert_eq!(step_timeout(last, 1), last);
        // A non-listed current value (e.g. a 5 s phy override) snaps to nearest (10)
        // before stepping.
        assert_eq!(step_timeout(5, -1), 10);
        assert_eq!(step_timeout(5, 1), 20);
    }

    #[test]
    fn step_sleep_walks_durations_and_off() {
        // Steps between adjacent durations.
        assert_eq!(step_sleep(30, 1), 60);
        assert_eq!(step_sleep(60, -1), 30);
        // The longest real duration (300) steps up to Off (0), and Off steps back down.
        assert_eq!(step_sleep(300, 1), 0);
        assert_eq!(step_sleep(0, -1), 300);
        // Clamps at both ends.
        assert_eq!(step_sleep(15, -1), 15);
        assert_eq!(step_sleep(0, 1), 0);
        // A non-listed value snaps to the nearest real duration before stepping (and
        // never mis-snaps to the Off sentinel).
        assert_eq!(step_sleep(20, 1), 30);
        assert_eq!(step_sleep(20, -1), 15);
    }

    #[test]
    fn nav_tabs_map_left_to_right() {
        for (i, &tab) in NAV_TABS.iter().enumerate() {
            let r = nav_tab_rect(i as u16);
            let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
            assert_eq!(hit_nav(c), Some(tab));
        }
        // A tap above the nav bar selects no tab.
        assert_eq!(hit_nav(Point::new(PANEL_W / 2, NAV_TOP - 1)), None);
        // The far corners still resolve to the edge tabs (no dead gap).
        assert_eq!(hit_nav(Point::new(0, NAV_TOP)), Some(NavTab::Home));
        assert_eq!(
            hit_nav(Point::new(PANEL_W - 1, PANEL_H - 1)),
            Some(NavTab::Settings)
        );
    }

    #[test]
    fn list_rows_hit_in_order_and_gaps_miss() {
        let y0 = 40;
        for i in 0..5u16 {
            let r = row_rect(y0, i);
            assert_eq!(hit_list(Point::new(r.x + 2, r.y + r.h / 2), y0, 5), Some(i));
        }
        // The gap between rows 0 and 1 selects nothing.
        let r0 = row_rect(y0, 0);
        assert_eq!(hit_list(Point::new(r0.x + 2, r0.y + r0.h + 1), y0, 5), None);
        // A row index beyond `n` isn't matched.
        assert_eq!(
            hit_list(Point::new(r0.x + 2, row_rect(y0, 6).y + 2), y0, 5),
            None
        );
    }

    #[test]
    fn pager_hits_and_page_count() {
        let center = |r: Rect| Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert_eq!(hit_pager(center(PAGER_PREV_RECT)), Some(PagerKey::Prev));
        assert_eq!(hit_pager(center(PAGER_NEXT_RECT)), Some(PagerKey::Next));
        // The indicator gap between the two arrows selects nothing.
        assert_eq!(
            hit_pager(Point::new(
                PANEL_W / 2,
                PAGER_PREV_RECT.y + PAGER_PREV_RECT.h / 2
            )),
            None
        );
        // ceil(total / PK_ROWS_MAX), never zero.
        assert_eq!(page_count(0), 1);
        assert_eq!(page_count(1), 1);
        assert_eq!(page_count(PK_ROWS_MAX as u16), 1);
        assert_eq!(page_count(PK_ROWS_MAX as u16 + 1), 2);
        assert_eq!(page_count(62), 13);
    }

    #[test]
    fn rp_row_shows_nickname_over_rpid() {
        let mut r = RpRow {
            id: Label::clamp(b"github.com"),
            nick: Label::default(),
            accounts: 2,
        };
        assert_eq!(r.shown(), "github.com");
        r.nick = Label::clamp(b"Work GitHub");
        assert_eq!(r.shown(), "Work GitHub");
    }

    #[test]
    fn rename_key_centres_hit_their_keys() {
        let c = |r: Rect| Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert_eq!(hit_rename(c(RN_UP_RECT)), Some(RenameKey::Up));
        assert_eq!(hit_rename(c(RN_DOWN_RECT)), Some(RenameKey::Down));
        assert_eq!(hit_rename(c(RN_BKSP_RECT)), Some(RenameKey::Backspace));
        assert_eq!(hit_rename(c(RN_INS_RECT)), Some(RenameKey::Insert));
        assert_eq!(hit_rename(c(RN_SAVE_RECT)), Some(RenameKey::Save));
        // The field area (above the wheel) is not a wheel key.
        assert_eq!(hit_rename(c(RN_FIELD_RECT)), None);
    }

    #[test]
    fn title_edit_and_back_are_disjoint() {
        let c = |r: Rect| Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert!(hit_title_edit(c(TITLE_EDIT_RECT)));
        assert!(!hit_title_back(c(TITLE_EDIT_RECT)));
        assert!(hit_title_back(c(TITLE_BACK_RECT)));
        assert!(!hit_title_edit(c(TITLE_BACK_RECT)));
    }

    #[test]
    fn rename_charset_is_printable_and_cycles() {
        assert!(!RENAME_CHARSET.is_empty());
        assert!(RENAME_CHARSET.iter().all(|&b| (0x20..=0x7E).contains(&b)));
        // Distinct entries (no accidental dup that would stall the wheel on a value).
        for (i, &a) in RENAME_CHARSET.iter().enumerate() {
            assert!(!RENAME_CHARSET[i + 1..].contains(&a), "duplicate {a:?}");
        }
    }
}
