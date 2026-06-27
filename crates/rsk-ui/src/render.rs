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
    draw_target::{DrawTarget, DrawTargetExt},
    geometry::{Point as EgPoint, Size},
    pixelcolor::Rgb565,
    prelude::{RgbColor, WebColors},
    primitives::{
        Circle, Line, Primitive, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle,
        RoundedRectangle, StrokeAlignment,
    },
};

use crate::{
    ADJ_MINUS_RECT, ADJ_PLUS_RECT, ALLOW_RECT, AccountRow, BACK_RECT, BRIGHTNESS_LEVELS,
    ConfirmPrompt, DEL_HOLD_RECT, DENY_RECT, Glyph, HomeView, Label, NAV_H, NAV_TABS, NAV_TOP,
    NavTab, PANEL_H, PANEL_W, PIN_CANCEL_RECT, PIN_COLS, PIN_ROWS, PK_LIST_TOP, PinCaption, PinKey,
    PinPad, Point, Rect, RpRow, STATUS_BAR_H, Screen, SettingsPage, SettingsView, StatusKind,
    TITLE_BACK_RECT, TITLE_BAR_H, font, font::Role, glyph, hex_u16, hex_u64, nav_tab_rect,
    pin_grid_key, pin_key_rect, settings_row_rect, theme,
};

// Local semantic aliases, all sourced from `theme` so the whole renderer speaks one
// palette (these equal their tokens — re-sourcing is hygiene, not a visual change).
const BG: Rgb565 = theme::PANEL_BG;
const FG: Rgb565 = theme::TEXT;
const MUTED: Rgb565 = theme::MUTED;
/// Affirmative fill — the PIN pad's OK key and the brightness level bar. Calm
/// sea-green, not vivid, so it reads as confirmation rather than alarm. The decline
/// pair (Deny / Cancel) is a low-emphasis outline in [`theme::DENY`] instead, so
/// there is no filled-red counterpart const here.
const ALLOW_FILL: Rgb565 = theme::APPROVE;
/// Corner radius for the floating buttons — enough to read as rounded cards.
const BTN_RADIUS: u32 = 12;
/// Fill for the numeric PIN keys and the settings −/+ steppers — a dark neutral card
/// ([`theme::KEY_BG`]) edged with [`theme::KEY_BORDER`]. The affirmative OK is a solid
/// Allow-green key and Del a backspace glyph, so the special keys still stand out.
const KEY_FILL: Rgb565 = theme::KEY_BG;

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
        Screen::Locked => locked(target),
        Screen::Home(v) => home(target, v),
        Screen::Confirm(prompt) => confirm(target, prompt),
        Screen::Pin(pad) => pin(target, pad),
        Screen::Settings(view) => settings(target, view),
    }
}

/// The device-locked screen: a padlock in a calm surface circle, the "Locked" heading,
/// and a muted "Touch to unlock" hint. The whole screen is the unlock affordance (the
/// firmware treats any tap as "start PIN entry"), so there is no per-control hit rect.
/// Gates only the on-device UI — host CTAP ceremonies paint their own prompts over this.
fn locked<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    const DIA: u32 = 70;
    let cx = MIDX;
    let circle_top = 96;
    Circle::new(EgPoint::new(cx - DIA as i32 / 2, circle_top), DIA)
        .into_styled(PrimitiveStyle::with_fill(theme::SURFACE))
        .draw(t)?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new((cx - 17) as u16, (cyc - 17) as u16),
        34,
        theme::ACCENT,
    )?;
    text(t, "Locked", EgPoint::new(cx, 200), Role::Heading, FG)?;
    // The design breathes this hint (opacity 0.5↔1); we paint it static — the locked
    // screen is event-driven (no animation loop) and there is no retained framebuffer to
    // pulse cheaply, so a static muted line is the faithful no-framebuffer rendering.
    text(
        t,
        "Touch to unlock",
        EgPoint::new(cx, 228),
        Role::Body,
        MUTED,
    )
}

fn splash<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    text(t, "RS-Key", EgPoint::new(MIDX, 140), Role::Heading, FG)?;
    text(
        t,
        "trusted display",
        EgPoint::new(MIDX, 175),
        Role::Body,
        MUTED,
    )
}

/// The Home tab: header, a large status indicator (Ready / Working …), one info row,
/// and the bottom nav. The old MENU affordance is gone — the nav bar is the way into
/// Passkeys / Settings now.
fn home<D: DrawTarget<Color = Rgb565>>(t: &mut D, v: &HomeView) -> Result<(), D::Error> {
    status_bar(t)?;
    if matches!(v.status, StatusKind::Idle) {
        glyph::draw(
            t,
            Glyph::CheckCircle,
            Point::new(MIDX as u16 - 22, 64),
            44,
            theme::ACCENT,
        )?;
        text(
            t,
            "Ready",
            EgPoint::new(MIDX, 140),
            Role::Ready,
            theme::ACCENT,
        )?;
    } else {
        let c = status_color(v.status);
        Circle::new(EgPoint::new(MIDX - 18, 70), 36)
            .into_styled(PrimitiveStyle::with_fill(c))
            .draw(t)?;
        text(
            t,
            v.status.label(),
            EgPoint::new(MIDX, 140),
            Role::Heading,
            c,
        )?;
    }
    render_row(
        t,
        crate::row_rect(180, 0),
        Glyph::Usb,
        "USB connected",
        None,
        false,
    )?;
    render_nav(t, NavTab::Home)
}

/// The Passkeys tab: header, one row per relying party (generic globe + sanitized
/// rpId + account count + drill-in chevron), an "N items" footer, and the nav bar.
/// `total` is the true RP count even when `rows` holds only the first `PK_ROWS_MAX`.
/// A full-frame paint (the list is static once shown), so it clears first. Standalone
/// rather than a `Screen` variant — the list data is too large for the `Copy` enum.
pub fn render_passkeys_list<D>(t: &mut D, rows: &[RpRow], total: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Passkeys", theme::ACCENT, false)?;
    if rows.is_empty() {
        glyph::draw(t, Glyph::Key, Point::new(MIDX as u16 - 18, 96), 36, MUTED)?;
        text(
            t,
            "No passkeys yet",
            EgPoint::new(MIDX, 160),
            Role::Body,
            MUTED,
        )?;
    } else {
        for (i, r) in rows.iter().enumerate() {
            let mut buf = [0u8; 16];
            let unit = if r.accounts == 1 {
                "account"
            } else {
                "accounts"
            };
            let trailing = fmt_count(r.accounts as u16, unit, &mut buf);
            render_row(
                t,
                crate::row_rect(PK_LIST_TOP, i as u16),
                Glyph::Globe,
                r.id.as_str(),
                Some((trailing, MUTED)),
                true,
            )?;
        }
        footer_count(t, total, if total == 1 { "item" } else { "items" })?;
    }
    render_nav(t, NavTab::Passkeys)
}

/// The per-RP service detail: a back-chevron header + the (truncated) rpId, one row per
/// resident account (key glyph + sanitized name + a "UV" tag when credProtect-gated),
/// an "N accounts" footer, and the nav bar. The firmware makes each row tappable to
/// start the Confirm-Delete flow ([`render_confirm_delete`]); rename is a later wave.
pub fn render_service<D>(
    t: &mut D,
    title: &Label,
    accounts: &[AccountRow],
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, title.as_str(), theme::ACCENT, true)?;
    for (i, a) in accounts.iter().enumerate() {
        let trailing = if a.protected {
            Some(("UV", theme::ACCENT))
        } else {
            None
        };
        render_row(
            t,
            crate::row_rect(PK_LIST_TOP, i as u16),
            Glyph::Key,
            a.name.as_str(),
            trailing,
            false,
        )?;
    }
    footer_count(t, total, if total == 1 { "account" } else { "accounts" })?;
    render_nav(t, NavTab::Passkeys)
}

/// A right-aligned `"<n> <unit>"` footer just above the nav bar (the list / detail
/// total), in the muted colour.
fn footer_count<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    n: u16,
    unit: &str,
) -> Result<(), D::Error> {
    let mut buf = [0u8; 16];
    let s = fmt_count(n, unit, &mut buf);
    text_right(
        t,
        s,
        EgPoint::new(PANEL_W as i32 - 12, NAV_TOP as i32 - 10),
        Role::Mono,
        MUTED,
    )
}

/// The trusted Confirm-Delete screen for a resident passkey: the back (cancel)
/// chevron and a "Delete passkey" header in the decline colour, a card naming the
/// relying party and account about to be removed, a plain-language warning, and the
/// full-width **Hold to delete** button. The hold button starts empty; the firmware
/// grows it via [`render_hold_fill`] as the user holds. Standalone full-frame (like
/// [`render_service`]) — the labels are too large for the `Copy` `Screen` enum.
pub fn render_confirm_delete<D>(t: &mut D, rp: &Label, account: &Label) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    glyph::draw(t, Glyph::Back, Point::new(8, 7), 16, theme::DENY)?;
    text_left(
        t,
        "Delete passkey",
        EgPoint::new(44, 15),
        Role::Heading,
        theme::DENY,
    )?;
    // Card naming exactly what is about to be removed: relying party + account.
    let card = Rect::new(14, 54, PANEL_W - 28, 46);
    RoundedRectangle::with_equal_corners(eg_rect(card), Size::new(8, 8))
        .into_styled(PrimitiveStyle::with_fill(theme::ROW_BG))
        .draw(t)?;
    glyph::draw(
        t,
        Glyph::Globe,
        Point::new(card.x + 10, card.y + 13),
        20,
        theme::MUTED,
    )?;
    let tx = card.x as i32 + 40;
    text_left(
        t,
        rp.as_str(),
        EgPoint::new(tx, card.y as i32 + 16),
        Role::Body,
        theme::TEXT,
    )?;
    text_left(
        t,
        account.as_str(),
        EgPoint::new(tx, card.y as i32 + 32),
        Role::Body,
        theme::MUTED,
    )?;
    // Plain-language warning — including the honest caveat that the site is not told.
    text_left(
        t,
        "This removes the passkey",
        EgPoint::new(16, 124),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "from RS-Key. The site may",
        EgPoint::new(16, 142),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "still expect it.",
        EgPoint::new(16, 160),
        Role::Body,
        theme::WARN,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to delete", theme::DENY)
}

/// The trusted Factory-Reset confirm screen (reached from Settings → Factory reset):
/// a header back chevron to cancel, a centred warning, a plain-language note that
/// every credential and the PIN are erased, and the full-width hold-to-confirm button
/// — the same [`DEL_HOLD_RECT`] geometry the delete flow uses, so only a deliberate
/// hold commits. The firmware gates it on the device PIN (if set) before the hold.
pub fn render_confirm_factory_reset<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    glyph::draw(t, Glyph::Back, Point::new(8, 7), 16, theme::DENY)?;
    text_left(
        t,
        "Factory reset",
        EgPoint::new(44, 15),
        Role::Heading,
        theme::DENY,
    )?;
    // Large centred warning triangle marks this as the destructive screen.
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(PANEL_W / 2 - 16, 56),
        32,
        theme::WARN,
    )?;
    text_left(
        t,
        "Erases ALL passkeys, keys,",
        EgPoint::new(16, 122),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "and the device PIN. This",
        EgPoint::new(16, 140),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "cannot be undone.",
        EgPoint::new(16, 158),
        Role::Body,
        theme::WARN,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to reset", theme::DENY)
}

/// The "wiping" notice shown after a factory reset is confirmed: a centred warning
/// plus "Do not unplug", painted once before the multi-second flash scrub (which
/// blocks the panel) so the screen isn't frozen on the full hold button. No
/// controls — the device reboots itself when the wipe finishes.
pub fn render_erasing<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(PANEL_W / 2 - 16, 104),
        32,
        theme::DENY,
    )?;
    text(
        t,
        "Erasing...",
        EgPoint::new(MIDX, 168),
        Role::Heading,
        theme::TEXT,
    )?;
    text(
        t,
        "Do not unplug",
        EgPoint::new(MIDX, 196),
        Role::Body,
        MUTED,
    )?;
    Ok(())
}

/// The "PIN blocked" notice, shown when a local PIN gate exhausts the retry budget
/// (the counter reached zero). A danger padlock in a tinted circle, a "PIN blocked"
/// heading, and a two-line hint that recovery is a host-side reset — on-device actions
/// (unlock, delete, factory reset) all share that one blocked `EF_PIN` counter, so the
/// escape hatch is the host's touch-only `authenticatorReset`. No controls; the caller
/// waits for a tap or a short timeout, then returns.
pub fn render_pin_blocked<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    const DIA: u32 = 70;
    let circle_top = 84;
    Circle::new(EgPoint::new(MIDX - DIA as i32 / 2, circle_top), DIA)
        .into_styled(PrimitiveStyle::with_fill(theme::DANGER_BG))
        .draw(t)?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new((MIDX - 17) as u16, (cyc - 17) as u16),
        34,
        theme::DANGER,
    )?;
    text(
        t,
        "PIN blocked",
        EgPoint::new(MIDX, 188),
        Role::Heading,
        theme::DANGER,
    )?;
    text(
        t,
        "Too many wrong PINs.",
        EgPoint::new(MIDX, 216),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        "Reset from a host to recover.",
        EgPoint::new(MIDX, 236),
        Role::Body,
        MUTED,
    )
}

/// The trusted Approve prompt: header + shield, the operation title, the relying-
/// party card (generic globe + sanitized rp id / account), a "did you start this?"
/// caution, and the Deny / Hold-to-approve buttons. The hold button starts empty; the
/// firmware fills it via [`render_hold_button`] as the user holds.
fn confirm<D: DrawTarget<Color = Rgb565>>(t: &mut D, p: &ConfirmPrompt) -> Result<(), D::Error> {
    render_header(t, "RS-Key", false, Some(Glyph::Shield))?;
    glyph::draw(t, Glyph::Shield, Point::new(20, 42), 22, theme::ACCENT)?;
    text_left(t, p.title, EgPoint::new(50, 53), Role::Heading, theme::TEXT)?;
    // Relying-party card, only when the request carries rp text.
    if !p.primary.is_empty() {
        let card = Rect::new(14, 80, PANEL_W - 28, 46);
        RoundedRectangle::with_equal_corners(eg_rect(card), Size::new(8, 8))
            .into_styled(PrimitiveStyle::with_fill(theme::ROW_BG))
            .draw(t)?;
        glyph::draw(
            t,
            Glyph::Globe,
            Point::new(card.x + 10, card.y + 13),
            20,
            theme::MUTED,
        )?;
        let tx = card.x as i32 + 40;
        if p.secondary.is_empty() {
            text_left(
                t,
                p.primary.as_str(),
                EgPoint::new(tx, card.y as i32 + 23),
                Role::Body,
                theme::TEXT,
            )?;
        } else {
            text_left(
                t,
                p.primary.as_str(),
                EgPoint::new(tx, card.y as i32 + 16),
                Role::Body,
                theme::TEXT,
            )?;
            text_left(
                t,
                p.secondary.as_str(),
                EgPoint::new(tx, card.y as i32 + 32),
                Role::Body,
                theme::MUTED,
            )?;
        }
    }
    // Caution — a deliberate, plain-language warning against phishing.
    glyph::draw(t, Glyph::Warn, Point::new(16, 144), 15, theme::WARN)?;
    text_left(
        t,
        "Approve only if you",
        EgPoint::new(38, 148),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "started this",
        EgPoint::new(38, 164),
        Role::Body,
        theme::WARN,
    )?;
    // Deny is a single tap (low emphasis); Approve is a deliberate hold that fills.
    outline_button(t, DENY_RECT, "Deny", theme::DENY)?;
    render_hold_button(t, ALLOW_RECT, "Hold to approve", theme::APPROVE)
}

/// An outlined (not filled) rounded button — the low-emphasis action (Deny).
fn outline_button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    color: Rgb565,
) -> Result<(), D::Error> {
    // Inside-aligned stroke: the outline stays within `r`, so a button's paint never
    // bleeds past the exact rect the hit-test maps (the Allow/Deny contract).
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(color)
                .stroke_width(2)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    text(t, label, center(r), Role::Strong, color)
}

/// Fill a rounded floating button and center its caption — the fill and the
/// caption share the one [`Rect`] the hit-test uses, so paint and hit-test can
/// never disagree. The rounded card never extends past `r`, so it stays within the
/// exact region [`crate::hit_confirm`] approves.
fn button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    label: &str,
    fill: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    text(t, label, center(r), Role::Strong, FG)
}

/// Paint a rounded key surface at `r`: a `fill`, plus (when `bordered`) a subtle
/// [`theme::KEY_BORDER`] edge so a dark key still reads as pressable. The caller
/// centres the digit or glyph on top. Shared by the PIN pad and the settings ±.
fn key_surface<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    fill: Rgb565,
    bordered: bool,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    if bordered {
        RoundedRectangle::with_equal_corners(eg_rect(r), Size::new(BTN_RADIUS, BTN_RADIUS))
            .into_styled(
                PrimitiveStyleBuilder::new()
                    .stroke_color(theme::KEY_BORDER)
                    .stroke_width(1)
                    .stroke_alignment(StrokeAlignment::Inside)
                    .build(),
            )
            .draw(t)?;
    }
    Ok(())
}

/// Draw glyph `g` of side `size` centred in `r`.
fn glyph_centered<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    g: Glyph,
    r: Rect,
    size: u16,
    color: Rgb565,
) -> Result<(), D::Error> {
    glyph::draw(
        t,
        g,
        Point::new(r.x + r.w / 2 - size / 2, r.y + r.h / 2 - size / 2),
        size,
        color,
    )
}

/// The built-in-UV PIN pad in the new design language: a lock-marked header with a
/// low-emphasis outlined Cancel, the cyan masked entry, then the 3×4 grid of dark
/// neutral key cards — Del a backspace glyph, OK a solid green check. Each key is
/// painted in the exact [`pin_key_rect`] that [`crate::hit_pin`] maps a tap to, and
/// only masked dots — never the digits — are shown.
fn pin<D: DrawTarget<Color = Rgb565>>(t: &mut D, pad: &PinPad) -> Result<(), D::Error> {
    // Custom header (not `render_header`): Cancel keeps its top-left hit rect — clear
    // of the digit grid, so a digit tap can never abandon entry — so the title is
    // centred between it and a Lock that marks this as the secure-entry screen.
    text(t, pad.title, EgPoint::new(MIDX, 20), Role::Heading, FG)?;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new(PANEL_W - 26, 6),
        18,
        theme::ACCENT,
    )?;
    // Cancel is a back chevron (not a wide "Cancel" word that would collide with the
    // centred title) in the decline colour, painted inside its PIN_CANCEL_RECT hit area.
    glyph::draw(
        t,
        Glyph::Back,
        Point::new(PIN_CANCEL_RECT.x, 7),
        16,
        theme::DENY,
    )?;
    masked_entry(t, pad.entered)?;
    let mut row = 0;
    while row < PIN_ROWS {
        let mut col = 0;
        while col < PIN_COLS {
            let r = pin_key_rect(col, row);
            match pin_grid_key(col, row) {
                // OK is a solid green key with a white check; Del a backspace glyph on a
                // dark card; the digits are dark cards with a white numeral.
                PinKey::Ok => {
                    key_surface(t, r, ALLOW_FILL, false)?;
                    glyph_centered(t, Glyph::Check, r, 24, FG)?;
                }
                PinKey::Del => {
                    key_surface(t, r, KEY_FILL, true)?;
                    glyph_centered(t, Glyph::Backspace, r, 24, MUTED)?;
                }
                key => {
                    key_surface(t, r, KEY_FILL, true)?;
                    text(t, key_label(key), center(r), Role::Strong, FG)?;
                }
            }
            col += 1;
        }
        row += 1;
    }
    // A rejected entry leaves a danger-coloured caption in the strip below the grid, so a
    // wrong PIN / mismatch is visible rather than a silent re-prompt.
    if let Some(caption) = pad.caption {
        text(
            t,
            pin_caption_text(caption),
            EgPoint::new(MIDX, PANEL_H as i32 - 9),
            Role::Body,
            theme::DANGER,
        )?;
    }
    Ok(())
}

/// The feedback line for a [`PinCaption`]. Wrong-PIN counts index a fixed table so the
/// remaining attempts render with no alloc (the counter never exceeds the retry budget).
fn pin_caption_text(c: PinCaption) -> &'static str {
    const WRONG: [&str; 9] = [
        "Wrong PIN, 0 left",
        "Wrong PIN, 1 left",
        "Wrong PIN, 2 left",
        "Wrong PIN, 3 left",
        "Wrong PIN, 4 left",
        "Wrong PIN, 5 left",
        "Wrong PIN, 6 left",
        "Wrong PIN, 7 left",
        "Wrong PIN, 8 left",
    ];
    match c {
        PinCaption::WrongPin { retries_left } => {
            WRONG[(retries_left as usize).min(WRONG.len() - 1)]
        }
        PinCaption::Mismatch => "PINs don't match",
    }
}

/// One filled cyan dot per entered digit (capped to a row width), centered — the PIN
/// itself is never rendered, only its length.
fn masked_entry<D: DrawTarget<Color = Rgb565>>(t: &mut D, entered: usize) -> Result<(), D::Error> {
    const MAX_DOTS: usize = 10;
    const DIA: u32 = 12;
    const STEP: i32 = 20;
    let n = entered.min(MAX_DOTS) as i32;
    let start = MIDX - (n * STEP) / 2 + (STEP - DIA as i32) / 2;
    for i in 0..n {
        Circle::new(EgPoint::new(start + i * STEP, 54), DIA)
            .into_styled(PrimitiveStyle::with_fill(theme::ACCENT))
            .draw(t)?;
    }
    Ok(())
}

/// Top and height of the masked-entry band — the strip [`render_pin_dots`] repaints
/// on its own. Must cover the dot row `masked_entry` draws (y 54, dia 12).
const PIN_ENTRY_TOP: i32 = 48;
const PIN_ENTRY_H: u32 = 24;

/// Repaint **only** the masked-entry band (clear the strip, redraw the dots),
/// leaving the static keys untouched. The pad is painted in full once via
/// `render(&Screen::Pin(..))`; each keystroke then calls this, so adding or removing
/// a digit is a tiny partial update with no full-screen clear — and thus no flicker,
/// unlike repainting the whole 240×320 frame per tap.
pub fn render_pin_dots<D>(target: &mut D, entered: usize) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(
        EgPoint::new(0, PIN_ENTRY_TOP),
        Size::new(PANEL_W as u32, PIN_ENTRY_H),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(target)?;
    masked_entry(target, entered)
}

/// A static caption for a pad key — no alloc: digits index a fixed table.
fn key_label(k: PinKey) -> &'static str {
    const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
    match k {
        PinKey::Digit(n) => DIGITS[(n % 10) as usize],
        PinKey::Del => "Del",
        PinKey::Ok => "OK",
        PinKey::Cancel => "Cancel",
    }
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
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    font::centered(t, s, at, role, color)
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

// --- Design-system widgets (the re-skin layout) ----------------------------

/// Left-aligned, vertically-centred text (list-row labels, header titles).
fn text_left<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    font::left(t, s, at, role, color)
}

/// Right-aligned, vertically-centred text (trailing row status / values).
fn text_right<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
) -> Result<(), D::Error> {
    font::right(t, s, at, role, color)
}

/// Left-aligned text hard-clipped to `clip`, so a label too long for its slot is cut at
/// the boundary rather than overrunning a trailing value — proportional faces make long,
/// variable rp names a real risk.
fn text_left_clipped<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    clip: Rect,
) -> Result<(), D::Error> {
    font::left(&mut t.clipped(&eg_rect(clip)), s, at, role, color)
}

/// The persistent top **status bar** (the design's framing chrome): a mono "RS-Key"
/// wordmark at the left and the USB power indicator at the right. Faint, so it frames
/// the screen without competing with content. This is a bus-powered device, so the power
/// indicator is always the USB plug + "USB" label — never a battery.
pub fn status_bar<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    let cy = STATUS_BAR_H as i32 / 2 + 1;
    text_left(
        t,
        "RS-Key",
        EgPoint::new(13, cy),
        Role::MonoSmall,
        theme::FAINT,
    )?;
    // USB indicator: the "USB" label flush to the right edge, the plug glyph just left
    // of it (measured so they sit together regardless of the label's width).
    let label_right = PANEL_W as i32 - 13;
    text_right(
        t,
        "USB",
        EgPoint::new(label_right, cy),
        Role::MonoSmall,
        theme::FAINT,
    )?;
    let label_w = font::width("USB", Role::MonoSmall).unwrap_or(20) as i32;
    glyph::draw(
        t,
        Glyph::Usb,
        Point::new((label_right - label_w - 16).max(0) as u16, (cy - 7) as u16),
        14,
        theme::GREY,
    )
}

/// The **title bar** below the status bar: an optional back chevron (painted in
/// [`TITLE_BACK_RECT`], the region [`crate::hit_title_back`] maps a tap to) and the
/// screen `title`. The chevron tints with the title (both `color`), per the design.
pub fn title_bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    color: Rgb565,
    back: bool,
) -> Result<(), D::Error> {
    let cy = STATUS_BAR_H as i32 + TITLE_BAR_H as i32 / 2;
    let tx = if back {
        glyph::draw(
            t,
            Glyph::Back,
            Point::new(TITLE_BACK_RECT.x + 6, (cy - 8) as u16),
            16,
            color,
        )?;
        TITLE_BACK_RECT.x as i32 + TITLE_BACK_RECT.w as i32
    } else {
        13
    };
    text_left(t, title, EgPoint::new(tx, cy), Role::Heading, color)
}

/// The top header strip: a title (accent or muted) at the left, an optional status
/// glyph at the right.
pub fn render_header<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    accent: bool,
    right: Option<Glyph>,
) -> Result<(), D::Error> {
    let color = if accent { theme::ACCENT } else { theme::MUTED };
    text_left(t, title, EgPoint::new(12, 15), Role::Heading, color)?;
    if let Some(g) = right {
        glyph::draw(t, g, Point::new(PANEL_W - 26, 6), 18, theme::MUTED)?;
    }
    Ok(())
}

/// One list row: a lifted card, a leading glyph, the label, an optional trailing
/// coloured status/value, and an optional chevron. The geometry is the caller's
/// `rect` (from `row_rect`), so paint and [`crate::hit_list`] share it.
pub fn render_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    icon: Glyph,
    label: &str,
    trailing: Option<(&str, Rgb565)>,
    chevron: bool,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(6, 6))
        .into_styled(PrimitiveStyle::with_fill(theme::ROW_BG))
        .draw(t)?;
    let cy = rect.y as i32 + rect.h as i32 / 2;
    glyph::draw(
        t,
        icon,
        Point::new(rect.x + 8, (cy - 7) as u16),
        14,
        theme::MUTED,
    )?;
    // Lay the trailing block (chevron, then the value flush against it) first, tracking
    // the leftmost x it occupies — the label is then clipped to end before it.
    let mut right_x = rect.x as i32 + rect.w as i32 - 8;
    if chevron {
        right_x -= 12;
        glyph::draw(
            t,
            Glyph::Chevron,
            Point::new(right_x as u16, (cy - 6) as u16),
            12,
            theme::MUTED,
        )?;
    }
    let label_x = rect.x as i32 + 28;
    let label_right = if let Some((txt, col)) = trailing {
        let tx = right_x - 4;
        text_right(t, txt, EgPoint::new(tx, cy), Role::Body, col)?;
        tx - font::width(txt, Role::Body).unwrap_or(0) as i32 - ROW_TRAILING_GAP
    } else {
        right_x - ROW_TRAILING_GAP
    };
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_clipped(
        t,
        label,
        EgPoint::new(label_x, cy),
        Role::Body,
        theme::TEXT,
        clip,
    )
}

/// The gap kept between a row's (clipped) label and its trailing value / chevron, so the
/// two never touch even when the label fills its slot.
const ROW_TRAILING_GAP: i32 = 8;

/// The bottom nav bar: a surface + hairline, the `active` tab in accent and the rest
/// dimmed. Glyphs sit in the exact [`nav_tab_rect`] cells [`crate::hit_nav`] maps.
pub fn render_nav<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    active: NavTab,
) -> Result<(), D::Error> {
    Rectangle::new(
        EgPoint::new(0, NAV_TOP as i32),
        Size::new(PANEL_W as u32, NAV_H as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(theme::NAV_BG))
    .draw(t)?;
    Line::new(
        EgPoint::new(0, NAV_TOP as i32),
        EgPoint::new(PANEL_W as i32 - 1, NAV_TOP as i32),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::HAIRLINE, 1))
    .draw(t)?;
    for (i, &tab) in NAV_TABS.iter().enumerate() {
        let r = nav_tab_rect(i as u16);
        let color = if tab == active {
            theme::ACCENT
        } else {
            theme::NAV_INACTIVE
        };
        let g = match tab {
            NavTab::Home => Glyph::Home,
            NavTab::Passkeys => Glyph::Key,
            NavTab::Settings => Glyph::Gear,
        };
        glyph::draw(
            t,
            g,
            Point::new(r.x + r.w / 2 - 10, r.y + r.h / 2 - 10),
            20,
            color,
        )?;
    }
    Ok(())
}

/// The `fill`-coloured outline and the centred label of a hold button — re-stamped on
/// top of the fill so the advancing edge never eats them.
fn hold_outline_and_label<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
    color: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(color)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    // Small caption so longer labels ("Hold to approve") fit the button width.
    text(t, label, center(rect), Role::Body, theme::TEXT)
}

/// The **static base** of a hold-to-confirm button: a dark card, the `fill`-coloured
/// outline and the centred label. Painted once when the screen appears and again on a
/// hold reset; [`render_hold_fill`] then grows the fill over it without re-clearing the
/// card, so the build-up never flickers.
pub fn render_hold_button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
    fill: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(BTN_RADIUS, BTN_RADIUS))
        .into_styled(PrimitiveStyle::with_fill(theme::ROW_BG))
        .draw(t)?;
    hold_outline_and_label(t, rect, label, fill)
}

/// Grow the hold fill from `prev_num/den` to `num/den` of the button width, drawn over
/// the existing base/fill with **no card clear**, so repainting each poll doesn't
/// flicker. The fill is the button's *own* rounded-rect shape painted through a clip of
/// only the advancing strip `[prev_w, w]`: so its rounded corners are exactly the base's
/// (no square corner ever pokes past the card — the artifact the earlier left-rounded
/// approach left when narrow widths clamped the radius), the advancing edge is the flat
/// clip boundary, and only the thin new strip is painted (the centred label is overdrawn
/// ~2px at a time, not washed every frame). Pass `prev_num == 0` to start a fresh fill.
pub fn render_hold_fill<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
    prev_num: u16,
    num: u16,
    den: u16,
    fill: Rgb565,
) -> Result<(), D::Error> {
    if den > 0 {
        let frac = |n: u16| (rect.w as u32 * n.min(den) as u32 / den as u32).min(rect.w as u32);
        let (w, pw) = (frac(num), frac(prev_num));
        if w > pw {
            let strip = Rectangle::new(
                EgPoint::new(rect.x as i32 + pw as i32, rect.y as i32),
                Size::new(w - pw, rect.h as u32),
            );
            let mut clipped = t.clipped(&strip);
            RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(BTN_RADIUS, BTN_RADIUS))
                .into_styled(PrimitiveStyle::with_fill(fill))
                .draw(&mut clipped)?;
        }
    }
    hold_outline_and_label(t, rect, label, fill)
}

// --- Settings menu ---------------------------------------------------------

/// Paint the on-screen settings menu — dispatch by page. Every tappable control is
/// painted in the exact rect its `hit_*` test maps a tap to (the Allow/Deny contract,
/// extended to the menu).
fn settings<D: DrawTarget<Color = Rgb565>>(t: &mut D, v: &SettingsView) -> Result<(), D::Error> {
    match v.page {
        SettingsPage::Root => settings_root(t),
        SettingsPage::Brightness => settings_brightness(t, v.brightness),
        SettingsPage::Timeout => settings_timeout(t, v.timeout_secs),
        SettingsPage::Sleep => settings_sleep(t, v.sleep_secs),
        SettingsPage::Info => settings_info(t, v.version, v.chipid),
        SettingsPage::Security => settings_security(t, v.pin_set),
    }
}

/// The Root list: a header and the option rows, each in its `settings_row_rect` —
/// the new list look, with leading glyphs and a drill-in chevron.
fn settings_root<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    status_bar(t)?;
    // Back chevron exits to Home (the design's settings → back flow), so the list needs
    // no "Close" row — freeing a row keeps all six at a touch-comfortable height.
    title_bar(t, "Settings", theme::ACCENT, true)?;
    render_row(
        t,
        settings_row_rect(0),
        Glyph::Sun,
        "Brightness",
        None,
        true,
    )?;
    render_row(
        t,
        settings_row_rect(1),
        Glyph::Clock,
        "Touch timeout",
        None,
        true,
    )?;
    render_row(
        t,
        settings_row_rect(2),
        Glyph::Moon,
        "Display sleep",
        None,
        true,
    )?;
    render_row(
        t,
        settings_row_rect(3),
        Glyph::Info,
        "Device info",
        None,
        true,
    )?;
    // Lock now: a plain action row (no chevron — it locks immediately rather than
    // drilling in) with the padlock glyph.
    render_row(
        t,
        settings_row_rect(4),
        Glyph::Lock,
        "Lock now",
        None,
        false,
    )?;
    // Security drills into the Set/Change PIN + Factory reset sub-page (the design's
    // settings → security flow), keeping the destructive reset one tap deeper.
    render_row(
        t,
        settings_row_rect(5),
        Glyph::Shield,
        "Security",
        None,
        true,
    )
}

/// The Security sub-page: the PIN action (labelled by whether a PIN is set) above the
/// danger-styled Factory reset. Both rows reuse the Root list geometry; the title-bar
/// back chevron returns to the Root list.
fn settings_security<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    pin_set: bool,
) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Security", theme::ACCENT, true)?;
    render_row(
        t,
        settings_row_rect(0),
        Glyph::Lock,
        if pin_set { "Change PIN" } else { "Set PIN" },
        None,
        true,
    )?;
    danger_row(t, settings_row_rect(1), "Factory reset")
}

/// A destructive option row: the [`render_row`] card, but with a warning glyph,
/// label, and drill-in chevron all in the decline colour.
fn danger_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(6, 6))
        .into_styled(PrimitiveStyle::with_fill(theme::ROW_BG))
        .draw(t)?;
    let cy = rect.y as i32 + rect.h as i32 / 2;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(rect.x + 8, (cy - 7) as u16),
        14,
        theme::DENY,
    )?;
    text_left(
        t,
        label,
        EgPoint::new(rect.x as i32 + 28, cy),
        Role::Body,
        theme::DENY,
    )?;
    glyph::draw(
        t,
        Glyph::Chevron,
        Point::new(rect.x + rect.w - 20, (cy - 6) as u16),
        12,
        theme::DENY,
    )
}

/// Brightness adjust: a coarse level bar plus the shared −/+/Back controls.
fn settings_brightness<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    level: u8,
) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Brightness", theme::ACCENT, false)?;
    level_bar(t, level)?;
    adjust_controls(t)
}

/// Touch-timeout adjust: the current value in seconds plus −/+/Back.
fn settings_timeout<D: DrawTarget<Color = Rgb565>>(t: &mut D, secs: u16) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Touch timeout", theme::ACCENT, false)?;
    let mut buf = [0u8; 8];
    text(
        t,
        fmt_secs(secs, &mut buf),
        EgPoint::new(MIDX, 104),
        Role::Heading,
        theme::TEXT,
    )?;
    adjust_controls(t)
}

/// Display-sleep adjust: the current timeout (or "Off") plus the shared −/+/Back.
fn settings_sleep<D: DrawTarget<Color = Rgb565>>(t: &mut D, secs: u16) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Display sleep", theme::ACCENT, false)?;
    if secs == 0 {
        text(
            t,
            "Off",
            EgPoint::new(MIDX, 104),
            Role::Heading,
            theme::TEXT,
        )?;
    } else {
        let mut buf = [0u8; 8];
        text(
            t,
            fmt_secs(secs, &mut buf),
            EgPoint::new(MIDX, 104),
            Role::Heading,
            theme::TEXT,
        )?;
    }
    adjust_controls(t)
}

/// Read-only device info: model, firmware version (bcdDevice) and chip serial, plus
/// Back. The numbers are hex-formatted with no alloc.
fn settings_info<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    version: u16,
    chipid: u64,
) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Device info", theme::ACCENT, false)?;
    text(
        t,
        "RS-Key trusted display",
        EgPoint::new(MIDX, 72),
        Role::Body,
        MUTED,
    )?;
    text(t, "Version", EgPoint::new(MIDX, 108), Role::Mono, MUTED)?;
    let mut vbuf = [b'0', b'x', 0, 0, 0, 0];
    vbuf[2..].copy_from_slice(&hex_u16(version));
    text(t, str8(&vbuf), EgPoint::new(MIDX, 130), Role::Heading, FG)?;
    text(t, "Serial", EgPoint::new(MIDX, 170), Role::Mono, MUTED)?;
    let sh = hex_u64(chipid);
    text(t, str8(&sh), EgPoint::new(MIDX, 192), Role::Mono, FG)?;
    button(t, BACK_RECT, "Back", MUTED)
}

/// The −/+/Back controls shared by both adjust pages, painted in their hit rects.
fn adjust_controls<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    key_surface(t, ADJ_MINUS_RECT, KEY_FILL, true)?;
    text(t, "-", center(ADJ_MINUS_RECT), Role::Strong, FG)?;
    key_surface(t, ADJ_PLUS_RECT, KEY_FILL, true)?;
    text(t, "+", center(ADJ_PLUS_RECT), Role::Strong, FG)?;
    button(t, BACK_RECT, "Back", MUTED)
}

/// A row of `BRIGHTNESS_LEVELS` segments, the first `filled` lit green — a coarse
/// gauge, centered above the −/+ controls.
fn level_bar<D: DrawTarget<Color = Rgb565>>(t: &mut D, filled: u8) -> Result<(), D::Error> {
    const SEG_W: u16 = 32;
    const SEG_H: u16 = 28;
    const SEG_GAP: u16 = 8;
    const BAR_Y: i32 = 96;
    let total = BRIGHTNESS_LEVELS as u16;
    let span = total * SEG_W + (total - 1) * SEG_GAP;
    let x0 = MIDX - span as i32 / 2;
    for i in 0..total {
        let fill = if i < filled as u16 { ALLOW_FILL } else { MUTED };
        Rectangle::new(
            EgPoint::new(x0 + i as i32 * (SEG_W + SEG_GAP) as i32, BAR_Y),
            Size::new(SEG_W as u32, SEG_H as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    }
    Ok(())
}

/// `&str` view of an all-ASCII fixed buffer (the hex/decimal we built); falls back to
/// empty rather than panic if the invariant were ever broken.
fn str8(buf: &[u8]) -> &str {
    core::str::from_utf8(buf).unwrap_or("")
}

/// Decimal-format `v` into the tail of `buf`, returning the written slice (no alloc).
fn fmt_u16(mut v: u16, buf: &mut [u8; 5]) -> &str {
    let mut i = buf.len();
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    str8(&buf[i..])
}

/// Format `secs` as `"NN s"` into `buf` (≤5 digits + " s" ≤ 8).
fn fmt_secs(secs: u16, buf: &mut [u8; 8]) -> &str {
    let mut tmp = [0u8; 5];
    let num = fmt_u16(secs, &mut tmp);
    let n = num.len();
    buf[..n].copy_from_slice(num.as_bytes());
    buf[n] = b' ';
    buf[n + 1] = b's';
    str8(&buf[..n + 2])
}

/// Format `"<n> <unit>"` into `buf` with no alloc (e.g. `"2 accounts"`); returns
/// empty if it wouldn't fit, so the caller never panics on a tiny buffer.
fn fmt_count<'a>(n: u16, unit: &str, buf: &'a mut [u8]) -> &'a str {
    let mut tmp = [0u8; 5];
    let num = fmt_u16(n, &mut tmp);
    let end = num.len() + 1 + unit.len();
    if end > buf.len() {
        return "";
    }
    buf[..num.len()].copy_from_slice(num.as_bytes());
    buf[num.len()] = b' ';
    buf[num.len() + 1..end].copy_from_slice(unit.as_bytes());
    str8(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HomeView, PANEL_H};
    use embedded_graphics::{Pixel, geometry::OriginDimensions};

    fn has_color(d: &Rec, r: Rect, c: Rgb565) -> bool {
        (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| d.at(x, y) == c))
    }

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
    fn locked_screen_fits_and_draws() {
        let mut d = Rec::new();
        render(&mut d, &Screen::Locked).unwrap();
        assert!(!d.oob, "locked screen drew outside the panel");
        assert!(d.drew_anything());
        // The lock circle (surface fill) + accent glyph sit in the upper-middle band.
        assert!(
            d.any_non_bg_in(Rect::new(0, 96, PANEL_W, 80)),
            "lock circle / glyph missing"
        );
    }

    #[test]
    fn pin_blocked_screen_fits_and_warns() {
        let mut d = Rec::new();
        render_pin_blocked(&mut d).unwrap();
        assert!(!d.oob, "pin-blocked screen drew outside the panel");
        // The "PIN blocked" heading is painted in the danger colour.
        assert!(
            has_color(&d, Rect::new(0, 176, PANEL_W, 28), theme::DANGER),
            "danger 'PIN blocked' heading missing"
        );
    }

    #[test]
    fn every_home_status_fits_and_draws_with_nav() {
        for status in [
            StatusKind::Boot,
            StatusKind::Idle,
            StatusKind::Processing,
            StatusKind::Touch,
        ] {
            let mut d = Rec::new();
            render(&mut d, &Screen::Home(HomeView { status })).unwrap();
            assert!(!d.oob, "home {status:?} drew outside the panel");
            assert!(d.drew_anything(), "home {status:?} drew nothing");
            // The bottom nav is always present on a tab; Home is the active one.
            assert!(
                has_color(&d, crate::nav_tab_rect(0), theme::ACCENT),
                "home nav tab not accented on {status:?}"
            );
        }
    }

    #[test]
    fn passkeys_list_paints_rows_in_their_hit_rects() {
        let rows = [
            RpRow {
                id: Label::clamp(b"github.com"),
                accounts: 2,
            },
            RpRow {
                id: Label::clamp(b"google.com"),
                accounts: 1,
            },
        ];
        let mut d = Rec::new();
        render_passkeys_list(&mut d, &rows, 2).unwrap();
        assert!(!d.oob, "list drew outside the panel");
        // Each RP row is a card in the exact rect hit_list maps a tap to.
        for i in 0..rows.len() as u16 {
            assert!(
                has_color(&d, crate::row_rect(PK_LIST_TOP, i), theme::ROW_BG),
                "row {i} card missing from its hit rect"
            );
        }
        assert!(has_color(&d, crate::nav_tab_rect(1), theme::ACCENT));
    }

    #[test]
    fn passkeys_list_empty_state_draws() {
        let mut d = Rec::new();
        render_passkeys_list(&mut d, &[], 0).unwrap();
        assert!(!d.oob && d.drew_anything());
        assert!(has_color(&d, crate::nav_tab_rect(1), theme::ACCENT));
    }

    #[test]
    fn service_detail_paints_accounts_and_back_affordance() {
        let accounts = [
            AccountRow {
                name: Label::clamp(b"alex@example.com"),
                protected: true,
            },
            AccountRow {
                name: Label::clamp(b"alex.dev"),
                protected: false,
            },
        ];
        let title = Label::clamp(b"github.com");
        let mut d = Rec::new();
        render_service(&mut d, &title, &accounts, 2).unwrap();
        assert!(!d.oob, "detail drew outside the panel");
        // The back chevron paints in TITLE_BACK_RECT — where hit_title_back maps a tap.
        assert!(
            has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT),
            "back chevron missing from its title-bar hit rect"
        );
        for i in 0..accounts.len() as u16 {
            assert!(d.any_non_bg_in(crate::row_rect(PK_LIST_TOP, i)));
        }
    }

    /// The Confirm-Delete screen paints its hold control in `DEL_HOLD_RECT` and the
    /// cancel chevron in `PK_BACK_RECT` (both in the decline colour) — exactly the
    /// regions `hit_del_hold` / `hit_pk_back` map a tap to — with the rp + account on
    /// screen so the user sees what they are removing.
    #[test]
    fn confirm_delete_paints_hold_and_cancel_in_their_hit_rects() {
        let rp = Label::clamp(b"github.com");
        let account = Label::clamp(b"alex@example.com");
        let mut d = Rec::new();
        render_confirm_delete(&mut d, &rp, &account).unwrap();
        assert!(!d.oob, "confirm-delete drew outside the panel");
        assert!(
            has_color(&d, crate::DEL_HOLD_RECT, theme::DENY),
            "Hold-to-delete not in its rect"
        );
        assert!(
            has_color(&d, crate::PK_BACK_RECT, theme::DENY),
            "cancel chevron not in its rect"
        );
    }

    /// The Factory-Reset confirm screen paints its hold control in `DEL_HOLD_RECT`
    /// and the cancel chevron in `PK_BACK_RECT` (both in the decline colour) — the
    /// regions `hit_del_hold` / `hit_pk_back` map a tap to.
    #[test]
    fn confirm_factory_reset_paints_hold_and_cancel_in_their_hit_rects() {
        let mut d = Rec::new();
        render_confirm_factory_reset(&mut d).unwrap();
        assert!(!d.oob, "confirm-factory-reset drew outside the panel");
        assert!(
            has_color(&d, crate::DEL_HOLD_RECT, theme::DENY),
            "Hold-to-reset not in its rect"
        );
        assert!(
            has_color(&d, crate::PK_BACK_RECT, theme::DENY),
            "cancel chevron not in its rect"
        );
    }

    /// The core security property: the Hold-to-approve control lives in `ALLOW_RECT`
    /// (in the approve colour) and Deny in `DENY_RECT` (in the deny colour) — exactly
    /// the regions `hit_confirm` maps a tap to — with the sanitized rp id on screen.
    #[test]
    fn confirm_paints_deny_and_hold_in_their_hit_rects() {
        let p = ConfirmPrompt::new("Sign in?", b"github.com", b"alice");
        let mut d = Rec::new();
        render(&mut d, &Screen::Confirm(p)).unwrap();
        assert!(!d.oob, "confirm drew outside the panel");
        // Deny carries the deny colour in DENY_RECT; Hold the approve colour in
        // ALLOW_RECT — paint and hit-test share the rect.
        assert!(
            has_color(&d, DENY_RECT, theme::DENY),
            "Deny not in its rect"
        );
        assert!(
            has_color(&d, ALLOW_RECT, theme::APPROVE),
            "Hold not in its rect"
        );
        // The two never overlap (disjoint by construction).
        assert!(!has_color(&d, DENY_RECT, theme::APPROVE));
    }

    #[test]
    fn confirm_buttons_stay_below_the_prompt_band() {
        // No approve/deny-coloured paint strays above the button band, so a tap in the
        // prompt area can never land on a button.
        let p = ConfirmPrompt::new("Register key?", b"example.org", b"");
        let mut d = Rec::new();
        render(&mut d, &Screen::Confirm(p)).unwrap();
        let row = crate::BTN_BAND_TOP - 1;
        assert!((0..PANEL_W).all(|x| {
            let c = d.at(x, row);
            c != theme::APPROVE && c != theme::DENY
        }));
    }

    #[test]
    fn pin_pad_fits_and_paints_keys_in_their_hit_rects() {
        let mut d = Rec::new();
        render(&mut d, &Screen::Pin(PinPad::new(4))).unwrap();
        assert!(!d.oob, "pin pad drew outside the panel");
        // The OK key is filled in its own hit rect (the key you see is the key you tap).
        let ok = pin_key_rect(2, 3);
        assert_eq!(d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3), ALLOW_FILL);
        assert!(d.any_non_bg_in(ok));
        // A digit key carries paint; Cancel is the low-emphasis outline in the deny colour.
        assert!(d.any_non_bg_in(pin_key_rect(0, 0)));
        assert!(has_color(&d, PIN_CANCEL_RECT, theme::DENY));
        // Four entered digits paint cyan masked dots in the band above the grid.
        assert!(has_color(&d, Rect::new(0, 48, PANEL_W, 24), theme::ACCENT));
    }

    #[test]
    fn pin_caption_paints_below_the_grid_in_the_danger_colour() {
        // A wrong-PIN re-prompt carries a danger-coloured caption in the strip under the
        // last key row (grid bottom is y300; the caption sits in 300..320).
        let mut d = Rec::new();
        let pad = PinPad::with_caption(
            0,
            "Enter PIN",
            Some(PinCaption::WrongPin { retries_left: 3 }),
        );
        render(&mut d, &Screen::Pin(pad)).unwrap();
        assert!(!d.oob, "caption drew outside the panel");
        assert!(
            has_color(&d, Rect::new(0, 301, PANEL_W, PANEL_H - 301), theme::DANGER),
            "wrong-PIN caption must paint in the danger colour below the grid"
        );
        // A fresh prompt (no caption) leaves that strip blank.
        let mut clean = Rec::new();
        render(&mut clean, &Screen::Pin(PinPad::new(0))).unwrap();
        assert!(
            !has_color(
                &clean,
                Rect::new(0, 301, PANEL_W, PANEL_H - 301),
                theme::DANGER
            ),
            "a fresh pad must not show a caption"
        );
    }

    #[test]
    fn pin_dots_partial_update_leaves_keys_intact() {
        let mut d = Rec::new();
        render(&mut d, &Screen::Pin(PinPad::new(2))).unwrap();
        let ok = pin_key_rect(2, 3);
        let key_px = d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3);
        // A partial dots update touches only the entry band, never the keys.
        render_pin_dots(&mut d, 5).unwrap();
        assert!(!d.oob);
        assert_eq!(
            d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3),
            key_px,
            "the static keys must survive a partial dots update"
        );
        // The band still carries dots for the new digit count.
        assert!((48..72).any(|y| (0..PANEL_W).any(|x| d.at(x, y) != BG)));
    }

    fn view(page: SettingsPage) -> SettingsView {
        SettingsView {
            page,
            brightness: 3,
            timeout_secs: 30,
            sleep_secs: 60,
            version: 0x078A,
            chipid: 0x0123_4567_89ab_cdef,
            pin_set: true,
        }
    }

    #[test]
    fn every_settings_page_fits_and_draws() {
        for page in [
            SettingsPage::Root,
            SettingsPage::Brightness,
            SettingsPage::Timeout,
            SettingsPage::Sleep,
            SettingsPage::Info,
            SettingsPage::Security,
        ] {
            let mut d = Rec::new();
            render(&mut d, &Screen::Settings(view(page))).unwrap();
            assert!(!d.oob, "settings {page:?} drew outside the panel");
            assert!(d.drew_anything(), "settings {page:?} drew nothing");
        }
    }

    #[test]
    fn security_page_paints_both_rows_under_either_pin_state() {
        for pin_set in [false, true] {
            let mut v = view(SettingsPage::Security);
            v.pin_set = pin_set;
            let mut d = Rec::new();
            render(&mut d, &Screen::Settings(v)).unwrap();
            assert!(
                !d.oob,
                "security (pin_set={pin_set}) drew outside the panel"
            );
            // Both Security rows are painted in the rects `hit_security` maps taps to.
            assert!(
                d.any_non_bg_in(settings_row_rect(0)),
                "PIN row unpainted (pin_set={pin_set})"
            );
            assert!(
                d.any_non_bg_in(settings_row_rect(1)),
                "Factory reset row unpainted (pin_set={pin_set})"
            );
        }
    }

    #[test]
    fn settings_root_paints_every_row_in_its_hit_rect() {
        let mut d = Rec::new();
        render(&mut d, &Screen::Settings(view(SettingsPage::Root))).unwrap();
        for i in 0..crate::SETTINGS_ROWS {
            assert!(
                d.any_non_bg_in(settings_row_rect(i)),
                "root row {i} unpainted"
            );
        }
    }

    #[test]
    fn adjust_pages_paint_controls_in_their_hit_rects() {
        for page in [
            SettingsPage::Brightness,
            SettingsPage::Timeout,
            SettingsPage::Sleep,
        ] {
            let mut d = Rec::new();
            render(&mut d, &Screen::Settings(view(page))).unwrap();
            assert!(d.any_non_bg_in(ADJ_MINUS_RECT), "{page:?} minus unpainted");
            assert!(d.any_non_bg_in(ADJ_PLUS_RECT), "{page:?} plus unpainted");
            assert!(d.any_non_bg_in(BACK_RECT), "{page:?} back unpainted");
        }
    }

    #[test]
    fn brightness_bar_lights_more_segments_at_higher_levels() {
        // The bar band is just above the −/+ controls; a higher level fills more of it.
        let band = Rect::new(0, 96, PANEL_W, 28);
        let count_lit = |level: u8| {
            let mut v = view(SettingsPage::Brightness);
            v.brightness = level;
            let mut d = Rec::new();
            render(&mut d, &Screen::Settings(v)).unwrap();
            (band.x..band.x + band.w)
                .filter(|&x| (band.y..band.y + band.h).any(|y| d.at(x, y) == ALLOW_FILL))
                .count()
        };
        assert!(
            count_lit(4) > count_lit(1),
            "more brightness must light more bar"
        );
    }

    #[test]
    fn header_row_and_nav_draw_within_bounds() {
        let mut d = Rec::new();
        render_header(&mut d, "Settings", true, Some(Glyph::Shield)).unwrap();
        let r = crate::row_rect(40, 0);
        render_row(&mut d, r, Glyph::Lock, "PIN", Some(("OK", theme::OK)), true).unwrap();
        render_nav(&mut d, NavTab::Settings).unwrap();
        assert!(!d.oob, "design-system widgets drew outside the panel");
        // The list-row card fills its rect (sampled on the flat top span).
        assert_eq!(d.at(r.x + r.w / 2, r.y + 3), theme::ROW_BG);
    }

    /// A row label far too long for its slot is clipped clear of the trailing value —
    /// the proportional-font regression that made "webauthn.io" touch "4 accounts".
    #[test]
    fn long_row_label_is_clipped_clear_of_the_trailing_value() {
        let r = crate::row_rect(40, 0);
        let txt = "4 accounts";
        let mut d = Rec::new();
        render_row(
            &mut d,
            r,
            Glyph::Globe,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some((txt, theme::MUTED)),
            true,
        )
        .unwrap();
        assert!(!d.oob);
        // Reconstruct the trailing value's left edge; the ROW_TRAILING_GAP-wide seam to
        // its left must be free of the (white) label text.
        let right_x = r.x as i32 + r.w as i32 - 8 - 12;
        let value_left = (right_x - 4) - font::width(txt, Role::Body).unwrap() as i32;
        for x in (value_left - ROW_TRAILING_GAP).max(0)..value_left {
            for y in r.y..r.y + r.h {
                assert_ne!(
                    d.at(x as u16, y),
                    theme::TEXT,
                    "label not clipped clear of the trailing value at x={x}"
                );
            }
        }
    }

    /// The two-tier chrome paints within its strips and, with `back`, the title-bar
    /// chevron lands in `TITLE_BACK_RECT` (where `hit_title_back` maps a tap).
    #[test]
    fn chrome_bars_draw_in_their_strips() {
        let mut d = Rec::new();
        status_bar(&mut d).unwrap();
        title_bar(&mut d, "Passkeys", theme::ACCENT, true).unwrap();
        assert!(!d.oob, "chrome drew outside the panel");
        // The status strip carries the RS-Key wordmark + USB indicator.
        assert!(
            d.any_non_bg_in(Rect::new(0, 0, PANEL_W, STATUS_BAR_H)),
            "status bar painted nothing"
        );
        // The back chevron lands in its title-bar hit rect.
        assert!(
            has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT),
            "back chevron not in TITLE_BACK_RECT"
        );
    }

    #[test]
    fn nav_accents_only_the_active_tab() {
        let mut d = Rec::new();
        render_nav(&mut d, NavTab::Settings).unwrap();
        let has = |r: Rect, c: Rgb565| {
            (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| d.at(x, y) == c))
        };
        assert!(
            has(crate::nav_tab_rect(2), theme::ACCENT),
            "active tab not accented"
        );
        assert!(
            !has(crate::nav_tab_rect(0), theme::ACCENT),
            "inactive tab accented"
        );
    }

    #[test]
    fn hold_fill_grows_left_to_right_with_a_flat_edge() {
        // Count fill pixels along the horizontal centre line only — whole-column
        // sampling would also catch the fill-coloured outline (it spans the full
        // width) and mask the progress difference.
        let r = Rect::new(20, 200, 120, 60);
        let yc = r.y + r.h / 2;
        let lit = |num: u16| {
            let mut d = Rec::new();
            render_hold_fill(&mut d, r, "Hold", 0, num, 10, theme::APPROVE).unwrap();
            (r.x..r.x + r.w)
                .filter(|&x| d.at(x, yc) == theme::APPROVE)
                .count()
        };
        assert!(
            lit(8) > lit(2),
            "more hold progress must fill more of the button"
        );
        // The advancing edge is flat (only the left corners are rounded), so the fill
        // reaches the top row right up to its right edge — a rounded-all-corners fill
        // would leave that corner empty (the artifact this guards against).
        let mut d = Rec::new();
        render_hold_fill(&mut d, r, "Hold", 0, 5, 10, theme::APPROVE).unwrap();
        let w = r.w / 2; // num/den = 5/10
        assert_eq!(d.at(r.x + w - 3, r.y + 2), theme::APPROVE);
    }
}
