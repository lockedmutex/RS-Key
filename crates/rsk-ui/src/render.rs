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
        RoundedRectangle, StrokeAlignment, Triangle,
    },
};

use crate::{
    ADJ_MINUS_RECT, ADJ_PLUS_RECT, ALLOW_RECT, AccountRow, AuditKind, AuditRow, BACK_RECT,
    BACKUP_REVEAL_RECT, BACKUP_SEAL_RECT, BRIGHTNESS_LEVELS, BackupView, CONTENT_TOP,
    ConfirmPrompt, DEL_HOLD_RECT, DENY_RECT, FMT_PHRASE_RECT, FMT_SHARES_RECT, Glyph, HomeView,
    Label, NAV_H, NAV_TABS, NAV_TOP, NavTab, PAGER_NEXT_RECT, PAGER_PREV_RECT, PANEL_H, PANEL_W,
    PICK_CONTINUE_RECT, PICK_N_MINUS_RECT, PICK_N_PLUS_RECT, PICK_T_MINUS_RECT, PICK_T_PLUS_RECT,
    PIN_CANCEL_RECT, PIN_COLS, PIN_EYE_RECT, PIN_ROWS, PK_BACK_RECT, PK_LIST_TOP, PinCaption,
    PinKey, PinPad, Point, RN_BKSP_RECT, RN_DOWN_RECT, RN_FIELD_RECT, RN_INS_RECT, RN_SAVE_RECT,
    RN_UP_RECT, Rect, RevealKind, RpRow, STATUS_BAR_H, Screen, SettingsPage, SettingsView,
    StatusKind, SuccessKind, TITLE_BACK_RECT, TITLE_BAR_H, TITLE_EDIT_RECT, font, font::Role,
    glyph, hex_u16, hex_u64, nav_tab_rect, page_count, pin_grid_key, pin_key_rect,
    settings_row_rect, theme,
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
/// rpId + account count + drill-in chevron), the list tail (pager when it spans more
/// than one page, else an "N items" footer), and the nav bar. `rows` is the current
/// page's slice; `page` is its 0-based index; `total` is the true RP count. A full-frame
/// paint, so it clears first. Standalone rather than a `Screen` variant — too large for
/// the `Copy` enum.
pub fn render_passkeys_list<D>(
    t: &mut D,
    rows: &[RpRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
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
                r.shown(),
                Some((trailing, MUTED)),
                true,
            )?;
        }
        list_tail(t, page, total, "item", "items")?;
    }
    render_nav(t, NavTab::Passkeys)
}

/// The per-RP service detail: a back-chevron header + the (truncated) shown name (the
/// device-local nickname or the rpId), a pencil [edit affordance](TITLE_EDIT_RECT) at the
/// right of the title bar that opens the rename screen, one row per resident account (key
/// glyph + sanitized name + a "UV" tag when credProtect-gated), an "N accounts" footer,
/// and the nav bar. The firmware makes each row tappable to start the Confirm-Delete flow
/// ([`render_confirm_delete`]).
pub fn render_service<D>(
    t: &mut D,
    title: &Label,
    accounts: &[AccountRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, title.as_str(), theme::ACCENT, true)?;
    glyph_centered(t, Glyph::Edit, TITLE_EDIT_RECT, 18, theme::ACCENT)?;
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
    list_tail(t, page, total, "account", "accounts")?;
    render_nav(t, NavTab::Passkeys)
}

/// The rename screen: a character-wheel editor for a relying party's device-local
/// nickname. Status + title chrome (the back chevron cancels), a `NICKNAME` caption, the
/// value field with a caret, then the wheel — a backspace key on the left, the ▲ / big
/// candidate / ▼ centre column, and an insert (`+`) key on the right — over a full-width
/// Save button. `value` is the current buffer; `candidate` the wheel's current byte
/// (`b' '` shows as an underscore so a space is visible). The caret is static (no blink:
/// there is no framebuffer / animation loop, as on the lock screen).
pub fn render_rename<D>(t: &mut D, value: &str, candidate: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Rename", theme::ACCENT, true)?;
    text_left(
        t,
        "NICKNAME",
        EgPoint::new(14, RN_FIELD_RECT.y as i32 - 10),
        Role::Mono,
        theme::CAPTION,
    )?;

    // The value field: a bordered surface holding the text and a static caret.
    let field = RN_FIELD_RECT;
    RoundedRectangle::with_equal_corners(eg_rect(field), Size::new(8, 8))
        .into_styled(PrimitiveStyle::with_fill(theme::SURFACE))
        .draw(t)?;
    RoundedRectangle::with_equal_corners(eg_rect(field), Size::new(8, 8))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(theme::BORDER_FIELD)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    let pad = 10i32;
    let inner = Rect::new(
        field.x + pad as u16,
        field.y,
        field.w - 2 * pad as u16,
        field.h,
    );
    let baseline = field.y as i32 + field.h as i32 / 2;
    text_left_clipped(
        t,
        value,
        EgPoint::new(inner.x as i32, baseline),
        Role::Body,
        FG,
        inner,
    )?;
    let text_w = font::width(value, Role::Body).unwrap_or(0) as i32;
    let caret_x = (inner.x as i32 + text_w).min(field.x as i32 + field.w as i32 - 6);
    Line::new(
        EgPoint::new(caret_x, field.y as i32 + 7),
        EgPoint::new(caret_x, field.y as i32 + field.h as i32 - 7),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 1))
    .draw(t)?;

    // The wheel: up / down arrows around the big candidate character.
    key_surface(t, RN_UP_RECT, KEY_FILL, true)?;
    wheel_arrow(t, RN_UP_RECT, true, theme::ACCENT)?;
    key_surface(t, RN_DOWN_RECT, KEY_FILL, true)?;
    wheel_arrow(t, RN_DOWN_RECT, false, theme::ACCENT)?;
    let cy = (RN_UP_RECT.y + RN_UP_RECT.h + RN_DOWN_RECT.y) as i32 / 2;
    if candidate == b' ' {
        // A space candidate: a short underline so the wheel isn't blank.
        Line::new(
            EgPoint::new(MIDX - 10, cy + 9),
            EgPoint::new(MIDX + 10, cy + 9),
        )
        .into_styled(PrimitiveStyle::with_stroke(FG, 2))
        .draw(t)?;
    } else {
        let b = [candidate];
        let s = core::str::from_utf8(&b).unwrap_or("?");
        text(t, s, EgPoint::new(MIDX, cy), Role::Ready, FG)?;
    }

    // Backspace (left) and insert-candidate (right).
    key_surface(t, RN_BKSP_RECT, theme::KEY_DARK, true)?;
    glyph_centered(t, Glyph::Backspace, RN_BKSP_RECT, 22, MUTED)?;
    key_surface(t, RN_INS_RECT, KEY_FILL, true)?;
    let ic = center(RN_INS_RECT);
    Line::new(EgPoint::new(ic.x - 9, ic.y), EgPoint::new(ic.x + 9, ic.y))
        .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 2))
        .draw(t)?;
    Line::new(EgPoint::new(ic.x, ic.y - 9), EgPoint::new(ic.x, ic.y + 9))
        .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 2))
        .draw(t)?;

    button(t, RN_SAVE_RECT, "Save", ALLOW_FILL)
}

/// A filled wheel arrow (▲ when `up`, else ▼) centred in `r`.
fn wheel_arrow<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    r: Rect,
    up: bool,
    color: Rgb565,
) -> Result<(), D::Error> {
    let cx = (r.x + r.w / 2) as i32;
    let cy = (r.y + r.h / 2) as i32;
    let (apex, left, right) = if up {
        (
            EgPoint::new(cx, cy - 8),
            EgPoint::new(cx - 9, cy + 6),
            EgPoint::new(cx + 9, cy + 6),
        )
    } else {
        (
            EgPoint::new(cx, cy + 8),
            EgPoint::new(cx - 9, cy - 6),
            EgPoint::new(cx + 9, cy - 6),
        )
    };
    Triangle::new(apex, left, right)
        .into_styled(PrimitiveStyle::with_fill(color))
        .draw(t)
}

/// The read-only on-device audit log (Settings → Security → Audit log): the most recent
/// journal events, newest first — a status dot coloured by [`AuditKind`], the event
/// label, and a compact "time ago" for current-power-cycle entries. The back chevron
/// returns to Security. Standalone full-frame like [`render_passkeys_list`] but without
/// the nav bar (a settings sub-screen, not a tab). `rows` is the current page's slice,
/// `page` its 0-based index, `total` the live journal depth — so the tail shows the pager
/// ("page / pages") when the log spans more than one page, else a true "N events" count.
pub fn render_audit_log<D>(
    t: &mut D,
    rows: &[AuditRow],
    page: u16,
    total: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Audit log", theme::ACCENT, true)?;
    if rows.is_empty() {
        glyph::draw(t, Glyph::Clock, Point::new(MIDX as u16 - 18, 96), 36, MUTED)?;
        text(
            t,
            "No activity yet",
            EgPoint::new(MIDX, 160),
            Role::Body,
            MUTED,
        )?;
    } else {
        for (i, r) in rows.iter().enumerate() {
            audit_row(t, crate::row_rect(PK_LIST_TOP, i as u16), r)?;
        }
        list_tail(t, page, total, "event", "events")?;
    }
    Ok(())
}

/// The read-only **Backup** screen (Settings → Security → Backup). It paints the seed-
/// backup status the device genuinely tracks — *not* the static mockup's fictional "N of M
/// recovery shares": backup here is a one-time seed export over the USB host channel, then
/// sealed. A colour-coded status plate (review needed / backed up / no seed / restore-only)
/// sits over two fact rows (recovery seed present, export window sealed) and a muted hint
/// that the host app drives the backup — there is no on-device action. The title-bar back
/// chevron exits.
pub fn render_backup<D>(t: &mut D, v: &BackupView) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Backup", theme::ACCENT, true)?;

    // The status plate + hint. State only what the device actually knows — the export
    // *window* state — never "a backup exists": the device cannot verify an export ever
    // happened (`sealed` is set by `BACKUP_FINALIZE`, which merely closes the window), so the
    // trusted headline must not vouch for a recovery copy it can't see. The fact rows below
    // restate the same window state.
    let (icon, l1, l2, fill, border, fg, h1, h2) = if !v.has_seed {
        (
            Glyph::Warn,
            "No recovery seed",
            "Nothing to back up yet.",
            theme::DANGER_BG,
            theme::DANGER_BORDER,
            theme::DANGER,
            "Set up the device first.",
            "",
        )
    } else if !v.exportable {
        (
            Glyph::Lock,
            "Restore-only",
            "Seed export disabled.",
            theme::TINT_BLUE,
            theme::BORDER_UPDATE,
            theme::ACCENT_TEXT,
            "Recovery is restore-only",
            "on this device.",
        )
    } else if v.sealed {
        (
            Glyph::Lock,
            "Export sealed",
            "Seed export is closed.",
            theme::TINT_BLUE,
            theme::BORDER_UPDATE,
            theme::ACCENT_TEXT,
            "Reset the device to",
            "export again.",
        )
    } else {
        (
            Glyph::Warn,
            "Review needed",
            "Seed export still open.",
            theme::WARN_BG,
            theme::WARN_BORDER,
            theme::WARN,
            "Back up the seed using",
            "the RS-Key app over USB.",
        )
    };
    let plate = Rect::new(14, CONTENT_TOP + 8, PANEL_W - 28, 54);
    RoundedRectangle::with_equal_corners(eg_rect(plate), Size::new(11, 11))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    RoundedRectangle::with_equal_corners(eg_rect(plate), Size::new(11, 11))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(border)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    glyph::draw(t, icon, Point::new(plate.x + 12, plate.y + 18), 18, fg)?;
    let tx = plate.x as i32 + 42;
    // Clip the two lines to the plate interior so a wider face never overruns the panel.
    let clip = Rect::new(
        tx as u16,
        plate.y,
        (plate.x + plate.w).saturating_sub(6 + tx as u16),
        plate.h,
    );
    text_left_clipped(
        t,
        l1,
        EgPoint::new(tx, plate.y as i32 + 20),
        Role::Strong,
        fg,
        clip,
    )?;
    text_left_clipped(
        t,
        l2,
        EgPoint::new(tx, plate.y as i32 + 38),
        Role::Body,
        MUTED,
        clip,
    )?;

    // The honest facts, as a small group below the plate.
    text_left(
        t,
        "RECOVERY",
        EgPoint::new(14, plate.y as i32 + plate.h as i32 + 14),
        Role::Mono,
        theme::CAPTION,
    )?;
    let row0 = Rect::new(16, 138, PANEL_W - 32, 34);
    let row1 = Rect::new(16, 176, PANEL_W - 32, 34);
    let seed = if v.has_seed {
        ("Present", theme::OK)
    } else {
        ("Missing", theme::DANGER)
    };
    render_row(t, row0, Glyph::Lifebuoy, "Recovery seed", Some(seed), false)?;
    let window = if v.sealed {
        ("Sealed", theme::OK)
    } else if v.exportable {
        ("Open", theme::WARN)
    } else {
        ("Disabled", MUTED)
    };
    render_row(t, row1, Glyph::Lock, "Backup window", Some(window), false)?;

    if v.can_reveal {
        // Window open + seed readable: the on-device actions. The phrase is shown ON the
        // device (it never crosses USB); sealing closes the window when the user is done.
        button(
            t,
            BACKUP_REVEAL_RECT,
            "Show recovery phrase",
            theme::ACCENT_FILL,
        )?;
        button(t, BACKUP_SEAL_RECT, "Seal backup", theme::KEY_BG)
    } else {
        // No on-device action available — a per-state hint points at the next step. A blank
        // `h2` draws nothing (the `!has_seed` state has a single line).
        text(t, h1, EgPoint::new(MIDX, 270), Role::Body, MUTED)?;
        text(t, h2, EgPoint::new(MIDX, 288), Role::Body, MUTED)
    }
}

/// The **recovery-format chooser** (after the device-PIN re-auth, before any secret is
/// shown): two cards — a single BIP-39 phrase, or SLIP-39 Shamir shares. Chrome-less like
/// the reveal gate; the firmware maps a tap with [`crate::hit_backup_format`] and the
/// top-left [`crate::PK_BACK_RECT`] chevron cancels. Each card is a title over a dim format
/// sublabel.
pub fn render_backup_format<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Choose format",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    choice_card(t, FMT_PHRASE_RECT, "Single phrase", "24 words (BIP-39)")?;
    choice_card(
        t,
        FMT_SHARES_RECT,
        "Shamir shares",
        "Split T-of-N (SLIP-39)",
    )
}

/// A two-line choice card: a bright title over a dim sublabel, on a bordered key surface —
/// the format-chooser's tappable options.
fn choice_card<D>(t: &mut D, r: Rect, title: &str, sub: &str) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    key_surface(t, r, KEY_FILL, true)?;
    text_left(
        t,
        title,
        EgPoint::new(r.x as i32 + 14, r.y as i32 + 22),
        Role::Strong,
        FG,
    )?;
    text_left(
        t,
        sub,
        EgPoint::new(r.x as i32 + 14, r.y as i32 + 44),
        Role::Body,
        MUTED,
    )
}

/// The SLIP-39 **share picker**: two −/+ steppers (recovery threshold `T`, total shares `N`)
/// and a Continue button, summarising "Any T of N shares". Chrome-less like the chooser; the
/// firmware maps taps with [`crate::hit_share_picker`], steps the pair with
/// [`crate::step_share_params`], and the top-left [`crate::PK_BACK_RECT`] chevron returns to
/// the chooser.
pub fn render_share_picker<D>(t: &mut D, threshold: u8, total: u8) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Shamir shares",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    stepper_row(
        t,
        "Needed to recover",
        PICK_T_MINUS_RECT,
        PICK_T_PLUS_RECT,
        threshold,
    )?;
    stepper_row(
        t,
        "Total shares",
        PICK_N_MINUS_RECT,
        PICK_N_PLUS_RECT,
        total,
    )?;
    // "Any T of N shares reconstruct the seed." — split across two lines.
    let mut b1 = [0u8; 5];
    let mut b2 = [0u8; 5];
    let mut line = [0u8; 24];
    let mut i = 0;
    for &c in b"Any " {
        line[i] = c;
        i += 1;
    }
    for &c in fmt_u16(threshold as u16, &mut b1).as_bytes() {
        line[i] = c;
        i += 1;
    }
    for &c in b" of " {
        line[i] = c;
        i += 1;
    }
    for &c in fmt_u16(total as u16, &mut b2).as_bytes() {
        line[i] = c;
        i += 1;
    }
    for &c in b" shares" {
        line[i] = c;
        i += 1;
    }
    text(
        t,
        str8(&line[..i]),
        EgPoint::new(MIDX, 228),
        Role::Body,
        theme::ACCENT_TEXT,
    )?;
    button(t, PICK_CONTINUE_RECT, "Continue", theme::ACCENT_FILL)
}

/// One picker stepper: a caption above a `[−]  value  [+]` row, the value centred between the
/// two key surfaces. Used for both the threshold and total rows.
fn stepper_row<D>(
    t: &mut D,
    caption: &str,
    minus: Rect,
    plus: Rect,
    value: u8,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    text_left(
        t,
        caption,
        EgPoint::new(16, minus.y as i32 - 14),
        Role::Body,
        MUTED,
    )?;
    key_surface(t, minus, KEY_FILL, true)?;
    text(t, "-", center(minus), Role::Strong, FG)?;
    key_surface(t, plus, KEY_FILL, true)?;
    text(t, "+", center(plus), Role::Strong, FG)?;
    let mut b = [0u8; 5];
    text(
        t,
        fmt_u16(value as u16, &mut b),
        EgPoint::new(MIDX, minus.y as i32 + minus.h as i32 / 2),
        Role::Ready,
        FG,
    )
}

/// The deliberate **reveal gate** before showing the recovery phrase: a warning that the
/// next screen prints the master secret, over a [hold button](render_hold_button) the
/// firmware drives with [`crate::DEL_HOLD_RECT`] / [`crate::PK_BACK_RECT`] (cancel). The
/// device PIN is checked *before* this screen; the hold is the second, deliberate gesture.
pub fn render_reveal_warning<D>(t: &mut D, kind: RevealKind) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (heading, line1) = match kind {
        RevealKind::Phrase => ("Reveal phrase", "Showing 24 secret words"),
        RevealKind::Shares => ("Reveal shares", "Showing secret shares"),
    };
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        heading,
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(PANEL_W / 2 - 16, 56),
        32,
        theme::WARN,
    )?;
    text_left(t, line1, EgPoint::new(16, 118), Role::Body, theme::WARN)?;
    text_left(
        t,
        "that restore everything.",
        EgPoint::new(16, 136),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "Make sure no person or",
        EgPoint::new(16, 160),
        Role::Body,
        MUTED,
    )?;
    text_left(
        t,
        "camera can see the screen.",
        EgPoint::new(16, 178),
        Role::Body,
        MUTED,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to reveal", theme::DENY)
}

/// The **seal confirmation**: closing the backup window is one-way (until a factory reset),
/// so it takes a deliberate hold. Same chrome-less layout / hold mechanics as the reveal
/// gate; the firmware drives [`crate::DEL_HOLD_RECT`] / [`crate::PK_BACK_RECT`].
pub fn render_seal_confirm<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Seal backup",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new(PANEL_W / 2 - 16, 56),
        32,
        theme::WARN,
    )?;
    text_left(
        t,
        "Closes the backup window.",
        EgPoint::new(16, 118),
        Role::Body,
        theme::WARN,
    )?;
    text_left(
        t,
        "You can't show or export the",
        EgPoint::new(16, 142),
        Role::Body,
        MUTED,
    )?;
    text_left(
        t,
        "phrase again until a reset.",
        EgPoint::new(16, 160),
        Role::Body,
        MUTED,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to seal", theme::DENY)
}

/// The **recovery phrase** itself: the 24 BIP-39 words rendered on the trusted display so
/// the seed never crosses USB. Twelve words per page in two numbered columns; the
/// [pager](render_pager) walks the pages, the title-bar back chevron exits. `words` is the
/// full ordered list (held transiently by the firmware, never stored), `page` the 0-based
/// page. The words are drawn bright with a dim index so a transcription error is unlikely.
pub fn render_seed_phrase<D>(
    t: &mut D,
    words: &[&str],
    page: u16,
    pages: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Recovery phrase", theme::ACCENT, true)?;
    word_grid(t, words, page)?;
    render_pager(t, page, pages)
}

/// Paint up to twelve numbered words of `words` for `page` (0-based, 12 per page) in two
/// columns of six — the shared body of the recovery-phrase and SLIP-39 share screens. The
/// 1-based word number (within `words`, so per-phrase or per-share) is dimmed to the left of
/// each bright word so a transcription error is unlikely.
fn word_grid<D>(t: &mut D, words: &[&str], page: u16) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let per_page = 12usize;
    let start = page as usize * per_page;
    for c in 0..per_page {
        let gi = start + c;
        if gi >= words.len() {
            break;
        }
        let col = c / 6;
        let row = c % 6;
        let base_x = if col == 0 { 16 } else { 126 };
        let cy = 76 + row as i32 * 27;
        // "N." — the 1-based word number, right-aligned just left of the word and dimmed.
        let n = (gi + 1) as u8;
        let mut nb = [0u8; 4];
        let mut k = 0;
        if n >= 10 {
            nb[k] = b'0' + n / 10;
            k += 1;
        }
        nb[k] = b'0' + n % 10;
        k += 1;
        nb[k] = b'.';
        k += 1;
        let ns = core::str::from_utf8(&nb[..k]).unwrap_or(".");
        text_right(
            t,
            ns,
            EgPoint::new(base_x + 22, cy),
            Role::Mono,
            theme::CAPTION,
        )?;
        text_left(
            t,
            words[gi],
            EgPoint::new(base_x + 27, cy),
            Role::BodyStrong,
            FG,
        )?;
    }
    Ok(())
}

/// One page of a SLIP-39 **share**: `words` (the current share's full word list), under a
/// "Share i/N" title so the user knows which share to label. `page`/`pages` are the **global**
/// position across all shares (so the pager arrows dim correctly at the first/last page); the
/// share's own sub-page (which 12 words to show) is derived from `page` modulo the share's
/// page count. The words are secret (any threshold of shares reconstruct the seed) — the
/// firmware holds them transiently and zeroizes on exit.
pub fn render_slip39_share<D>(
    t: &mut D,
    words: &[&str],
    share_idx: u16,
    share_total: u16,
    page: u16,
    pages: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    let mut buf = [0u8; 18];
    title_bar(
        t,
        fmt_share_title(share_idx, share_total, &mut buf),
        theme::ACCENT,
        true,
    )?;
    let per_share = (words.len() as u16).div_ceil(12).max(1);
    word_grid(t, words, page % per_share)?;
    render_pager(t, page, pages)
}

/// Format `"Share P/N"` into `buf`, no alloc. Sized for the full u16 domain: `"Share " (6)
/// + 5 + "/" + 5 = 17` bytes.
fn fmt_share_title(p: u16, n: u16, buf: &mut [u8; 18]) -> &str {
    let mut i = 0;
    for &c in b"Share " {
        buf[i] = c;
        i += 1;
    }
    let mut a = [0u8; 5];
    for &c in fmt_u16(p, &mut a).as_bytes() {
        buf[i] = c;
        i += 1;
    }
    buf[i] = b'/';
    i += 1;
    let mut b = [0u8; 5];
    for &c in fmt_u16(n, &mut b).as_bytes() {
        buf[i] = c;
        i += 1;
    }
    str8(&buf[..i])
}

/// One audit row: a status dot (its colour the at-a-glance signal), the event label, and
/// a right-aligned "time ago". Mirrors [`render_row`]'s card + clip metrics, but leads
/// with a coloured dot instead of a muted glyph.
fn audit_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    r: &AuditRow,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(6, 6))
        .into_styled(PrimitiveStyle::with_fill(theme::ROW_BG))
        .draw(t)?;
    let cy = rect.y as i32 + rect.h as i32 / 2;
    let dot: u32 = 12;
    Circle::new(EgPoint::new(rect.x as i32 + 9, cy - dot as i32 / 2), dot)
        .into_styled(PrimitiveStyle::with_fill(audit_dot(r.kind)))
        .draw(t)?;
    // Trailing time first (right), then the label clipped to end before it.
    let right_x = rect.x as i32 + rect.w as i32 - 8;
    let label_x = rect.x as i32 + 30;
    let label_right = if let Some(secs) = r.secs_ago {
        let mut buf = [0u8; 8];
        let s = fmt_ago(secs, &mut buf);
        text_right(t, s, EgPoint::new(right_x, cy), Role::Mono, MUTED)?;
        right_x - font::width(s, Role::Mono).unwrap_or(0) as i32 - ROW_TRAILING_GAP
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
        r.kind.label(),
        EgPoint::new(label_x, cy),
        Role::Body,
        FG,
        clip,
    )
}

/// The status-dot colour for an audit event class (green = sign-in, blue = add/backup,
/// red = lockout/reset, grey = everything else).
fn audit_dot(kind: AuditKind) -> Rgb565 {
    match kind {
        AuditKind::Login => theme::SUCCESS,
        AuditKind::Register | AuditKind::Backup => theme::ACCENT,
        AuditKind::Denied | AuditKind::Reset => theme::DANGER,
        _ => theme::GREY,
    }
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

/// The bottom of a scrollable list: the [pager](render_pager) when it spans more than
/// one page, else the item-count footer. Keeps the three list screens consistent.
fn list_tail<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    page: u16,
    total: u16,
    one: &str,
    many: &str,
) -> Result<(), D::Error> {
    let pages = page_count(total);
    if pages > 1 {
        render_pager(t, page, pages)
    } else {
        footer_count(t, total, if total == 1 { one } else { many })
    }
}

/// Paint the pager band: a `‹` prev arrow (dimmed on the first page), a centred
/// "page / pages" indicator, and a `›` next arrow (dimmed on the last page). The arrows
/// land in [`PAGER_PREV_RECT`] / [`PAGER_NEXT_RECT`] — exactly where [`crate::hit_pager`]
/// maps a tap — so a painted arrow and its hit target can never disagree.
fn render_pager<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    page: u16,
    pages: u16,
) -> Result<(), D::Error> {
    let cy = PAGER_PREV_RECT.y as i32 + PAGER_PREV_RECT.h as i32 / 2;
    let prev_col = if page > 0 {
        theme::ACCENT
    } else {
        theme::CAPTION
    };
    let next_col = if page + 1 < pages {
        theme::ACCENT
    } else {
        theme::CAPTION
    };
    glyph::draw(
        t,
        Glyph::Back,
        Point::new(
            PAGER_PREV_RECT.x + PAGER_PREV_RECT.w / 2 - 8,
            (cy - 8) as u16,
        ),
        16,
        prev_col,
    )?;
    glyph::draw(
        t,
        Glyph::Chevron,
        Point::new(
            PAGER_NEXT_RECT.x + PAGER_NEXT_RECT.w / 2 - 8,
            (cy - 8) as u16,
        ),
        16,
        next_col,
    )?;
    let mut buf = [0u8; 13];
    text(
        t,
        fmt_pages(page + 1, pages, &mut buf),
        EgPoint::new(MIDX, cy),
        Role::Mono,
        MUTED,
    )
}

/// Format `"P / N"` (current / total pages) into `buf`, no alloc. Sized for the full u16
/// domain: 5 digits + " / " + 5 digits = 13 bytes (page counts never reach that, but the
/// buffer matches `fmt_u16`'s range so it can't index out of bounds).
fn fmt_pages(p: u16, n: u16, buf: &mut [u8; 13]) -> &str {
    let mut a = [0u8; 5];
    let ps = fmt_u16(p, &mut a);
    let mut b = [0u8; 5];
    let ns = fmt_u16(n, &mut b);
    let mut i = 0;
    for &c in ps.as_bytes() {
        buf[i] = c;
        i += 1;
    }
    for &c in b" / " {
        buf[i] = c;
        i += 1;
    }
    for &c in ns.as_bytes() {
        buf[i] = c;
        i += 1;
    }
    str8(&buf[..i])
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
    back_button(t, PK_BACK_RECT, theme::DENY)?;
    text_left(
        t,
        "Delete passkey",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
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
    back_button(t, PK_BACK_RECT, theme::DENY)?;
    text_left(
        t,
        "Factory reset",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
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

// --- Success screens -------------------------------------------------------

/// Centre of the success "pop" circle.
const SUCCESS_CY: i32 = 112;
/// Resting diameter of the success circle (the 100% frame).
const SUCCESS_DIA: u32 = 72;
/// The fixed square the circle is cleared/redrawn within — large enough for the 1.06
/// overshoot frame plus a margin, and clear of the heading below it, so a smaller pop
/// frame fully erases a larger one without ever touching the static chrome.
const SUCCESS_BOX: u32 = SUCCESS_DIA + 18;

/// `(mark colour, circle fill, mark glyph, heading, subtitle)` for a success kind. A
/// green check on a green tint for approve/delete; the grey [`Glyph::Rotate`] on a
/// neutral chip for the wipe (which restarts, hence no green "all-good" check).
fn success_visuals(kind: SuccessKind) -> (Rgb565, Rgb565, Glyph, &'static str, &'static str) {
    match kind {
        SuccessKind::Approved => (
            theme::SUCCESS,
            theme::SUCCESS_BG,
            Glyph::Check,
            "Approved",
            "",
        ),
        SuccessKind::Deleted => (
            theme::SUCCESS,
            theme::SUCCESS_BG,
            Glyph::Check,
            "Passkey deleted",
            "Removed from RS-Key.",
        ),
        SuccessKind::Wiped => (
            theme::GREY,
            theme::CHIP,
            Glyph::Rotate,
            "RS-Key erased",
            "Restarting...",
        ),
    }
}

/// Paint a success screen's static chrome: the heading, an optional subtitle, and —
/// when `with_button` — a primary **Done** button in [`DEL_HOLD_RECT`] (the firmware
/// dismisses it via [`crate::hit_success_done`]). The circle area is left as
/// background; the firmware animates the "pop" in with [`render_success_circle`],
/// which repaints *only* the circle and so never disturbs (or flickers) this chrome.
pub fn render_success<D>(t: &mut D, kind: SuccessKind, with_button: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    let (_, _, _, heading, subtitle) = success_visuals(kind);
    text(t, heading, EgPoint::new(MIDX, 178), Role::Heading, FG)?;
    if !subtitle.is_empty() {
        text(t, subtitle, EgPoint::new(MIDX, 206), Role::Body, MUTED)?;
    }
    if with_button {
        RoundedRectangle::with_equal_corners(
            eg_rect(DEL_HOLD_RECT),
            Size::new(BTN_RADIUS, BTN_RADIUS),
        )
        .into_styled(PrimitiveStyle::with_fill(theme::ACCENT_FILL))
        .draw(t)?;
        text(t, "Done", center(DEL_HOLD_RECT), Role::Strong, FG)?;
    }
    Ok(())
}

/// Repaint just the success circle at `scale_pct`% of its resting size — the building
/// block of the firmware's pop (e.g. 60 → 106 → 100, ending at 100 for the resting
/// frame). It clears the fixed [`SUCCESS_BOX`] to background first (so a smaller frame
/// erases a larger one cleanly), then fills the tinted circle and centres the mark
/// glyph at ~48% of the circle (the Lock-in-circle proportion on the blocked screen).
pub fn render_success_circle<D>(
    t: &mut D,
    kind: SuccessKind,
    scale_pct: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (mark, fill, mark_glyph, _, _) = success_visuals(kind);
    Rectangle::new(
        EgPoint::new(
            MIDX - SUCCESS_BOX as i32 / 2,
            SUCCESS_CY - SUCCESS_BOX as i32 / 2,
        ),
        Size::new(SUCCESS_BOX, SUCCESS_BOX),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(t)?;
    let dia = (SUCCESS_DIA * scale_pct as u32 / 100).max(4);
    Circle::new(
        EgPoint::new(MIDX - dia as i32 / 2, SUCCESS_CY - dia as i32 / 2),
        dia,
    )
    .into_styled(PrimitiveStyle::with_fill(fill))
    .draw(t)?;
    let gs = (dia * 48 / 100).max(10) as u16;
    glyph::draw(
        t,
        mark_glyph,
        Point::new(
            (MIDX - gs as i32 / 2) as u16,
            (SUCCESS_CY - gs as i32 / 2) as u16,
        ),
        gs,
        mark,
    )
}

// --- Ceremony screens (request / approve / add-passkey) --------------------

/// Left inset of the title-row leading icon (the approve shield).
const CEREMONY_ICON_X: i32 = 13;
/// Where the title text starts, after the 18px leading icon.
const CEREMONY_TITLE_X: i32 = CEREMONY_ICON_X + 18 + 8;
/// Vertical centre of the title row (matches [`title_bar`]).
const CEREMONY_TITLE_CY: i32 = STATUS_BAR_H as i32 + TITLE_BAR_H as i32 / 2;
/// The service header sits just under the chrome; the info / caution plate below it.
const CEREMONY_HEAD_TOP: i32 = CONTENT_TOP as i32 + 6;
const CEREMONY_PLATE_TOP: i32 = CONTENT_TOP as i32 + 54;
const CEREMONY_PLATE_H: u16 = 46;

/// Centred text that, when too wide to fit `clip`, falls back to left-aligned and is
/// hard-clipped at the boundary. So a short relying party stays nicely centred (the
/// design), but a long, attacker-influenced rp id can never overrun the panel and is
/// cut from one side (head readable) rather than centred with both ends hidden.
fn centered_clipped<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    cx: i32,
    y: i32,
    role: Role,
    color: Rgb565,
    clip: Rect,
) -> Result<(), D::Error> {
    let w = font::width(s, role).unwrap_or(clip.w as u32);
    if w <= clip.w as u32 {
        text(t, s, EgPoint::new(cx, y), role, color)
    } else {
        text_left_clipped(t, s, EgPoint::new(clip.x as i32, y), role, color, clip)
    }
}

/// The service header shared by the request and approve ceremonies: a rounded chip
/// with the generic relying-party globe (we ship no per-brand logos), then the
/// relying party and — when present — the account beneath it. Both untrusted fields
/// are clipped to the panel so a long rp id is cut, never overrun. Drawn from `y`
/// (the chip's top); the caller lays content out below it.
fn service_head<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    y: i32,
    rp: &Label,
    account: &Label,
) -> Result<(), D::Error> {
    let chip = Rect::new(14, y as u16, 38, 38);
    RoundedRectangle::with_equal_corners(eg_rect(chip), Size::new(9, 9))
        .into_styled(PrimitiveStyle::with_fill(theme::CHIP))
        .draw(t)?;
    glyph::draw(
        t,
        Glyph::Globe,
        Point::new(chip.x + 8, chip.y + 8),
        22,
        theme::TEXT,
    )?;
    let tx = chip.x as i32 + chip.w as i32 + 11;
    let clip = Rect::new(tx as u16, y as u16, PANEL_W - 14 - tx as u16, 38);
    if account.as_str().is_empty() {
        text_left_clipped(
            t,
            rp.as_str(),
            EgPoint::new(tx, y + 19),
            Role::Strong,
            theme::TEXT,
            clip,
        )
    } else {
        text_left_clipped(
            t,
            rp.as_str(),
            EgPoint::new(tx, y + 12),
            Role::Strong,
            theme::TEXT,
            clip,
        )?;
        text_left_clipped(
            t,
            account.as_str(),
            EgPoint::new(tx, y + 28),
            Role::Body,
            theme::GREY,
            clip,
        )
    }
}

/// A full-width info / caution plate (rounded, tinted) below the service header — the
/// "Sign in with passkey" hint on the request screen, the amber "did you start this?"
/// caution on the approve screen. Two short lines fit; the caller supplies them.
fn ceremony_plate<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    icon: Glyph,
    line1: &str,
    line2: &str,
    fill: Rgb565,
    border: Rgb565,
    text_color: Rgb565,
) -> Result<(), D::Error> {
    let plate = Rect::new(
        14,
        CEREMONY_PLATE_TOP as u16,
        PANEL_W - 28,
        CEREMONY_PLATE_H,
    );
    RoundedRectangle::with_equal_corners(eg_rect(plate), Size::new(11, 11))
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    RoundedRectangle::with_equal_corners(eg_rect(plate), Size::new(11, 11))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(border)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    glyph::draw(
        t,
        icon,
        Point::new(plate.x + 12, plate.y + 13),
        16,
        text_color,
    )?;
    let tx = plate.x as i32 + 38;
    if line2.is_empty() {
        text_left(
            t,
            line1,
            EgPoint::new(tx, plate.y as i32 + 23),
            Role::Body,
            text_color,
        )
    } else {
        text_left(
            t,
            line1,
            EgPoint::new(tx, plate.y as i32 + 16),
            Role::Body,
            text_color,
        )?;
        text_left(
            t,
            line2,
            EgPoint::new(tx, plate.y as i32 + 32),
            Role::Body,
            text_color,
        )
    }
}

/// The trusted Approve prompt: the status/title chrome with a shield + the operation
/// title, the relying-party header (chip + sanitized rp id / account), an amber "did
/// you start this?" caution, and the Deny / Hold-to-approve buttons. The hold button
/// starts empty; the firmware fills it via [`render_hold_button`] as the user holds.
/// Shared by the FIDO sign-in approve and the generic OpenPGP/PIV/OATH/OTP touch
/// policies — for those the title is the operation, and `primary` may be empty.
fn confirm<D: DrawTarget<Color = Rgb565>>(t: &mut D, p: &ConfirmPrompt) -> Result<(), D::Error> {
    t.clear(BG)?;
    status_bar(t)?;
    glyph::draw(
        t,
        Glyph::Shield,
        Point::new(CEREMONY_ICON_X as u16, (CEREMONY_TITLE_CY - 9) as u16),
        18,
        theme::ACCENT,
    )?;
    text_left(
        t,
        p.title,
        EgPoint::new(CEREMONY_TITLE_X, CEREMONY_TITLE_CY),
        Role::Heading,
        theme::TEXT,
    )?;
    // Relying-party header, only when the request carries rp text (generic confirms
    // such as an OpenPGP signature may not).
    if !p.primary.is_empty() {
        service_head(t, CEREMONY_HEAD_TOP, &p.primary, &p.secondary)?;
    }
    // Caution — a deliberate, plain-language warning against phishing.
    ceremony_plate(
        t,
        Glyph::Warn,
        "Approve only if you",
        "started this",
        theme::WARN_BG,
        theme::WARN_BORDER,
        theme::WARN,
    )?;
    // Deny is a single tap (low emphasis); Approve is a deliberate hold that fills.
    outline_button(t, DENY_RECT, "Deny", theme::DENY)?;
    render_hold_button(t, ALLOW_RECT, "Hold to approve", theme::APPROVE)
}

/// The trusted **add-passkey** prompt (the design's `makeCredential` step): a dashed
/// placeholder tile with the generic globe, the relying party + account being enrolled,
/// "Save new passkey for this account?", and Cancel / Save. Save ([`ALLOW_RECT`])
/// confirms the registration; Cancel ([`DENY_RECT`]) refuses. Standalone full-frame.
/// The untrusted rp / account are clipped to the panel (centred when they fit, else
/// left-clipped) so a long rp id cannot overrun the trusted display.
pub fn render_add_passkey<D>(t: &mut D, rp: &Label, account: &Label) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Add passkey", theme::ACCENT, false)?;
    // Placeholder tile for the (logo-less) relying party. embedded-graphics has no
    // dashed stroke, so the border is solid — the tile still reads as "new / pending".
    let tile = Rect::new((MIDX - 37) as u16, CONTENT_TOP + 16, 74, 74);
    RoundedRectangle::with_equal_corners(eg_rect(tile), Size::new(16, 16))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(theme::BORDER_CARD)
                .stroke_width(2)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    glyph::draw(
        t,
        Glyph::Globe,
        Point::new(tile.x + 18, tile.y + 18),
        38,
        theme::TEXT,
    )?;
    // Untrusted fields, clipped to the panel (with side margins) so they cannot overrun.
    let rp_y = tile.y as i32 + 90;
    let acct_y = tile.y as i32 + 110;
    centered_clipped(
        t,
        rp.as_str(),
        MIDX,
        rp_y,
        Role::Strong,
        theme::TEXT,
        Rect::new(6, (rp_y - 11) as u16, PANEL_W - 12, 22),
    )?;
    if !account.as_str().is_empty() {
        centered_clipped(
            t,
            account.as_str(),
            MIDX,
            acct_y,
            Role::Body,
            theme::GREY,
            Rect::new(6, (acct_y - 11) as u16, PANEL_W - 12, 22),
        )?;
    }
    text(
        t,
        "Save new passkey",
        EgPoint::new(MIDX, tile.y as i32 + 134),
        Role::Body,
        theme::TEXT_2,
    )?;
    text(
        t,
        "for this account?",
        EgPoint::new(MIDX, tile.y as i32 + 150),
        Role::Body,
        theme::TEXT_2,
    )?;
    outline_button(t, DENY_RECT, "Cancel", theme::DENY)?;
    button(t, ALLOW_RECT, "Save", theme::ACCENT_FILL)
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

/// A back / cancel affordance with a **visible bounded tap target**: a rounded outline
/// drawn around the whole hit `rect` (so it is obvious how large the pressable area is)
/// with a centred chevron inside. Used for every small back/cancel chevron — the title
/// bar, the chrome-less modals, the PIN pad — so they all read as real buttons rather
/// than a lone glyph. The outline tints with the action `color` (accent for a plain
/// back, the decline colour for a cancel).
fn back_button<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    color: Rgb565,
) -> Result<(), D::Error> {
    RoundedRectangle::with_equal_corners(eg_rect(rect), Size::new(9, 9))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(color)
                .stroke_width(1)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(t)?;
    glyph_centered(t, Glyph::Back, rect, 18, color)
}

/// The built-in-UV PIN pad in the new design language: a lock-marked header with a
/// low-emphasis outlined Cancel, the cyan masked entry, then the 3×4 grid of dark
/// neutral key cards — Del a backspace glyph, OK a solid green check. Each key is
/// painted in the exact [`pin_key_rect`] that [`crate::hit_pin`] maps a tap to, and
/// only masked dots — never the digits — are shown.
fn pin<D: DrawTarget<Color = Rgb565>>(t: &mut D, pad: &PinPad) -> Result<(), D::Error> {
    // Custom header (not `render_header`): the Cancel back button keeps its top-left hit
    // rect — clear of the digit grid, so a digit tap can never abandon entry. The title
    // is centred in the gap *between* that button and the Lock (not on the panel midline),
    // so a wide title like "Confirm PIN" can't slide under either.
    let lock_x = PANEL_W - 26;
    let title_cx = (PIN_CANCEL_RECT.x + PIN_CANCEL_RECT.w + lock_x) / 2;
    text(
        t,
        pad.title,
        EgPoint::new(title_cx as i32, 20),
        Role::Heading,
        FG,
    )?;
    glyph::draw(t, Glyph::Lock, Point::new(lock_x, 6), 18, theme::ACCENT)?;
    // Cancel is an outlined back button (not a wide "Cancel" word that would collide
    // with the centred title) in the decline colour, filling its PIN_CANCEL_RECT hit area.
    back_button(t, PIN_CANCEL_RECT, theme::DENY)?;
    // Entry starts masked; the reveal eye (drawn by `masked_entry`) toggles it live.
    masked_entry(t, pad.entered, pad.expected, None)?;
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
    // The caption strip below the grid: a rejection is danger-coloured (a wrong PIN /
    // mismatch is visible, never a silent re-prompt); an informational hint (tries
    // remaining / choose / re-enter) is muted so it reads as guidance, not an error.
    if let Some(caption) = pad.caption {
        let color = if caption.is_rejection() {
            theme::DANGER
        } else {
            MUTED
        };
        text(
            t,
            pin_caption_text(caption),
            EgPoint::new(MIDX, PANEL_H as i32 - 9),
            Role::Body,
            color,
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
    // "N tries remaining" up front (the unlock pad), singular at one. Indexed by the live
    // budget, which never exceeds the retry ceiling, so the table needs no alloc.
    const TRIES: [&str; 9] = [
        "0 tries remaining",
        "1 try remaining",
        "2 tries remaining",
        "3 tries remaining",
        "4 tries remaining",
        "5 tries remaining",
        "6 tries remaining",
        "7 tries remaining",
        "8 tries remaining",
    ];
    match c {
        PinCaption::WrongPin { retries_left } => {
            WRONG[(retries_left as usize).min(WRONG.len() - 1)]
        }
        PinCaption::Mismatch => "PINs don't match",
        PinCaption::TriesRemaining { left } => TRIES[(left as usize).min(TRIES.len() - 1)],
        PinCaption::ChoosePin => "Choose a PIN",
        PinCaption::Reenter => "Re-enter to confirm",
    }
}

/// Pixels: the entry row's left margin, dot diameter, dot pitch, and vertical centre. The
/// row is left-aligned (not centred) so the reveal eye has a fixed home on the right.
const ENTRY_X0: i32 = 24;
const ENTRY_DIA: u32 = 12;
const ENTRY_STEP: i32 = 16;
const ENTRY_CY: i32 = 60;
/// The most dots/digits the entry row shows before a "+" overflow marker (it fits left of
/// the eye); a longer PIN is still entered and verified in full.
const ENTRY_MAX_SHOWN: usize = 10;

/// The masked entry row plus the reveal (eye) toggle. Masked (`reveal = None`): a filled
/// accent dot per entered digit over `expected` dim placeholder outlines (the design's
/// fixed indicator), so an empty pad already shows how many digits are wanted. Revealed
/// (`reveal = Some(digits)`): the typed digits themselves, so the user can check them
/// before committing. Either way at most [`ENTRY_MAX_SHOWN`] symbols show, then a "+"; the
/// eye is always drawn at [`PIN_EYE_RECT`]. The PIN is only painted while revealed, and
/// only ever lives in the firmware's buffer — `masked_entry` is handed it transiently.
fn masked_entry<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    entered: usize,
    expected: u8,
    reveal: Option<&[u8]>,
) -> Result<(), D::Error> {
    // The reveal toggle, always present at the right of the band.
    glyph_centered(t, Glyph::Eye, PIN_EYE_RECT, 18, theme::FAINT)?;
    if let Some(digits) = reveal {
        // Build "<digits>[+]" in a small buffer (ASCII digits, device-internal → trusted).
        let shown = digits.len().min(ENTRY_MAX_SHOWN);
        let mut buf = [0u8; ENTRY_MAX_SHOWN + 1];
        buf[..shown].copy_from_slice(&digits[..shown]);
        let mut n = shown;
        if digits.len() > ENTRY_MAX_SHOWN {
            buf[n] = b'+';
            n += 1;
        }
        let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
        text_left(
            t,
            s,
            EgPoint::new(ENTRY_X0, ENTRY_CY),
            Role::Body,
            theme::TEXT_2,
        )?;
        return Ok(());
    }
    let total = (expected as usize).max(entered).min(ENTRY_MAX_SHOWN);
    for i in 0..total {
        let at = EgPoint::new(
            ENTRY_X0 + i as i32 * ENTRY_STEP,
            ENTRY_CY - ENTRY_DIA as i32 / 2,
        );
        let style = if i < entered {
            PrimitiveStyle::with_fill(theme::ACCENT)
        } else {
            PrimitiveStyle::with_stroke(theme::CAPTION, 1)
        };
        Circle::new(at, ENTRY_DIA).into_styled(style).draw(t)?;
    }
    // A PIN longer than the row marks the extra digits with a "+", so the dot count never
    // reads as the whole PIN (the full PIN is still entered and verified).
    if entered > ENTRY_MAX_SHOWN {
        let mx = ENTRY_X0 + total as i32 * ENTRY_STEP;
        text_left(
            t,
            "+",
            EgPoint::new(mx, ENTRY_CY),
            Role::Body,
            theme::CAPTION,
        )?;
    }
    Ok(())
}

/// Top and height of the masked-entry band — the strip [`render_pin_dots`] repaints
/// on its own. Must cover the dot row (centre y 60, dia 12) and the eye toggle.
const PIN_ENTRY_TOP: i32 = 44;
const PIN_ENTRY_H: u32 = 32;

/// Repaint **only** the masked-entry band (clear the strip, redraw the dots/digits and the
/// eye), leaving the static keys untouched. The pad is painted in full once via
/// `render(&Screen::Pin(..))`; each keystroke — and each reveal toggle — then calls this,
/// so a change is a tiny partial update with no full-screen clear (no flicker), unlike
/// repainting the whole 240×320 frame per tap. `reveal` matches [`masked_entry`]: `None`
/// shows masked dots, `Some(digits)` the typed digits (passed transiently by the firmware
/// when the user taps the eye — never stored here).
pub fn render_pin_dots<D>(
    target: &mut D,
    entered: usize,
    expected: u8,
    reveal: Option<&[u8]>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(
        EgPoint::new(0, PIN_ENTRY_TOP),
        Size::new(PANEL_W as u32, PIN_ENTRY_H),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(target)?;
    masked_entry(target, entered, expected, reveal)
}

/// A static caption for a pad key — no alloc: digits index a fixed table.
fn key_label(k: PinKey) -> &'static str {
    const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
    match k {
        PinKey::Digit(n) => DIGITS[(n % 10) as usize],
        PinKey::Del => "Del",
        PinKey::Ok => "OK",
        PinKey::Cancel => "Cancel",
        // Not a grid key — the eye toggle is drawn by `masked_entry`, never labelled here.
        PinKey::Reveal => "",
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
/// screen `title`. The chevron tints with the title (both `color`), per the design. The
/// title is **clipped** to the strip left of the right-edge affordance zone
/// ([`TITLE_EDIT_RECT`]): a long, user-controllable title (e.g. a device-local nickname)
/// is cut at the boundary rather than overrunning off-panel or under the edit pencil.
pub fn title_bar<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    color: Rgb565,
    back: bool,
) -> Result<(), D::Error> {
    let cy = STATUS_BAR_H as i32 + TITLE_BAR_H as i32 / 2;
    let tx = if back {
        back_button(t, TITLE_BACK_RECT, color)?;
        TITLE_BACK_RECT.x as i32 + TITLE_BACK_RECT.w as i32 + 6
    } else {
        13
    };
    let right = TITLE_EDIT_RECT.x.saturating_sub(4); // a gap before the affordance zone
    let clip = Rect::new(
        tx as u16,
        STATUS_BAR_H,
        right.saturating_sub(tx as u16),
        TITLE_BAR_H,
    );
    text_left_clipped(t, title, EgPoint::new(tx, cy), Role::Heading, color, clip)
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
        SettingsPage::Root => settings_root(t, v.version),
        SettingsPage::Brightness => settings_brightness(t, v.brightness),
        SettingsPage::Timeout => settings_timeout(t, v.timeout_secs),
        SettingsPage::Sleep => settings_sleep(t, v.sleep_secs),
        SettingsPage::Security => {
            settings_security(t, v.device_pin_set, v.fido_pin_set, v.backup_sealed)
        }
    }
}

/// The Root list: a header and the option rows, each in its `settings_row_rect` —
/// the new list look, with leading glyphs and a drill-in chevron.
fn settings_root<D: DrawTarget<Color = Rgb565>>(t: &mut D, version: u16) -> Result<(), D::Error> {
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
    // Firmware: the installed build (bcdDevice) inline, drilling into the
    // reboot-to-update-over-USB screen.
    let mut vbuf = [b'0', b'x', 0, 0, 0, 0];
    vbuf[2..].copy_from_slice(&hex_u16(version));
    render_row(
        t,
        settings_row_rect(3),
        Glyph::Cpu,
        "Firmware",
        Some((str8(&vbuf), theme::FAINT)),
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
    device_pin_set: bool,
    fido_pin_set: bool,
    backup_sealed: bool,
) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Security", theme::ACCENT, true)?;
    // Row order here must match [`crate::security_row_entry`] — the paint and the tap-dispatch
    // share `settings_row_rect(i)` but not a single table, so the danger Factory reset stays
    // last on both. Two independent PINs: the device PIN (lock glyph) gates the on-device UI;
    // the FIDO clientPIN (key glyph) is WebAuthn's. Each row sets or changes only its own.
    render_row(
        t,
        settings_row_rect(0),
        Glyph::Lock,
        if device_pin_set {
            "Change device PIN"
        } else {
            "Set device PIN"
        },
        None,
        true,
    )?;
    render_row(
        t,
        settings_row_rect(1),
        Glyph::Key,
        if fido_pin_set {
            "Change FIDO PIN"
        } else {
            "Set FIDO PIN"
        },
        None,
        true,
    )?;
    render_row(
        t,
        settings_row_rect(2),
        Glyph::Clock,
        "Audit log",
        None,
        true,
    )?;
    // The row shows the cheap export-*window* bit only ("Sealed" / "Review"); the full
    // 4-way state (no-seed / restore-only / sealed / review) lives on the Backup page, which
    // also reads `has_seed` + the build profile. The row deliberately skips that extra lookup.
    render_row(
        t,
        settings_row_rect(3),
        Glyph::Lifebuoy,
        "Backup",
        Some(if backup_sealed {
            ("Sealed", theme::OK)
        } else {
            ("Review", theme::WARN)
        }),
        true,
    )?;
    danger_row(t, settings_row_rect(4), "Factory reset")
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

/// The **Firmware** screen (Settings → Firmware): the installed build (bcdDevice) above the
/// honest update story and the device serial. This authenticator can't discover updates on
/// its own — the RS-Key host app delivers a signed image over USB, and a deliberate hold
/// reboots into the BOOTSEL bootloader so the host can flash. `secure_boot` is the device's
/// *real* OTP fuse state: only when it is set does the RP2350 boot ROM verify the image
/// signature, so the screen states the verification as fact only then — on an un-fused board
/// it warns the update is unverified instead (the trusted display must not vouch for a check
/// the silicon isn't doing, mirroring the honest Backup-status screen). Same chrome-less
/// layout / hold mechanics as the reveal / seal gates, but the hold is the blue primary
/// action; the firmware drives [`crate::DEL_HOLD_RECT`] (hold) / [`crate::PK_BACK_RECT`] (cancel).
pub fn render_firmware<D>(
    t: &mut D,
    version: u16,
    chipid: u64,
    secure_boot: bool,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Firmware",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    glyph::draw(
        t,
        Glyph::Cpu,
        Point::new(PANEL_W / 2 - 14, 48),
        28,
        theme::ACCENT,
    )?;
    text(
        t,
        "INSTALLED",
        EgPoint::new(MIDX, 96),
        Role::Mono,
        theme::CAPTION,
    )?;
    let mut vbuf = [b'0', b'x', 0, 0, 0, 0];
    vbuf[2..].copy_from_slice(&hex_u16(version));
    text(t, str8(&vbuf), EgPoint::new(MIDX, 118), Role::Heading, FG)?;
    text(
        t,
        "Updates arrive over USB.",
        EgPoint::new(MIDX, 150),
        Role::Body,
        MUTED,
    )?;
    // Only claim a signature check when secure boot is actually fused; otherwise the
    // bootloader takes any image, so say so rather than vouch for a check that isn't run.
    if secure_boot {
        text(
            t,
            "Secure boot checks the",
            EgPoint::new(MIDX, 170),
            Role::Body,
            MUTED,
        )?;
        text(
            t,
            "signature before it runs.",
            EgPoint::new(MIDX, 188),
            Role::Body,
            MUTED,
        )?;
    } else {
        text(
            t,
            "Secure boot is off —",
            EgPoint::new(MIDX, 170),
            Role::Body,
            theme::WARN,
        )?;
        text(
            t,
            "updates are NOT verified.",
            EgPoint::new(MIDX, 188),
            Role::Body,
            theme::WARN,
        )?;
    }
    let sh = hex_u64(chipid);
    text(
        t,
        str8(&sh),
        EgPoint::new(MIDX, 222),
        Role::Mono,
        theme::CAPTION,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to update", theme::ACCENT_FILL)
}

/// The brief notice painted the instant a [`render_firmware`] hold commits, before the
/// secure reboot into BOOTSEL drops the panel — it tells the user to finish the flash from
/// the host. The reboot follows within a worker tick, so this shows only momentarily.
pub fn render_rebooting<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    glyph::draw(
        t,
        Glyph::Usb,
        Point::new(PANEL_W / 2 - 16, 110),
        32,
        theme::ACCENT,
    )?;
    text(
        t,
        "Rebooting to update",
        EgPoint::new(MIDX, 176),
        Role::Strong,
        FG,
    )?;
    text(
        t,
        "Flash from the RS-Key app.",
        EgPoint::new(MIDX, 200),
        Role::Body,
        MUTED,
    )
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

/// Format a "time ago" as a compact mono token (`"now"`, `"5m"`, `"3h"`, `"2d"`, `"1w"`)
/// into `buf`. Boot-relative, so only meaningful within the current power cycle — the
/// firmware passes the elapsed seconds only for current-session entries. The numeric
/// part is always < 60, so it fits two digits.
fn fmt_ago(secs: u32, buf: &mut [u8; 8]) -> &str {
    let (n, unit) = if secs < 60 {
        return "now";
    } else if secs < 3_600 {
        (secs / 60, b'm')
    } else if secs < 86_400 {
        (secs / 3_600, b'h')
    } else if secs < 604_800 {
        (secs / 86_400, b'd')
    } else {
        (secs / 604_800, b'w')
    };
    let mut tmp = [0u8; 5];
    let num = fmt_u16(n as u16, &mut tmp);
    let len = num.len();
    buf[..len].copy_from_slice(num.as_bytes());
    buf[len] = unit;
    str8(&buf[..len + 1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HomeView, PANEL_H, SuccessKind};
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
                nick: Label::default(),
                accounts: 2,
            },
            RpRow {
                id: Label::clamp(b"google.com"),
                nick: Label::default(),
                accounts: 1,
            },
        ];
        let mut d = Rec::new();
        render_passkeys_list(&mut d, &rows, 0, 2).unwrap();
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
        render_passkeys_list(&mut d, &[], 0, 0).unwrap();
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
        render_service(&mut d, &title, &accounts, 0, 2).unwrap();
        assert!(!d.oob, "detail drew outside the panel");
        // The back chevron paints in TITLE_BACK_RECT — where hit_title_back maps a tap.
        assert!(
            has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT),
            "back chevron missing from its title-bar hit rect"
        );
        // The pencil edit affordance paints in TITLE_EDIT_RECT (the rename entry).
        assert!(
            d.any_non_bg_in(crate::TITLE_EDIT_RECT),
            "edit affordance missing from its title-bar hit rect"
        );
        for i in 0..accounts.len() as u16 {
            assert!(d.any_non_bg_in(crate::row_rect(PK_LIST_TOP, i)));
        }
    }

    #[test]
    fn service_title_clips_a_wide_nickname_in_panel() {
        // A max-length wide nickname (24 'W') must be clipped to the title strip, not
        // overrun off-panel or under the edit pencil (TITLE_EDIT_RECT).
        let accounts = [AccountRow {
            name: Label::clamp(b"alex@example.com"),
            protected: false,
        }];
        let wide = Label::clamp(&[b'W'; 24]);
        let mut d = Rec::new();
        render_service(&mut d, &wide, &accounts, 0, 1).unwrap();
        assert!(!d.oob, "wide service title drew outside the panel");
        // The pencil's region still gets its glyph (the title didn't paint over it... the
        // clip ends before it).
        assert!(d.any_non_bg_in(crate::TITLE_EDIT_RECT));
    }

    #[test]
    fn rename_screen_paints_wheel_and_save() {
        let mut d = Rec::new();
        render_rename(&mut d, "work", b'a').unwrap();
        assert!(!d.oob, "rename drew outside the panel");
        assert!(d.drew_anything());
        // The back chevron cancels; the Save button is the primary fill — both in their
        // hit rects.
        assert!(has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT));
        assert!(
            has_color(&d, crate::RN_SAVE_RECT, theme::ACCENT_FILL),
            "Save button missing from its hit rect"
        );
        // Each wheel control paints something in its own tap target.
        for r in [
            crate::RN_UP_RECT,
            crate::RN_DOWN_RECT,
            crate::RN_BKSP_RECT,
            crate::RN_INS_RECT,
        ] {
            assert!(d.any_non_bg_in(r), "wheel key {r:?} painted nothing");
        }
    }

    #[test]
    fn rename_space_candidate_stays_in_panel() {
        // The space candidate takes a different (underline) draw path — still in-bounds,
        // and an empty value (caret at the field start) must not spill either.
        let mut d = Rec::new();
        render_rename(&mut d, "", b' ').unwrap();
        assert!(!d.oob, "rename(space) drew outside the panel");
        assert!(d.drew_anything());
    }

    #[test]
    fn rename_long_value_is_clipped_to_the_field() {
        // A value far wider than the field must not paint past the panel (it is clipped).
        let long = "abcdefghijklmnopqrstuvwx";
        let mut d = Rec::new();
        render_rename(&mut d, long, b'z').unwrap();
        assert!(!d.oob, "rename(long) drew outside the panel");
    }

    #[test]
    fn passkeys_list_shows_nickname_over_rpid() {
        let rows = [RpRow {
            id: Label::clamp(b"github.com"),
            nick: Label::clamp(b"Work GitHub"),
            accounts: 2,
        }];
        let mut d = Rec::new();
        render_passkeys_list(&mut d, &rows, 0, 1).unwrap();
        assert!(!d.oob && d.drew_anything());
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

    /// Around the centred success circle — comfortably covers the mark glyph at any
    /// pop scale, well clear of the heading band below it.
    const SUCCESS_BAND: Rect = Rect::new(96, 88, 48, 52);

    /// Every success kind paints its mark in the circle, stays in-panel, and uses the
    /// design's colour (green check for approve/delete, grey rotate for the wipe).
    #[test]
    fn success_screens_fit_and_mark_their_kind() {
        for (kind, mark) in [
            (SuccessKind::Approved, theme::SUCCESS),
            (SuccessKind::Deleted, theme::SUCCESS),
            (SuccessKind::Wiped, theme::GREY),
        ] {
            let mut d = Rec::new();
            render_success(&mut d, kind, false).unwrap();
            render_success_circle(&mut d, kind, 100).unwrap();
            assert!(!d.oob, "{kind:?} success drew outside the panel");
            assert!(d.drew_anything(), "{kind:?} success drew nothing");
            assert!(
                has_color(&d, SUCCESS_BAND, mark),
                "{kind:?} success mark colour missing from the circle"
            );
        }
    }

    /// The wipe screen is deliberately grey (it restarts), never the green success
    /// check used by approve/delete — so the two read as different outcomes.
    #[test]
    fn wiped_success_is_grey_not_green() {
        let mut d = Rec::new();
        render_success(&mut d, SuccessKind::Wiped, false).unwrap();
        render_success_circle(&mut d, SuccessKind::Wiped, 100).unwrap();
        assert!(
            !has_color(&d, SUCCESS_BAND, theme::SUCCESS),
            "wipe screen must not use the green success colour"
        );
    }

    /// The wait-for-Done variant paints the primary Done button in the exact region
    /// `hit_success_done` maps a tap to.
    #[test]
    fn success_done_button_in_its_hit_rect() {
        let mut d = Rec::new();
        render_success(&mut d, SuccessKind::Deleted, true).unwrap();
        assert!(!d.oob, "success-with-Done drew outside the panel");
        assert!(
            has_color(&d, crate::DEL_HOLD_RECT, theme::ACCENT_FILL),
            "Done button not painted in its hit rect"
        );
        assert!(crate::hit_success_done(crate::Point::new(120, 270)));
        assert!(!crate::hit_success_done(crate::Point::new(0, 0)));
    }

    /// Every pop frame — including the 1.06 overshoot — stays inside the fixed circle
    /// box, so a frame never spills onto the heading below or off the panel.
    #[test]
    fn success_pop_frames_stay_in_box() {
        for pct in [40u16, 55, 85, 100, 106] {
            let mut d = Rec::new();
            render_success_circle(&mut d, SuccessKind::Approved, pct).unwrap();
            assert!(!d.oob, "pop frame {pct}% drew outside the panel");
            assert!(
                !d.any_non_bg_in(Rect::new(0, 170, PANEL_W, 60)),
                "pop frame {pct}% bled into the heading / button area"
            );
        }
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

    /// The re-skinned approve screen must stay on-panel even with the empty rp a
    /// generic OpenPGP/PIV touch confirm carries (no service header) — no panic, no OOB.
    #[test]
    fn confirm_with_empty_rp_stays_on_panel() {
        let p = ConfirmPrompt::new("Sign with key?", b"", b"");
        let mut d = Rec::new();
        render(&mut d, &Screen::Confirm(p)).unwrap();
        assert!(!d.oob, "empty-rp confirm drew outside the panel");
    }

    /// Add-passkey reuses the same band: Cancel in `DENY_RECT`, Save filled in
    /// `ALLOW_RECT`.
    #[test]
    fn add_passkey_paints_cancel_and_save_in_their_hit_rects() {
        let rp = Label::clamp(b"github.com");
        let account = Label::clamp(b"alex@example.com");
        let mut d = Rec::new();
        render_add_passkey(&mut d, &rp, &account).unwrap();
        assert!(!d.oob, "add-passkey drew outside the panel");
        assert!(
            has_color(&d, DENY_RECT, theme::DENY),
            "Cancel not in its rect"
        );
        assert!(
            has_color(&d, ALLOW_RECT, theme::ACCENT_FILL),
            "Save not in its rect"
        );
    }

    /// A long, attacker-influenced rp / account on the add-passkey screen must never
    /// overrun the trusted panel — the `centered_clipped` fallback keeps it bounded.
    #[test]
    fn add_passkey_clips_a_wide_rp_and_account() {
        let rp = Label::clamp(&[b'a'; 48]);
        let account = Label::clamp(b"login.corp.example-company.com");
        let mut d = Rec::new();
        render_add_passkey(&mut d, &rp, &account).unwrap();
        assert!(!d.oob, "wide add-passkey rp/account overran the panel");
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
        // The reveal (eye) toggle is painted in its hit rect.
        assert!(
            has_color(&d, crate::PIN_EYE_RECT, theme::FAINT),
            "reveal eye not drawn on the pad"
        );
    }

    #[test]
    fn pin_reveal_shows_digits_not_dots() {
        // The full masked-entry band (covers the dot row and the eye).
        let band = Rect::new(0, 44, PANEL_W, 32);
        // Masked: accent dots, no revealed digits.
        let mut masked = Rec::new();
        render_pin_dots(&mut masked, 4, 0, None).unwrap();
        assert!(!masked.oob);
        assert!(
            has_color(&masked, band, theme::ACCENT),
            "masked entry must show accent dots"
        );
        // Revealed: the typed digits in the secondary text colour, and no accent dots.
        let mut shown = Rec::new();
        render_pin_dots(&mut shown, 4, 0, Some(b"1234")).unwrap();
        assert!(!shown.oob);
        assert!(
            has_color(&shown, band, theme::TEXT_2),
            "revealed entry must show the typed digits"
        );
        assert!(
            !has_color(&shown, band, theme::ACCENT),
            "revealed entry must not also show masked dots"
        );
    }

    #[test]
    fn pin_long_entry_marks_overflow() {
        let band = Rect::new(0, 44, PANEL_W, 32);
        // A PIN within the row draws no overflow marker.
        let mut short = Rec::new();
        render_pin_dots(&mut short, 4, 0, None).unwrap();
        assert!(
            !has_color(&short, band, theme::CAPTION),
            "no overflow marker for a short PIN"
        );
        // A PIN longer than the row (e.g. the 63-digit CTAP max) caps the dots and marks
        // the rest with a "+" (caption colour) — and never draws outside the panel.
        let mut long = Rec::new();
        render_pin_dots(&mut long, 63, 0, None).unwrap();
        assert!(!long.oob, "a long PIN must not draw outside the panel");
        assert!(
            has_color(&long, band, theme::CAPTION),
            "overflow marker missing for a long PIN"
        );
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
        render_pin_dots(&mut d, 5, 0, None).unwrap();
        assert!(!d.oob);
        assert_eq!(
            d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3),
            key_px,
            "the static keys must survive a partial dots update"
        );
        // The band still carries dots for the new digit count.
        assert!((48..72).any(|y| (0..PANEL_W).any(|x| d.at(x, y) != BG)));
    }

    #[test]
    fn pin_placeholders_outline_the_expected_minimum() {
        let band = Rect::new(0, 48, PANEL_W, 24);
        // An empty pad expecting 6 digits already outlines them — dim placeholder rings,
        // no filled accent dot yet.
        let mut empty = Rec::new();
        render(&mut empty, &Screen::Pin(PinPad::new(0).expecting(6))).unwrap();
        assert!(!empty.oob);
        assert!(
            has_color(&empty, band, theme::CAPTION),
            "an empty pad must outline the expected digits"
        );
        assert!(
            !has_color(&empty, band, theme::ACCENT),
            "no digit entered yet, so no filled dot"
        );
        // Two of six entered: the row carries both filled (accent) and outlined (dim) dots.
        let mut some = Rec::new();
        render(&mut some, &Screen::Pin(PinPad::new(2).expecting(6))).unwrap();
        assert!(has_color(&some, band, theme::ACCENT), "entered digits fill");
        assert!(
            has_color(&some, band, theme::CAPTION),
            "the remaining placeholders stay outlined"
        );
    }

    #[test]
    fn pin_info_caption_paints_muted_not_danger() {
        // The strip under the grid (grid bottom is y300; the caption sits in 301..320).
        let strip = Rect::new(0, 301, PANEL_W, PANEL_H - 301);
        for hint in [
            PinCaption::TriesRemaining { left: 7 },
            PinCaption::ChoosePin,
            PinCaption::Reenter,
        ] {
            let mut d = Rec::new();
            render(
                &mut d,
                &Screen::Pin(PinPad::with_caption(0, "Enter PIN", Some(hint))),
            )
            .unwrap();
            assert!(!d.oob);
            assert!(
                has_color(&d, strip, MUTED),
                "an informational hint must paint muted"
            );
            assert!(
                !has_color(&d, strip, theme::DANGER),
                "an informational hint must not use the danger colour"
            );
        }
    }

    fn view(page: SettingsPage) -> SettingsView {
        SettingsView {
            page,
            brightness: 3,
            timeout_secs: 30,
            sleep_secs: 60,
            version: 0x078A,
            chipid: 0x0123_4567_89ab_cdef,
            device_pin_set: true,
            fido_pin_set: true,
            backup_sealed: true,
        }
    }

    #[test]
    fn every_settings_page_fits_and_draws() {
        for page in [
            SettingsPage::Root,
            SettingsPage::Brightness,
            SettingsPage::Timeout,
            SettingsPage::Sleep,
            SettingsPage::Security,
        ] {
            let mut d = Rec::new();
            render(&mut d, &Screen::Settings(view(page))).unwrap();
            assert!(!d.oob, "settings {page:?} drew outside the panel");
            assert!(d.drew_anything(), "settings {page:?} drew nothing");
        }
    }

    #[test]
    fn firmware_screen_fits_and_draws() {
        // The Firmware screen is a hold sub-flow (rendered directly, not via the settings
        // dispatch); it must paint its version + serial + hold button inside the panel under
        // both secure-boot states (the copy branches on the real fuse).
        for secure_boot in [true, false] {
            let mut d = Rec::new();
            render_firmware(&mut d, 0x07B6, 0x8e0f_f6ae_ae0b_c470, secure_boot).unwrap();
            assert!(
                !d.oob,
                "firmware screen (sb={secure_boot}) drew outside the panel"
            );
            assert!(
                d.drew_anything(),
                "firmware screen (sb={secure_boot}) drew nothing"
            );
        }
        // The notice shown the instant the hold commits must also fit.
        let mut n = Rec::new();
        render_rebooting(&mut n).unwrap();
        assert!(!n.oob, "rebooting notice drew outside the panel");
        assert!(n.drew_anything(), "rebooting notice drew nothing");
    }

    #[test]
    fn security_page_paints_every_row_under_either_pin_state() {
        for pin_set in [false, true] {
            let mut v = view(SettingsPage::Security);
            v.device_pin_set = pin_set;
            v.fido_pin_set = !pin_set;
            let mut d = Rec::new();
            render(&mut d, &Screen::Settings(v)).unwrap();
            assert!(
                !d.oob,
                "security (pin_set={pin_set}) drew outside the panel"
            );
            // Every Security row (Device PIN, FIDO PIN, Audit log, Backup, Factory reset) is
            // painted in the rect `hit_security` maps its tap to.
            for i in 0..crate::SECURITY_ROWS {
                assert!(
                    d.any_non_bg_in(settings_row_rect(i)),
                    "security row {i} unpainted (pin_set={pin_set})"
                );
            }
        }
    }

    #[test]
    fn backup_screen_paints_every_state_inside_the_panel() {
        // (sealed, has_seed, exportable, can_reveal): the status states plus the
        // window-open state that shows the on-device action buttons.
        let states = [
            BackupView {
                sealed: false,
                has_seed: true,
                exportable: true,
                can_reveal: true,
            },
            BackupView {
                sealed: true,
                has_seed: true,
                exportable: true,
                can_reveal: false,
            },
            BackupView {
                sealed: false,
                has_seed: false,
                exportable: true,
                can_reveal: false,
            },
            BackupView {
                sealed: true,
                has_seed: true,
                exportable: false,
                can_reveal: false,
            },
        ];
        for v in states {
            let mut d = Rec::new();
            render_backup(&mut d, &v).unwrap();
            assert!(!d.oob, "backup {v:?} drew outside the panel");
            assert!(d.drew_anything(), "backup {v:?} painted nothing");
            // When the actions are offered, both buttons are painted in their hit rects.
            if v.can_reveal {
                assert!(
                    d.any_non_bg_in(crate::BACKUP_REVEAL_RECT),
                    "reveal button unpainted"
                );
                assert!(
                    d.any_non_bg_in(crate::BACKUP_SEAL_RECT),
                    "seal button unpainted"
                );
            }
        }
    }

    #[test]
    fn seed_phrase_and_gates_paint_inside_the_panel() {
        // A full 24-word phrase, both pages, plus the reveal/seal gate screens.
        let words: [&str; 24] = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "zoo", "zone", "zero", "youth", "yellow",
            "wrist", "write", "wrong", "yard", "year", "wealth", "weapon",
        ];
        for page in 0..2u16 {
            let mut d = Rec::new();
            render_seed_phrase(&mut d, &words, page, 2).unwrap();
            assert!(!d.oob, "seed phrase page {page} drew outside the panel");
            assert!(d.drew_anything(), "seed phrase page {page} painted nothing");
        }
        for kind in [RevealKind::Phrase, RevealKind::Shares] {
            let mut d = Rec::new();
            render_reveal_warning(&mut d, kind).unwrap();
            assert!(!d.oob && d.drew_anything());
        }
        let mut d = Rec::new();
        render_seal_confirm(&mut d).unwrap();
        assert!(!d.oob && d.drew_anything());

        // The recovery-format chooser, the SLIP-39 share picker, and a share page must all
        // paint inside the panel.
        let mut d = Rec::new();
        render_backup_format(&mut d).unwrap();
        assert!(
            !d.oob && d.drew_anything(),
            "format chooser drew outside the panel"
        );
        let mut d = Rec::new();
        render_share_picker(&mut d, 2, 3).unwrap();
        assert!(
            !d.oob && d.drew_anything(),
            "share picker drew outside the panel"
        );
        let share: [&str; 33] = ["academic"; 33];
        for page in 0..3u16 {
            let mut d = Rec::new();
            render_slip39_share(&mut d, &share, 1, 3, page, 3).unwrap();
            assert!(!d.oob, "share page {page} drew outside the panel");
            assert!(d.drew_anything(), "share page {page} painted nothing");
        }
    }

    #[test]
    fn audit_log_paints_rows_with_kind_coloured_dots() {
        let rows = [
            AuditRow {
                kind: AuditKind::Login,
                secs_ago: Some(120),
            },
            AuditRow {
                kind: AuditKind::Register,
                secs_ago: Some(3600),
            },
            AuditRow {
                kind: AuditKind::Denied,
                secs_ago: None,
            },
        ];
        let mut d = Rec::new();
        render_audit_log(&mut d, &rows, 0, 3).unwrap();
        assert!(!d.oob, "audit log drew outside the panel");
        // Each row's status dot is painted in its kind colour, inside its row rect.
        for (i, c) in [theme::SUCCESS, theme::ACCENT, theme::DANGER]
            .into_iter()
            .enumerate()
        {
            assert!(
                has_color(&d, crate::row_rect(crate::PK_LIST_TOP, i as u16), c),
                "row {i} status-dot colour missing"
            );
        }
    }

    #[test]
    fn audit_log_empty_shows_placeholder_and_no_rows() {
        let mut d = Rec::new();
        render_audit_log(&mut d, &[], 0, 0).unwrap();
        assert!(!d.oob, "empty audit log drew outside the panel");
        assert!(d.drew_anything(), "empty audit log drew nothing");
        // No row card is painted when there are no events.
        assert!(
            !d.any_non_bg_in(crate::row_rect(crate::PK_LIST_TOP, 0)),
            "empty audit log painted a row card"
        );
    }

    #[test]
    fn multi_page_list_shows_pager_in_its_hit_rects() {
        // A full page of a 3-page list (13 events): mid-list, so both arrows are active.
        let rows = [AuditRow {
            kind: AuditKind::Login,
            secs_ago: Some(60),
        }; crate::PK_ROWS_MAX];
        let mut d = Rec::new();
        render_audit_log(&mut d, &rows, 1, 13).unwrap();
        assert!(!d.oob, "paged audit log drew outside the panel");
        assert!(
            has_color(&d, crate::PAGER_PREV_RECT, theme::ACCENT),
            "prev arrow missing from its hit rect"
        );
        assert!(
            has_color(&d, crate::PAGER_NEXT_RECT, theme::ACCENT),
            "next arrow missing from its hit rect"
        );
    }

    #[test]
    fn pager_dims_the_unavailable_end_arrow() {
        let rows = [AuditRow {
            kind: AuditKind::Login,
            secs_ago: Some(60),
        }; crate::PK_ROWS_MAX];
        // First page of 3: prev is dimmed, next is active.
        let mut d = Rec::new();
        render_audit_log(&mut d, &rows, 0, 13).unwrap();
        assert!(
            has_color(&d, crate::PAGER_PREV_RECT, theme::CAPTION),
            "prev not dimmed on the first page"
        );
        assert!(
            has_color(&d, crate::PAGER_NEXT_RECT, theme::ACCENT),
            "next not active on the first page"
        );
        // Last page (2 of 3): next is dimmed.
        let mut d2 = Rec::new();
        render_audit_log(&mut d2, &rows[..3], 2, 13).unwrap();
        assert!(
            has_color(&d2, crate::PAGER_NEXT_RECT, theme::CAPTION),
            "next not dimmed on the last page"
        );
    }

    #[test]
    fn single_page_list_shows_footer_not_pager() {
        let rows = [AuditRow {
            kind: AuditKind::Login,
            secs_ago: Some(60),
        }; 3];
        let mut d = Rec::new();
        render_audit_log(&mut d, &rows, 0, 3).unwrap();
        // One page → no pager: the prev-arrow region (left, clear of the right-aligned
        // item-count footer) stays background.
        assert!(
            !d.any_non_bg_in(crate::PAGER_PREV_RECT),
            "single-page list painted a pager arrow"
        );
    }

    #[test]
    fn fmt_ago_buckets_units() {
        let mut b = [0u8; 8];
        assert_eq!(fmt_ago(0, &mut b), "now");
        assert_eq!(fmt_ago(59, &mut b), "now");
        assert_eq!(fmt_ago(60, &mut b), "1m");
        assert_eq!(fmt_ago(125, &mut b), "2m");
        assert_eq!(fmt_ago(3_600, &mut b), "1h");
        assert_eq!(fmt_ago(86_400, &mut b), "1d");
        assert_eq!(fmt_ago(6 * 86_400, &mut b), "6d");
        assert_eq!(fmt_ago(604_800, &mut b), "1w");
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
