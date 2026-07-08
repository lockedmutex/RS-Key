// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Passkey screens: the RP list, service detail, rename, and the delete confirm.

use super::*;

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
        group_card(t, PK_LIST_TOP, rows.len() as u16)?;
        for (i, r) in rows.iter().enumerate() {
            let mut buf = [0u8; 16];
            let unit = if r.accounts == 1 {
                "account"
            } else {
                "accounts"
            };
            let trailing = fmt_count(r.accounts as u16, unit, &mut buf);
            let name = r.shown();
            row_body(
                t,
                crate::row_rect(PK_LIST_TOP, i as u16),
                service_glyph(name),
                name,
                Some((trailing, MUTED)),
                true,
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
    group_card(t, PK_LIST_TOP, accounts.len() as u16)?;
    for (i, a) in accounts.iter().enumerate() {
        let trailing = if a.protected {
            Some(("UV", theme::ACCENT))
        } else {
            None
        };
        row_body(
            t,
            crate::row_rect(PK_LIST_TOP, i as u16),
            Glyph::Key,
            a.name.as_str(),
            trailing,
            false,
            true,
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
/// (`b' '` shows as an underscore so a space is visible). The firmware blinks the caret by
/// repainting [`render_rename_caret`] on a timer.
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

/// Repaint just the rename field's caret — drawn in accent when `on`, erased to the field
/// surface when `off`, so the firmware can blink it on a timer without redrawing the
/// screen. The caret sits at the end of `value` (clamped inside the field), matching
/// [`render_rename`]'s static caret exactly.
pub fn render_rename_caret<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    value: &str,
    on: bool,
) -> Result<(), D::Error> {
    let field = RN_FIELD_RECT;
    let text_w = font::width(value, Role::Body).unwrap_or(0) as i32;
    let caret_x = (field.x as i32 + 10 + text_w).min(field.x as i32 + field.w as i32 - 6);
    let color = if on { theme::ACCENT } else { theme::SURFACE };
    Line::new(
        EgPoint::new(caret_x, field.y as i32 + 7),
        EgPoint::new(caret_x, field.y as i32 + field.h as i32 - 7),
    )
    .into_styled(PrimitiveStyle::with_stroke(color, 1))
    .draw(t)
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
    // Clip + ellipsize the untrusted rp/account to the card, marking any truncation —
    // an anti-phishing screen must never show a silently-cut look-alike identity
    // (matches the getAssertion-approve and add-passkey ceremonies).
    let clip = Rect::new(tx as u16, card.y, (card.x + card.w) - tx as u16, card.h);
    // The rp is attacker-chosen: head-ellipsize (leading "…") so the registrable-domain
    // suffix stays on screen and a padded look-alike can't hide the real domain behind
    // the cut on the very screen meant to expose it (matches the getAssertion ceremony).
    text_right_ellipsized(
        t,
        rp.as_str(),
        EgPoint::new(tx, card.y as i32 + 16),
        Role::Body,
        theme::TEXT,
        clip,
        rp.truncated,
    )?;
    text_left_ellipsized(
        t,
        account.as_str(),
        EgPoint::new(tx, card.y as i32 + 32),
        Role::Body,
        theme::MUTED,
        clip,
        account.truncated,
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
    render_hold_button(t, DEL_HOLD_RECT, "Hold to delete", theme::DANGER_FILL)
}
