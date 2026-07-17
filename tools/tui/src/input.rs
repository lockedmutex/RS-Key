// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Key handling — translates a `KeyEvent` (given the current mode) into a state
//! change plus a [`Flow`] for the event loop. No device I/O, no rendering, so
//! the navigation can be driven by synthetic key events in tests.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{App, AppMode, Flow, Modal};
use crate::model::{LogLevel, Section};

pub fn handle_key(app: &mut App, key: KeyEvent) -> Flow {
    if key.kind != KeyEventKind::Press {
        return Flow::Continue;
    }
    // Raw mode swallows SIGINT — Ctrl-C arrives as a plain key. Quit cleanly,
    // wiping anything in flight first.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.cancel_modal();
        app.should_quit = true;
        return Flow::Continue;
    }

    enum Kind {
        Normal,
        Text,
        YesNo,
        Dismiss,
        Message,
        Search,
    }
    let kind = match &app.mode {
        AppMode::Normal => Kind::Normal,
        AppMode::Search(_) => Kind::Search,
        AppMode::Modal(Modal::Input { .. }) | AppMode::Modal(Modal::Confirm { .. }) => Kind::Text,
        AppMode::Modal(Modal::YesNo { .. }) => Kind::YesNo,
        // A Message modal scrolls (long audit output); Reveal dismisses on any key
        // so a shoulder-surfed secret clears fast.
        AppMode::Modal(Modal::Message { .. }) => Kind::Message,
        AppMode::Modal(_) => Kind::Dismiss,
    };

    match kind {
        Kind::Normal => normal(app, key),
        Kind::Text => text(app, key),
        Kind::YesNo => yesno(app, key),
        Kind::Dismiss => dismiss(app, key),
        Kind::Message => message(app, key),
        Kind::Search => search(app, key),
    }
}

fn normal(app: &mut App, key: KeyEvent) -> Flow {
    match key.code {
        KeyCode::Char('q') => {
            app.should_quit = true;
            Flow::Continue
        }
        KeyCode::Char('r') => app.begin_action(crate::model::Action::Refresh),
        KeyCode::Tab | KeyCode::Right => {
            app.next_section();
            Flow::Continue
        }
        KeyCode::BackTab | KeyCode::Left => {
            app.prev_section();
            Flow::Continue
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.move_menu(1);
            Flow::Continue
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.move_menu(-1);
            Flow::Continue
        }
        KeyCode::Enter => app.activate_menu(),
        KeyCode::Char('?') => {
            app.set_section(Section::Help);
            Flow::Continue
        }
        KeyCode::Char('/') => {
            app.open_search();
            Flow::Continue
        }
        _ => Flow::Continue,
    }
}

/// Free-text or masked-PIN editing (Input / Confirm modals).
fn text(app: &mut App, key: KeyEvent) -> Flow {
    match key.code {
        KeyCode::Esc => {
            app.cancel_modal();
            app.set_status(LogLevel::Info, "cancelled");
            return Flow::Continue;
        }
        KeyCode::Enter => return app.submit_modal(),
        _ => {}
    }
    if let AppMode::Modal(Modal::Input { buf, .. }) | AppMode::Modal(Modal::Confirm { buf, .. }) =
        &mut app.mode
    {
        match key.code {
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => buf.push(c),
            _ => {}
        }
    }
    Flow::Continue
}

fn yesno(app: &mut App, key: KeyEvent) -> Flow {
    match key.code {
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => app.submit_modal(),
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.cancel_modal();
            app.set_status(LogLevel::Info, "cancelled");
            Flow::Continue
        }
        _ => Flow::Continue,
    }
}

/// Reveal modal: any key dismisses (Enter routes through submit so a revealed
/// secret is zeroized).
fn dismiss(app: &mut App, key: KeyEvent) -> Flow {
    if key.code == KeyCode::Esc {
        app.cancel_modal();
        Flow::Continue
    } else {
        app.submit_modal()
    }
}

/// Message modal (audit journal, LED state, verify report): arrows / j / k /
/// PageUp / PageDown / Home / End scroll long output; Enter, Esc, q, or Space
/// close it.
fn message(app: &mut App, key: KeyEvent) -> Flow {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.scroll_message(-1),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_message(1),
        KeyCode::PageUp => app.scroll_message(-10),
        KeyCode::PageDown => app.scroll_message(10),
        KeyCode::Home => app.scroll_message(-i32::MAX / 2),
        KeyCode::End => app.scroll_message(i32::MAX / 2),
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char(' ') => {
            app.cancel_modal()
        }
        _ => {}
    }
    Flow::Continue
}

fn search(app: &mut App, key: KeyEvent) -> Flow {
    match key.code {
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
            Flow::Continue
        }
        KeyCode::Enter => {
            let chosen = if let AppMode::Search(s) = &app.mode {
                App::search_results(&s.query).get(s.sel).copied()
            } else {
                None
            };
            app.mode = AppMode::Normal;
            match chosen {
                Some(a) => {
                    app.set_section(a.section());
                    app.begin_action(a)
                }
                None => Flow::Continue,
            }
        }
        KeyCode::Up => {
            if let AppMode::Search(s) = &mut app.mode {
                s.sel = s.sel.saturating_sub(1);
            }
            Flow::Continue
        }
        KeyCode::Down => {
            if let AppMode::Search(s) = &mut app.mode {
                let n = App::search_results(&s.query).len();
                if n > 0 {
                    s.sel = (s.sel + 1).min(n - 1);
                }
            }
            Flow::Continue
        }
        KeyCode::Backspace => {
            if let AppMode::Search(s) = &mut app.mode {
                s.query.pop();
                s.sel = 0;
            }
            Flow::Continue
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let AppMode::Search(s) = &mut app.mode {
                s.query.push(c);
                s.sel = 0;
            }
            Flow::Continue
        }
        _ => Flow::Continue,
    }
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
