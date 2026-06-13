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
        Search,
    }
    let kind = match &app.mode {
        AppMode::Normal => Kind::Normal,
        AppMode::Search(_) => Kind::Search,
        AppMode::Modal(Modal::Input { .. }) | AppMode::Modal(Modal::Confirm { .. }) => Kind::Text,
        AppMode::Modal(Modal::YesNo { .. }) => Kind::YesNo,
        AppMode::Modal(_) => Kind::Dismiss,
    };

    match kind {
        Kind::Normal => normal(app, key),
        Kind::Text => text(app, key),
        Kind::YesNo => yesno(app, key),
        Kind::Dismiss => dismiss(app, key),
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

/// Reveal / Message modals: any key dismisses (Enter routes through submit so a
/// revealed secret is zeroized).
fn dismiss(app: &mut App, key: KeyEvent) -> Flow {
    if key.code == KeyCode::Esc {
        app.cancel_modal();
        Flow::Continue
    } else {
        app.submit_modal()
    }
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
mod tests {
    use super::*;
    use crate::device::MockProvider;
    use crate::model::Action;
    use crate::theme::Theme;

    fn app() -> App {
        App::new(Box::new(MockProvider::new()), Theme { ascii: true })
    }
    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn q_quits() {
        let mut a = app();
        handle_key(&mut a, press(KeyCode::Char('q')));
        assert!(a.should_quit);
    }

    #[test]
    fn ctrl_c_quits_from_any_mode() {
        let mut a = app();
        a.begin_action(Action::BackupRestore); // opens an Input modal
        handle_key(
            &mut a,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );
        assert!(a.should_quit);
        assert!(matches!(a.mode, AppMode::Normal));
    }

    #[test]
    fn tab_cycles_sections() {
        let mut a = app();
        assert_eq!(a.section, Section::Overview);
        handle_key(&mut a, press(KeyCode::Tab));
        assert_eq!(a.section, Section::Fido);
        handle_key(&mut a, press(KeyCode::BackTab));
        assert_eq!(a.section, Section::Overview);
    }

    #[test]
    fn enter_on_led_section_runs_led_get() {
        let mut a = app();
        a.set_section(Section::Led);
        let flow = handle_key(&mut a, press(KeyCode::Enter));
        assert_eq!(flow, Flow::Run(Action::LedGet));
    }

    #[test]
    fn question_mark_jumps_to_help() {
        let mut a = app();
        handle_key(&mut a, press(KeyCode::Char('?')));
        assert_eq!(a.section, Section::Help);
    }

    #[test]
    fn slash_opens_search_and_typing_filters() {
        let mut a = app();
        handle_key(&mut a, press(KeyCode::Char('/')));
        assert!(matches!(a.mode, AppMode::Search(_)));
        for c in "led".chars() {
            handle_key(&mut a, press(KeyCode::Char(c)));
        }
        let flow = handle_key(&mut a, press(KeyCode::Enter));
        // First "led" match is "LED · read state" → LedGet, in the LED section.
        assert_eq!(flow, Flow::Run(Action::LedGet));
        assert_eq!(a.section, Section::Led);
    }
}
