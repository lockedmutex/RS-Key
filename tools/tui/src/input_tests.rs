// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

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
