// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::device::MockProvider;

fn app() -> App {
    App::new(
        Box::new(MockProvider::new()),
        Theme {
            ascii: true,
            depth: crate::theme::Depth::Basic,
        },
    )
}

#[test]
fn section_cycling_wraps() {
    let mut a = app();
    assert_eq!(a.section, Section::Overview);
    a.prev_section();
    assert_eq!(a.section, Section::Help);
    a.next_section();
    assert_eq!(a.section, Section::Overview);
}

#[test]
fn menu_selection_wraps_and_resets_on_section_change() {
    let mut a = app();
    a.set_section(Section::Backup);
    assert_eq!(a.menu_sel, 0);
    let n = a.menu().len();
    assert!(n >= 3);
    a.move_menu(-1);
    assert_eq!(a.menu_sel, n - 1);
    a.move_menu(1);
    assert_eq!(a.menu_sel, 0);
    a.set_section(Section::Led);
    assert_eq!(a.menu_sel, 0);
}

#[test]
fn finalize_requires_typed_seal() {
    let mut a = app();
    let flow = a.begin_action(Action::BackupFinalize);
    assert_eq!(flow, Flow::Continue);
    // Wrong text cancels, does not run.
    if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut a.mode {
        *buf = "seal".into(); // lowercase ≠ SEAL
    } else {
        panic!("expected confirm modal");
    }
    assert_eq!(a.submit_modal(), Flow::Continue);
    assert!(matches!(a.mode, AppMode::Normal));

    // Correct text runs it.
    a.begin_action(Action::BackupFinalize);
    if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut a.mode {
        *buf = "SEAL".into();
    } else {
        panic!("expected confirm modal");
    }
    assert_eq!(a.submit_modal(), Flow::Run(Action::BackupFinalize));
}

#[test]
fn export_flow_confirm_then_pin_then_run() {
    let mut a = app(); // mock has client_pin = true
    assert_eq!(a.begin_action(Action::BackupExport), Flow::Continue);
    // Typed EXPORT confirmation.
    if let AppMode::Modal(Modal::Confirm { buf, want, .. }) = &mut a.mode {
        assert_eq!(*want, "EXPORT");
        *buf = "EXPORT".into();
    } else {
        panic!("expected EXPORT confirm");
    }
    // → opens a masked PIN input.
    assert_eq!(a.submit_modal(), Flow::Continue);
    match &mut a.mode {
        AppMode::Modal(Modal::Input { mask, buf, .. }) => {
            assert!(*mask);
            *buf = "1234".into();
        }
        _ => panic!("expected PIN input"),
    }
    // → runs the export with the staged PIN.
    assert_eq!(a.submit_modal(), Flow::Run(Action::BackupExport));
    assert_eq!(a.staging.pin.as_deref().map(String::as_str), Some("1234"));
}

#[test]
fn export_without_pin_skips_straight_to_run() {
    let mut a = app();
    a.snapshot.fido.client_pin = Some(false);
    a.begin_action(Action::BackupExport);
    if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut a.mode {
        *buf = "EXPORT".into();
    } else {
        panic!("expected confirm");
    }
    assert_eq!(a.submit_modal(), Flow::Run(Action::BackupExport));
}

#[test]
fn verify_gates_pin_through_the_chokepoint() {
    let mut a = app(); // mock has client_pin = true
    // A directly-gated action (no typed confirm first) opens the masked PIN.
    assert_eq!(a.begin_action(Action::Verify), Flow::Continue);
    match &mut a.mode {
        AppMode::Modal(Modal::Input { mask, buf, .. }) => {
            assert!(*mask);
            *buf = "1234".into();
        }
        _ => panic!("expected PIN input"),
    }
    // The single PinThenRun continuation routes back to the right action.
    assert_eq!(a.submit_modal(), Flow::Run(Action::Verify));
    assert_eq!(a.staging.pin.as_deref().map(String::as_str), Some("1234"));
}

#[test]
fn verify_without_pin_runs_directly() {
    let mut a = app();
    a.snapshot.fido.client_pin = Some(false);
    // No clientPIN → the chokepoint runs the action with no prompt.
    assert_eq!(a.begin_action(Action::Verify), Flow::Run(Action::Verify));
    assert!(matches!(a.mode, AppMode::Normal));
}

#[test]
fn reboot_bootsel_needs_typed_confirmation() {
    let mut a = app();
    a.begin_action(Action::RebootBootsel);
    match &mut a.mode {
        AppMode::Modal(Modal::Confirm { want, buf, .. }) => {
            assert_eq!(*want, "BOOTSEL");
            *buf = "BOOTSEL".into();
        }
        _ => panic!("expected BOOTSEL confirm"),
    }
    assert_eq!(a.submit_modal(), Flow::Run(Action::RebootBootsel));
}

#[test]
fn cancel_zeroizes_and_returns_to_normal() {
    let mut a = app();
    a.begin_action(Action::BackupRestore);
    if let AppMode::Modal(Modal::Input { buf, .. }) = &mut a.mode {
        *buf = "secret words".into();
    }
    a.cancel_modal();
    assert!(matches!(a.mode, AppMode::Normal));
    assert!(a.staging.phrase.is_none());
}

#[test]
fn search_filters_actions() {
    let all = App::search_results("");
    assert_eq!(all.len(), Action::ALL.len());
    let led = App::search_results("led");
    assert!(
        led.iter()
            .all(|a| a.label().to_ascii_lowercase().contains("led"))
    );
    assert!(!led.is_empty());
    assert!(App::search_results("zzz-no-match").is_empty());
}
