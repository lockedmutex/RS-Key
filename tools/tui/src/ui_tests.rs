// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::device::MockProvider;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn buffer_text(app: &App, w: u16, h: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| render(f, app)).unwrap();
    let buf = term.backend().buffer().clone();
    buf.content().iter().map(|c| c.symbol()).collect()
}

fn demo_app() -> App {
    App::new(Box::new(MockProvider::new()), Theme { ascii: true })
}

#[test]
fn renders_demo_overview() {
    let app = demo_app();
    let text = buffer_text(&app, 100, 40);
    assert!(text.contains("rs-key"));
    assert!(text.contains("Overview"));
    assert!(text.contains("DEMO"));
    assert!(text.contains("firmware"));
}

#[test]
fn renders_at_tiny_size_without_panicking() {
    // Below the log / 2-line-status thresholds — must still paint.
    let app = demo_app();
    for (w, h) in [(40, 8), (24, 6), (10, 3), (80, 1)] {
        let _ = buffer_text(&app, w, h);
    }
}

#[test]
fn modal_and_search_paint_at_tiny_size() {
    // A Message modal / Search overlay on a terminal shorter than the modal's
    // preferred height must not panic (regression: clamp(min, max<min)).
    let mut app = demo_app();
    app.open_message("t".into(), "a\nb\nc\nd\ne\nf".into(), LogLevel::Warn);
    for (w, h) in [(40, 4), (20, 3), (60, 2)] {
        let _ = buffer_text(&app, w, h);
    }
    app.open_search();
    for (w, h) in [(40, 4), (20, 3)] {
        let _ = buffer_text(&app, w, h);
    }
}

#[test]
fn reveal_modal_shows_seed_but_log_does_not() {
    let mut app = demo_app();
    // Drive export: confirm EXPORT, enter a PIN, run.
    app.begin_action(Action::BackupExport);
    if let AppMode::Modal(Modal::Confirm { buf, .. }) = &mut app.mode {
        *buf = "EXPORT".into();
    }
    app.submit_modal();
    if let AppMode::Modal(Modal::Input { buf, .. }) = &mut app.mode {
        *buf = "1234".into();
    }
    let _ = app.submit_modal(); // returns Run(BackupExport)
    let input = std::mem::take(&mut app.staging);
    let result = app.provider.run(Action::BackupExport, &input);
    drop(input);
    if let ActionResult::Reveal { title, body } = result {
        let words = body.to_string();
        app.open_reveal(title, body);
        app.log(LogLevel::Good, "seed exported — on screen, not logged");
        // The reveal modal renders the mnemonic…
        let screen = buffer_text(&app, 100, 40);
        assert!(screen.contains(words.split(' ').next().unwrap()));
        // …but no log entry ever contains any of it.
        for w in words.split(' ') {
            for entry in app.log.iter() {
                assert!(!entry.text.contains(w), "log leaked seed word {w}");
            }
        }
    } else {
        panic!("expected a reveal");
    }
}
