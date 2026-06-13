// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Styles, colors, and status glyphs for rsk-tui.
//!
//! Colors are conservative named ANSI colors so they read on both dark and
//! light terminals; the selection highlight uses REVERSED rather than a
//! hardcoded fg/bg pair so it adapts to the user's palette. Glyphs degrade to
//! ASCII when the locale is not UTF-8 (or `RSK_TUI_ASCII` is set), so the UI is
//! never garbled on a legacy terminal.

use ratatui::style::{Color, Modifier, Style};

use crate::model::{Health, LogLevel};

#[derive(Clone, Copy)]
pub struct Theme {
    pub ascii: bool,
}

impl Theme {
    /// Pick the glyph set from the environment. UTF-8 unless we have positive
    /// evidence otherwise.
    pub fn detect() -> Self {
        if std::env::var_os("RSK_TUI_ASCII").is_some() {
            return Theme { ascii: true };
        }
        let locales = ["LC_ALL", "LC_CTYPE", "LANG"];
        let any_set = locales.iter().any(|k| std::env::var_os(k).is_some());
        let utf8 = locales
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .any(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("utf-8") || v.contains("utf8")
            });
        // If a locale is set and it is not UTF-8, fall back to ASCII; if nothing
        // is set at all, assume a modern UTF-8 terminal.
        Theme {
            ascii: any_set && !utf8,
        }
    }

    /// The status dot for a health level.
    pub fn dot(&self, h: Health) -> &'static str {
        if self.ascii {
            match h {
                Health::Ok => "[+]",
                Health::Warn => "[!]",
                Health::Error => "[x]",
                Health::Unknown => "[?]",
                Health::NotApplicable => "[-]",
            }
        } else {
            match h {
                Health::Ok => "●",
                Health::Warn => "▲",
                Health::Error => "✖",
                Health::Unknown => "○",
                Health::NotApplicable => "–",
            }
        }
    }

    pub fn arrow(&self) -> &'static str {
        if self.ascii { "> " } else { "▶ " }
    }

    pub fn color(&self, h: Health) -> Color {
        match h {
            Health::Ok => Color::Green,
            Health::Warn => Color::Yellow,
            Health::Error => Color::Red,
            Health::Unknown => Color::DarkGray,
            Health::NotApplicable => Color::DarkGray,
        }
    }

    pub fn health_style(&self, h: Health) -> Style {
        Style::default().fg(self.color(h))
    }

    pub fn log_style(&self, level: LogLevel) -> Style {
        let c = match level {
            LogLevel::Info => Color::Gray,
            LogLevel::Good => Color::Green,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Error => Color::Red,
        };
        Style::default().fg(c)
    }
}

/// The accent used for titles and the active section.
pub const ACCENT: Color = Color::Cyan;

/// Selection highlight — REVERSED so it adapts to the terminal palette.
pub fn selection() -> Style {
    Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

pub fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

pub fn warn() -> Style {
    Style::default().fg(Color::Yellow)
}

pub fn danger() -> Style {
    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
}
