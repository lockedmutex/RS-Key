// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Styles, colors, and status glyphs for rsk-tui.
//!
//! Two independent capabilities are detected from the environment:
//!
//! * **glyphs** — UTF-8 unless we have positive evidence otherwise (or
//!   `RSK_TUI_ASCII`); ASCII fallback keeps the UI legible on a legacy terminal.
//! * **colour depth** — a curated brand palette (rust / teal / sage) is used on
//!   truecolor and 256-colour terminals; on a bare 16-colour terminal we fall
//!   back to named ANSI colours that adapt to the user's palette, and the
//!   selection highlight falls back to `REVERSED`. Override with
//!   `RSK_TUI_TRUECOLOR=1|0`.
//!
//! Because the curated colours are fixed RGB, a truecolor render is
//! reproducible — the docs mockup and a real screenshot line up.

use ratatui::style::{Color, Modifier, Style};

use crate::model::{Health, LogLevel};

/// How much colour the terminal can show.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// 24-bit — exact brand RGB.
    TrueColor,
    /// 256-colour — nearest indexed approximation of the brand palette.
    Ansi256,
    /// 16-colour — named ANSI that adapts to the user's terminal palette.
    Basic,
}

#[derive(Clone, Copy)]
pub struct Theme {
    pub ascii: bool,
    pub depth: Depth,
}

impl Theme {
    /// Detect glyph set and colour depth from the environment.
    pub fn detect() -> Self {
        Theme {
            ascii: detect_ascii(),
            depth: detect_depth(),
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
        if self.ascii { "> " } else { "▸ " }
    }

    /// Colour for a health level.
    pub fn color(&self, h: Health) -> Color {
        match h {
            Health::Ok => self.ok(),
            Health::Warn => self.amber(),
            Health::Error => self.rust(),
            Health::Unknown | Health::NotApplicable => self.muted(),
        }
    }

    pub fn health_style(&self, h: Health) -> Style {
        Style::default().fg(self.color(h))
    }

    pub fn log_style(&self, level: LogLevel) -> Style {
        let c = match level {
            LogLevel::Info => self.muted(),
            LogLevel::Good => self.ok(),
            LogLevel::Warn => self.amber(),
            LogLevel::Error => self.rust(),
        };
        Style::default().fg(c)
    }

    // --- brand palette (truecolor RGB · 256-index · ANSI fallback) ---

    /// Teal accent — panel titles, the active section, the `rs-key` chip.
    pub fn accent(&self) -> Color {
        self.pick((95, 175, 165), 73, Color::Cyan)
    }
    fn ok(&self) -> Color {
        self.pick((143, 187, 111), 107, Color::Green)
    }
    fn amber(&self) -> Color {
        self.pick((224, 167, 74), 179, Color::Yellow)
    }
    fn rust(&self) -> Color {
        self.pick((216, 96, 58), 173, Color::Red)
    }
    fn muted(&self) -> Color {
        self.pick((128, 138, 146), 244, Color::DarkGray)
    }

    fn pick(&self, rgb: (u8, u8, u8), idx: u8, ansi: Color) -> Color {
        match self.depth {
            Depth::TrueColor => Color::Rgb(rgb.0, rgb.1, rgb.2),
            Depth::Ansi256 => Color::Indexed(idx),
            Depth::Basic => ansi,
        }
    }

    /// Accented, bold — panel titles.
    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    /// The `rs-key` chip in the header: brand fill, dark ink.
    pub fn chip_style(&self) -> Style {
        let ink = match self.depth {
            Depth::Basic => Color::Black,
            _ => Color::Rgb(0x22, 0x26, 0x2B),
        };
        Style::default()
            .fg(ink)
            .bg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    /// Subtle border colour so titles and content lead over the frame.
    pub fn border_style(&self) -> Style {
        Style::default().fg(self.pick((74, 82, 92), 240, Color::DarkGray))
    }

    /// Selection highlight — an explicit bar on curated terminals (keeps the
    /// row's own colours), `REVERSED` on a bare 16-colour one.
    pub fn selection(&self) -> Style {
        match self.depth {
            Depth::Basic => Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            _ => Style::default()
                .bg(self.pick((51, 59, 69), 237, Color::Black))
                .add_modifier(Modifier::BOLD),
        }
    }

    pub fn warn(&self) -> Style {
        Style::default().fg(self.amber())
    }

    pub fn danger(&self) -> Style {
        Style::default()
            .fg(self.rust())
            .add_modifier(Modifier::BOLD)
    }
}

fn detect_ascii() -> bool {
    if std::env::var_os("RSK_TUI_ASCII").is_some() {
        return true;
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
    // A locale that is set and not UTF-8 → ASCII; nothing set → assume modern.
    any_set && !utf8
}

fn detect_depth() -> Depth {
    match std::env::var("RSK_TUI_TRUECOLOR").ok().as_deref() {
        Some("0") | Some("false") => return Depth::Basic,
        Some(_) => return Depth::TrueColor,
        None => {}
    }
    let colorterm = std::env::var("COLORTERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if colorterm.contains("truecolor") || colorterm.contains("24bit") {
        return Depth::TrueColor;
    }
    let term = std::env::var("TERM").unwrap_or_default();
    if term.contains("256color") || term.contains("direct") {
        return Depth::Ansi256;
    }
    Depth::Basic
}

pub fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}
