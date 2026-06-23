// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display confirmation context threaded through every applet's
//! `UserPresence::request`. It says *what* a pending Approve/Deny prompt should
//! show: a short, trusted, device-controlled `title` plus up to two **untrusted**
//! relying-party fields the screen sanitizes before painting. The button presence
//! backend ignores all of it; only the `display` build's on-screen backend reads
//! it. It lives here, in the crate every applet already depends on, so threading
//! the context pulls no display code into a standard (screenless) key — the
//! fields are borrowed, so it costs nothing when ignored.

/// What an on-screen Approve/Deny prompt should say while a touch is requested.
///
/// `title` is firmware-controlled trusted text (e.g. `"Sign in?"`); `primary` and
/// `secondary` are **untrusted** relying-party bytes (an rp id, an account name)
/// the display backend reduces to bounded printable ASCII before rendering. Pass
/// empty slices for fields an operation does not carry.
#[derive(Clone, Copy)]
pub struct Confirm<'a> {
    pub title: &'static str,
    pub primary: &'a [u8],
    pub secondary: &'a [u8],
}

impl<'a> Confirm<'a> {
    /// A prompt with a trusted title and untrusted primary/secondary fields.
    pub const fn new(title: &'static str, primary: &'a [u8], secondary: &'a [u8]) -> Self {
        Self {
            title,
            primary,
            secondary,
        }
    }

    /// A title-only prompt — no relying-party text (e.g. reset, selection).
    pub const fn titled(title: &'static str) -> Self {
        Self::new(title, &[], &[])
    }
}
