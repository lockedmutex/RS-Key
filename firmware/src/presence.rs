// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Physical user presence over the BOOTSEL button, sampled via the
//! QSPI-CS-to-Hi-Z trick in a RAM function. The wait blocks the worker while the
//! high-priority transports stream keepalives reporting `UPNEEDED` ([`up_pending`]).
//! One [`BootselPresence`] serves every applet's `UserPresence` trait; without the
//! `up-button` feature `request` confirms instantly (for the automated suites).

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_rp::Peri;
use embassy_rp::peripherals::BOOTSEL;

#[cfg(feature = "up-button")]
use embassy_rp::bootsel::is_bootsel_pressed;
#[cfg(feature = "up-button")]
use embassy_time::{Duration, Instant, block_for};

/// Set while the worker is blocked in a button wait — read by the CTAPHID keepalive
/// to report `UPNEEDED` (0x02) instead of `PROCESSING` (0x01).
static UP_PENDING: AtomicBool = AtomicBool::new(false);

/// The CTAPHID keepalive hook passed to `CtapHid::new`: is a touch being awaited?
/// Always `false` when built without `up-button`, so the status stays `PROCESSING`.
pub fn up_pending() -> bool {
    UP_PENDING.load(Ordering::Relaxed)
}

// Poll cadence and the press timeout. `block_for` keeps interrupts enabled, so the
// high-priority executor (USB + keepalives) runs between polls; only the ~4000-cycle
// `is_bootsel_pressed` read briefly masks interrupts.
#[cfg(feature = "up-button")]
const POLL_MS: u64 = 16;
#[cfg(feature = "up-button")]
const TIMEOUT_MS: u64 = 30_000;

/// Neutral wait result, mapped to each applet's own `Presence` enum. The sync poll
/// has no cancel path, so it never produces a "declined".
#[cfg(feature = "up-button")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Confirmed,
    Timeout,
}

/// User presence via the BOOTSEL button.
pub struct BootselPresence {
    #[cfg_attr(not(feature = "up-button"), allow(dead_code))]
    bootsel: Peri<'static, BOOTSEL>,
}

impl BootselPresence {
    pub fn new(bootsel: Peri<'static, BOOTSEL>) -> Self {
        Self { bootsel }
    }

    /// One non-blocking sample of the BOOTSEL level, for the typed-ticket button
    /// watcher. Gated by `up-button`: the no-touch test build never sees a press
    /// and does no QSPI-CS polling.
    pub fn poll_pressed(&mut self) -> bool {
        #[cfg(feature = "up-button")]
        {
            is_bootsel_pressed(self.bootsel.reborrow())
        }
        #[cfg(not(feature = "up-button"))]
        {
            false
        }
    }

    #[cfg(feature = "up-button")]
    fn wait(&mut self) -> Outcome {
        // Save the LED status, show the touch status for the wait, restore after.
        let saved = crate::led::status();
        crate::led::set_status(crate::led::STATUS_TOUCH);
        UP_PENDING.store(true, Ordering::Relaxed);
        let start = Instant::now();
        // Wait for a press; with none in TIMEOUT_MS, return a timeout.
        let result = loop {
            if is_bootsel_pressed(self.bootsel.reborrow()) {
                break Outcome::Confirmed;
            }
            if start.elapsed() >= Duration::from_millis(TIMEOUT_MS) {
                break Outcome::Timeout;
            }
            block_for(Duration::from_millis(POLL_MS));
        };
        // Debounce: wait for release (bounded) so a held button doesn't
        // immediately satisfy the next operation.
        if result == Outcome::Confirmed {
            let release = Instant::now();
            while is_bootsel_pressed(self.bootsel.reborrow()) {
                if release.elapsed() >= Duration::from_millis(TIMEOUT_MS) {
                    break;
                }
                block_for(Duration::from_millis(POLL_MS));
            }
        }
        UP_PENDING.store(false, Ordering::Relaxed);
        crate::led::set_status(saved);
        result
    }
}

impl rsk_fido::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_fido::Presence {
        #[cfg(feature = "up-button")]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_fido::Presence::Confirmed,
                Outcome::Timeout => rsk_fido::Presence::Timeout,
            }
        }
        #[cfg(not(feature = "up-button"))]
        {
            rsk_fido::Presence::Confirmed
        }
    }
}

impl rsk_openpgp::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_openpgp::Presence {
        #[cfg(feature = "up-button")]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_openpgp::Presence::Confirmed,
                Outcome::Timeout => rsk_openpgp::Presence::Timeout,
            }
        }
        #[cfg(not(feature = "up-button"))]
        {
            rsk_openpgp::Presence::Confirmed
        }
    }
}

impl rsk_otp::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_otp::Presence {
        #[cfg(feature = "up-button")]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_otp::Presence::Confirmed,
                Outcome::Timeout => rsk_otp::Presence::Timeout,
            }
        }
        #[cfg(not(feature = "up-button"))]
        {
            rsk_otp::Presence::Confirmed
        }
    }
}

impl rsk_oath::UserPresence for BootselPresence {
    fn request(&mut self) -> rsk_oath::Presence {
        #[cfg(feature = "up-button")]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_oath::Presence::Confirmed,
                Outcome::Timeout => rsk_oath::Presence::Timeout,
            }
        }
        #[cfg(not(feature = "up-button"))]
        {
            rsk_oath::Presence::Confirmed
        }
    }
}
