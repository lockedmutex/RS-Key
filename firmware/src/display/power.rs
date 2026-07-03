// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Display sleep/wake, backlight brightness, and the wake/power button.

use super::*;

/// The locked-hint breathe advances one shade every this many ~100ms status-loop ticks, so
/// the 8-shade ramp cycles in ~2.4s (the design's breathe period).
pub(super) const BREATHE_TICKS: u32 = 3;

impl Ui {
    /// Apply a brightness level (`1..=BRIGHTNESS_LEVELS`) to the backlight PWM and
    /// remember it for the menu's gauge.
    pub(super) fn set_brightness(&mut self, level: u8) {
        self.brightness = level.clamp(1, BRIGHTNESS_LEVELS);
        self.bl
            .set_config(&backlight_cfg(level_duty(self.brightness)));
    }

    /// Blank the panel after the inactivity timeout: backlight off, then clear the
    /// glass to black. A *static* image is what burns into the IPS panel, so dropping
    /// it entirely (not just dimming) is the retention guard. Idempotent.
    fn sleep(&mut self) {
        if self.asleep {
            return;
        }
        self.bl.set_config(&backlight_cfg(0));
        let _ = self.panel.clear(Rgb565::BLACK);
        self.shown = None;
        self.asleep = true;
    }

    /// Restore the panel from sleep: backlight back to the saved brightness; the caller
    /// (the ambient loop, or a host ceremony) repaints. Idempotent.
    pub(super) fn wake(&mut self) {
        if !self.asleep {
            return;
        }
        self.bl
            .set_config(&backlight_cfg(level_duty(self.brightness)));
        self.asleep = false;
        self.shown = None;
    }

    /// One non-blocking sample of the wake button (if wired), honouring its polarity.
    pub(super) fn wake_pressed(&self) -> bool {
        match &self.wake_btn {
            Some((btn, active_high)) => {
                if *active_high {
                    btn.is_high()
                } else {
                    btn.is_low()
                }
            }
            None => false,
        }
    }

    /// Enter display sleep, additionally locking the on-device UI when a device PIN is
    /// set — so a walked-away device requires the PIN to browse passkeys / settings on
    /// wake. Without a PIN there is nothing to unlock with, so it only blanks.
    pub(super) fn enter_sleep(&mut self) {
        if rsk_fido::passkeys::device_pin_is_set(&mut self.fs.borrow_mut()) {
            self.locked = true;
        }
        self.sleep();
    }

    /// Block until the wake button is released (bounded), so a single press toggles
    /// sleep exactly once rather than oscillating while the button is held down.
    pub(super) fn wait_wake_release(&self) {
        let start = Instant::now();
        while self.wake_pressed() {
            if start.elapsed() >= Duration::from_millis(2000) {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// Poll the sleep/wake button from inside a browse modal: if pressed, sleep now
    /// (auto-locking like any sleep), wait for release, and return `true` so the modal
    /// exits to the now-asleep [`status_task`]. `status_task` polls the button itself on
    /// Home / Locked, so calling this in the tab modals makes the power button sleep the
    /// device from *any* on-device screen, not just Home.
    pub(super) fn sleep_button_pressed(&mut self) -> bool {
        if self.wake_pressed() {
            self.enter_sleep();
            self.wait_wake_release();
            true
        } else {
            false
        }
    }
}
