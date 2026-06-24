// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display backend for the `display` build: it drives the Waveshare
//! RP2350-Touch-LCD-2.8 (ST7789 over SPI1, CST328 touch over I2C1) and is the
//! `display` build's [`crate::presence::Presence`]. Two roles share one panel:
//!
//! * [`status_task`] mirrors the device status the onboard LED would show (boot /
//!   idle / working), repainting on change — the ambient screen.
//! * [`TouchPresence`] renders the trusted Approve/Deny prompt when an applet asks
//!   for user presence, naming the operation and the *real* relying party, and
//!   block-waits an on-screen tap. A tap on **Allow** confirms; a tap on **Deny**
//!   is a genuine `Declined` (→ `OPERATION_DENIED`) — the BOOTSEL button has no
//!   such gesture. This is the anti-WebUSB-phishing guarantee: a signature can't
//!   be obtained without a physical tap on a screen showing the true rp.
//!
//! The *what to draw*, the untrusted-string sanitizing, the Allow/Deny button
//! geometry and the touch-report parse all live in `rsk-ui` (host-tested + Kani);
//! this file is the thin HAL glue plus the cross-executor wait.
//!
//! Both roles run on the THREAD executor and share the panel through a `'static`
//! `RefCell<Ui>`. They never race for it: `TouchPresence::request` is *synchronous*
//! (the applet call chain is), so while it block-waits a tap the thread executor is
//! occupied and `status_task` cannot run — exactly like the BOOTSEL wait. USB on
//! the interrupt executor preempts the busy-wait throughout, so keepalives keep
//! flowing and a full-frame repaint never stalls enumeration.

use core::cell::RefCell;
use core::sync::atomic::Ordering;

use embassy_rp::gpio::Output;
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C1, SPI1};
use embassy_rp::spi::{Blocking as SpiBlocking, Spi};
use embassy_time::{Delay, Duration, Instant, Timer, block_for};
use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::ColorInversion;
use mipidsi::{Builder, Display};
use rsk_sdk::Confirm;
use rsk_ui::{Button, ConfirmPrompt, PinKey, PinPad, Screen, StatusKind};

use crate::led;
use crate::presence::{CANCEL_REQUESTED, PRESENCE_TIMEOUT_MS, UP_PENDING};

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;
/// Touch poll cadence during a confirm wait; `block_for` keeps interrupts on, so
/// the high-priority USB executor runs between polls (mirrors the BOOTSEL wait).
const TOUCH_POLL_MS: u64 = 16;

/// The fully-built ST7789 panel (write-only, blocking SPI1, no framebuffer).
type Panel = Display<SpiInterface<'static, PanelSpi, Output<'static>>, ST7789, Output<'static>>;
/// The SPI bus + CS presented as one `SpiDevice` for mipidsi.
type PanelSpi = ExclusiveDevice<Spi<'static, SPI1, SpiBlocking>, Output<'static>, Delay>;

/// The CST328 touch controller on I2C1. Owns only the bus; the reset pin is pulsed
/// once during [`Ui::build`].
struct Touch {
    i2c: I2c<'static, I2C1, I2cBlocking>,
}

impl Touch {
    /// Leave normal reporting mode set after the reset pulse — write register
    /// 0xD109 (REG_MODE_NORMAL) as a 2-byte big-endian address with no payload.
    fn normal_mode(&mut self) {
        let _ = self.i2c.blocking_write(CST328_ADDR, &[0xD1, 0x09]);
    }

    /// Read the first finger's coordinate, if any, then clear the report so the
    /// controller serves the next one. Any I2C error reads as "no touch". The
    /// coordinate is already in panel pixels (the controller is configured at the
    /// panel resolution; HW bringup confirmed the axes need no swap).
    fn read(&mut self) -> Option<rsk_ui::Point> {
        let mut buf = [0u8; 7];
        let pt = match self
            .i2c
            .blocking_write_read(CST328_ADDR, &[0xD0, 0x00], &mut buf)
        {
            Ok(()) => rsk_ui::touch::parse_cst328(&buf),
            Err(_) => None,
        };
        // Clear register 0xD005 (write address + a 0 byte) to ack the report.
        let _ = self.i2c.blocking_write(CST328_ADDR, &[0xD0, 0x05, 0x00]);
        pt
    }

    /// Block until the finger lifts (bounded by `timeout`), so one tap maps to one
    /// key press — the CST328 reports continuously while touched. Used by the PIN
    /// pad, where a held finger must not machine-gun a digit.
    fn wait_release(&mut self, start: Instant, timeout: Duration) {
        while self.read().is_some() {
            if start.elapsed() >= timeout {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }
}

/// The panel's SPI bus + control pins + pixel buffer, bundled so `main` stays
/// within embassy's argument cap when it hands the peripherals over.
pub struct PanelHw {
    pub spi: Spi<'static, SPI1, SpiBlocking>,
    pub cs: Output<'static>,
    pub dc: Output<'static>,
    pub rst: Output<'static>,
    pub bl: Output<'static>,
    pub buf: &'static mut [u8],
}

/// The CST328 touch controller's I2C bus + reset pin.
pub struct TouchHw {
    pub i2c: I2c<'static, I2C1, I2cBlocking>,
    pub rst: Output<'static>,
}

/// Panel + touch + the last-painted screen, owned behind a `'static` `RefCell`
/// shared by [`status_task`] and [`TouchPresence`].
pub struct Ui {
    panel: Panel,
    touch: Touch,
    // Backlight (GPIO16) and the CST328 reset (GPIO17), held for the device's
    // lifetime, never toggled again: an embassy `Output` disconnects its pad on
    // drop (sets funcsel = Null), so letting these drop when `build` returns would
    // kill the backlight (a black panel) and float the touch reset.
    #[allow(dead_code)]
    bl: Output<'static>,
    #[allow(dead_code)]
    tp_rst: Output<'static>,
    /// What is currently on screen, so the status loop only repaints on a change.
    shown: Option<Screen>,
}

impl Ui {
    /// Build and initialize the panel + touch from the raw peripherals, show the
    /// boot splash and raise the backlight, and put the CST328 into normal mode.
    /// Blocking (~200 ms of panel/touch reset) — `main` calls this *after* the USB
    /// task is spawned, so the interrupt executor keeps enumerating while these
    /// busy-waits run on the thread executor; enumeration is never delayed.
    pub fn build(panel: PanelHw, touch: TouchHw) -> Ui {
        let PanelHw {
            spi,
            cs,
            dc,
            rst,
            mut bl,
            buf,
        } = panel;
        let TouchHw {
            i2c,
            rst: mut tp_rst,
        } = touch;

        // The panel is write-only, so the only way `ExclusiveDevice` errors is a
        // CS-toggle programming bug.
        let spi_dev = ExclusiveDevice::new(spi, cs, Delay).unwrap();
        let di = SpiInterface::new(spi_dev, dc, buf);

        // ST7789 native 240×320 portrait, matching rsk-ui's geometry. The IPS module
        // needs `Inverted` (HW-verified on bringup).
        let mut delay = Delay;
        let mut panel = Builder::new(ST7789, di)
            .display_size(rsk_ui::PANEL_W, rsk_ui::PANEL_H)
            .invert_colors(ColorInversion::Inverted)
            .reset_pin(rst)
            .init(&mut delay)
            .unwrap();

        let _ = rsk_ui::render(&mut panel, &Screen::Splash);
        bl.set_high(); // backlight on only once there is something to show (no white flash)

        // CST328 reset pulse (high → low → high), then normal reporting mode.
        tp_rst.set_high();
        block_for(Duration::from_millis(10));
        tp_rst.set_low();
        block_for(Duration::from_millis(10));
        tp_rst.set_high();
        block_for(Duration::from_millis(50));
        let mut touch = Touch { i2c };
        touch.normal_mode();

        Ui {
            panel,
            touch,
            bl,
            tp_rst,
            shown: None,
        }
    }
}

/// Map the LED status engine's index ([`led::status`]) onto the on-screen status,
/// so the panel shows the same idle/working/touch state the LED would.
fn status_to_kind(s: u8) -> StatusKind {
    match s {
        led::STATUS_IDLE => StatusKind::Idle,
        led::STATUS_PROCESSING => StatusKind::Processing,
        led::STATUS_TOUCH => StatusKind::Touch,
        _ => StatusKind::Boot,
    }
}

/// Ambient status screen: after letting the splash linger, repaint the idle/working
/// status whenever [`led::status`] changes. The confirm prompt is painted by
/// [`TouchPresence`] (which holds the same [`Ui`]); a synchronous confirm occupies
/// this executor, so this loop never runs mid-confirm and the two never collide on
/// the panel (the `try_borrow_mut` is belt-and-suspenders).
#[embassy_executor::task]
pub async fn status_task(ui: &'static RefCell<Ui>) {
    Timer::after_millis(600).await; // let the boot splash linger
    loop {
        if let Ok(mut u) = ui.try_borrow_mut() {
            let screen = Screen::Status(status_to_kind(led::status()));
            if u.shown != Some(screen) {
                let _ = rsk_ui::render(&mut u.panel, &screen);
                u.shown = Some(screen);
            }
        }
        Timer::after_millis(100).await;
    }
}

/// The on-screen presence backend — the `display` build's
/// [`crate::presence::Presence`]. Holds the shared [`Ui`]; renders a trusted
/// Approve/Deny prompt and block-waits a tap.
pub struct TouchPresence {
    ui: &'static RefCell<Ui>,
}

/// Outcome of a confirm wait. Unlike the BOOTSEL button, the screen has a real
/// decline gesture (the Deny button) → [`Outcome::Declined`].
enum Outcome {
    Confirmed,
    Declined,
    Timeout,
    Cancelled,
}

impl TouchPresence {
    pub fn new(ui: &'static RefCell<Ui>) -> Self {
        Self { ui }
    }

    /// The standard-key BOOTSEL typed-ticket gesture has no analogue on the touch
    /// board (the screen is the interface), so the click-counter never fires.
    pub fn poll_pressed(&mut self) -> bool {
        false
    }

    /// Render `confirm` and block-wait for an Allow/Deny tap, a `CTAPHID_CANCEL`,
    /// or the presence timeout, then hand the panel back to the status loop. Sets
    /// `UP_PENDING` so the CTAPHID keepalive reports `UPNEEDED`, and polls
    /// `CANCEL_REQUESTED` each iteration — the same cross-executor contract the
    /// BOOTSEL wait honours.
    fn confirm_wait(&mut self, confirm: Confirm<'_>) -> Outcome {
        let saved = led::status();
        led::set_status(led::STATUS_TOUCH);
        // Drop any cancel left from an earlier (finished) request so this wait
        // starts clean.
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        UP_PENDING.store(true, Ordering::Relaxed);

        let prompt = ConfirmPrompt::new(confirm.title, confirm.primary, confirm.secondary);
        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let outcome = {
            // Held across the whole wait. The wait is synchronous, so the status
            // loop can't run (let alone borrow) until we return the panel.
            let mut u = self.ui.borrow_mut();
            let _ = rsk_ui::render(&mut u.panel, &Screen::Confirm(prompt));
            u.shown = None; // force the status loop to repaint once we release it
            loop {
                if let Some(p) = u.touch.read() {
                    match rsk_ui::hit_confirm(p) {
                        Some(Button::Allow) => break Outcome::Confirmed,
                        Some(Button::Deny) => break Outcome::Declined,
                        // A tap in a margin/gap selects nothing — keep waiting.
                        None => {}
                    }
                }
                if CANCEL_REQUESTED.load(Ordering::Relaxed) {
                    break Outcome::Cancelled;
                }
                if start.elapsed() >= timeout {
                    break Outcome::Timeout;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        };

        UP_PENDING.store(false, Ordering::Relaxed);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        led::set_status(saved);
        outcome
    }

    /// Run the built-in-UV PIN pad: render the masked keypad, block-poll the CST328,
    /// and accumulate ASCII digits into `out`. Each key is debounced to release, so
    /// one tap is one press; OK commits only at/above `min_len` (a too-short entry
    /// can't reach the verifier and burn a retry), Del backspaces, Cancel declines.
    /// Honors the same UP_PENDING / CANCEL_REQUESTED / timeout contract as the
    /// confirm wait. The entered digits are the caller's to zeroize after verifying.
    fn collect_pin_impl(&mut self, min_len: usize, out: &mut [u8]) -> rsk_fido::PinEntry {
        let saved = led::status();
        led::set_status(led::STATUS_TOUCH);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        UP_PENDING.store(true, Ordering::Relaxed);

        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let mut entered = 0usize;

        let outcome = {
            let mut u = self.ui.borrow_mut();
            let _ = rsk_ui::render(&mut u.panel, &Screen::Pin(PinPad::new(entered)));
            u.shown = None; // force the status loop to repaint once we release it
            loop {
                if let Some(p) = u.touch.read() {
                    let mut repaint = true;
                    let done = match rsk_ui::hit_pin(p) {
                        Some(PinKey::Digit(d)) => {
                            if entered < out.len() {
                                out[entered] = b'0' + d;
                                entered += 1;
                            }
                            None
                        }
                        Some(PinKey::Del) => {
                            entered = entered.saturating_sub(1);
                            None
                        }
                        Some(PinKey::Ok) if entered >= min_len => {
                            Some(rsk_fido::PinEntry::Entered(entered))
                        }
                        Some(PinKey::Cancel) => Some(rsk_fido::PinEntry::Declined),
                        // OK below the minimum, or a tap in a gap: nothing changes.
                        _ => {
                            repaint = false;
                            None
                        }
                    };
                    if repaint && done.is_none() {
                        let _ = rsk_ui::render(&mut u.panel, &Screen::Pin(PinPad::new(entered)));
                    }
                    u.touch.wait_release(start, timeout);
                    if let Some(o) = done {
                        break o;
                    }
                }
                if CANCEL_REQUESTED.load(Ordering::Relaxed) {
                    break rsk_fido::PinEntry::Cancelled;
                }
                if start.elapsed() >= timeout {
                    break rsk_fido::PinEntry::Timeout;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        };

        UP_PENDING.store(false, Ordering::Relaxed);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        led::set_status(saved);
        outcome
    }
}

impl rsk_fido::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_fido::Confirm<'_>) -> rsk_fido::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_fido::Presence::Confirmed,
            Outcome::Declined => rsk_fido::Presence::Declined,
            Outcome::Timeout => rsk_fido::Presence::Timeout,
            Outcome::Cancelled => rsk_fido::Presence::Cancelled,
        }
    }

    // The trusted display has an on-screen PIN pad, so built-in UV is available and
    // getInfo advertises `options.uv` — the PIN is typed here, never on the host.
    fn uv_available(&self) -> bool {
        true
    }

    fn collect_pin(&mut self, min_len: usize, out: &mut [u8]) -> rsk_fido::PinEntry {
        self.collect_pin_impl(min_len, out)
    }
}

impl rsk_openpgp::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_openpgp::Confirm<'_>) -> rsk_openpgp::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_openpgp::Presence::Confirmed,
            Outcome::Declined => rsk_openpgp::Presence::Declined,
            // OpenPGP/PIV run over CCID, which carries no CTAPHID_CANCEL.
            Outcome::Timeout | Outcome::Cancelled => rsk_openpgp::Presence::Timeout,
        }
    }
}

impl rsk_otp::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_otp::Confirm<'_>) -> rsk_otp::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_otp::Presence::Confirmed,
            Outcome::Declined => rsk_otp::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_otp::Presence::Timeout,
        }
    }
}

impl rsk_oath::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_oath::Confirm<'_>) -> rsk_oath::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_oath::Presence::Confirmed,
            Outcome::Declined => rsk_oath::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_oath::Presence::Timeout,
        }
    }
}
