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
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_rp::gpio::{Input, Output};
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C1, SPI1};
use embassy_rp::pwm::{Config as PwmConfig, Pwm};
use embassy_rp::spi::{Blocking as SpiBlocking, Spi};
use embassy_time::{Delay, Duration, Instant, Timer, block_for};
use embedded_graphics::{draw_target::DrawTarget, pixelcolor::Rgb565, prelude::RgbColor};
use embedded_hal_bus::spi::ExclusiveDevice;
use zeroize::Zeroize;

use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::ColorInversion;
use mipidsi::{Builder, Display};
use rsk_crypto::Device;
use rsk_sdk::Confirm;
use rsk_ui::{
    ALLOW_RECT, AccountRow, AdjustKey, AuditRow, BRIGHTNESS_LEVELS, Button, ConfirmPrompt,
    HomeView, Label, NavTab, PinCaption, PinKey, PinPad, RootEntry, RpRow, Screen, SecurityEntry,
    SettingsPage, SettingsView, StatusKind, SuccessKind,
};

use crate::handler::Store;
use crate::led;
use crate::presence::{CANCEL_REQUESTED, PRESENCE_TIMEOUT_MS, UP_PENDING};

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;
/// Touch poll cadence during a confirm wait; `block_for` keeps interrupts on, so
/// the high-priority USB executor runs between polls (mirrors the BOOTSEL wait).
const TOUCH_POLL_MS: u64 = 16;

/// Until this ms-since-boot the ambient status loop must not repaint. A modal
/// (PIN pad / Approve-Deny) sets it on exit so a back-to-back hand-off — pad →
/// confirm during one UV ceremony — doesn't flash the idle/working screen in the
/// brief host round-trip gap between the two. After the window the ambient screen
/// repaints as usual (returning to idle).
static AMBIENT_QUIET_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
/// How long to hold the ambient screen back after a modal ends — long enough to
/// cover the platform's next-command round-trip, short enough to feel immediate.
const AMBIENT_QUIET_MS: u32 = 400;

/// Auto-close an open on-device tab / menu (Passkeys / Settings / a Confirm-Delete)
/// after this long *without a tap*, returning to the idle status screen — a privacy
/// backstop so a walked-away device doesn't leave the passkey list (or a menu) on
/// screen indefinitely. It is **not** the host-starvation guard: while a tab is open
/// the worker is parked (single thread executor), but the browse loops poll
/// [`crate::worker::host_request_pending`] and yield the instant a host command
/// arrives, so this bound can be generous (a comfortable browse) without making the
/// host wait for it.
const MENU_INACTIVITY_MS: u64 = 60_000;

/// How long the user must hold the on-screen approve button before it confirms — long
/// enough that an accidental brush can't approve, short enough to feel responsive. The
/// button fills as the hold builds, and lifting the finger early resets it.
const HOLD_MS: u64 = 800;

/// Backlight PWM `top` (8-bit, like the LED): a brightness level maps to a compare
/// value `0..=BL_TOP`.
const BL_TOP: u16 = 255;

/// Built-in display-sleep timeout (ms): blank the panel after this long idle to stop
/// image retention on the IPS glass. Runtime-adjustable from the Settings → Display
/// sleep page ([`SLEEP_TIMEOUT_MS`]); `0` there means never sleep.
const DEFAULT_SLEEP_MS: u32 = 60_000;
/// Display-sleep timeout in ms, edited live by the menu. `0` = Off (never blanks).
/// Read each tick by the ambient loop; reboot reseeds the default.
static SLEEP_TIMEOUT_MS: AtomicU32 = AtomicU32::new(DEFAULT_SLEEP_MS);

/// ms-since-boot of the last user interaction (touch / wake button) or host ceremony —
/// the display-sleep countdown is measured from here. Bumped by [`note_activity`].
static LAST_ACTIVITY_MS: AtomicU32 = AtomicU32::new(0);

/// Mark "the user (or host) just did something", resetting the display-sleep countdown.
fn note_activity() {
    LAST_ACTIVITY_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
}

/// Device identity shown read-only on the settings Info page.
pub struct DeviceInfo {
    /// bcdDevice firmware build counter.
    pub version: u16,
    /// RP2350 chip serial (chipid).
    pub chipid: u64,
}

/// The device key material the read-only passkey enumerator needs to load and unbox
/// the resident-credential seed from `EF_KEY_DEV` — the same identity the worker's
/// `Ctx` carries, kept as owned copies so the display task can build a [`Device`] on
/// demand (when the Passkeys tab is open) without holding the seed itself.
pub struct DeviceKeys {
    pub serial_id: [u8; 8],
    pub serial_hash: [u8; 32],
    pub otp_mkek: Option<[u8; 32]>,
}

impl DeviceKeys {
    fn device(&self) -> Device<'_> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_mkek.as_ref(),
        }
    }
}

/// Outcome of the per-RP service-detail screen: return to the Passkeys list, or leave
/// the tab to another nav destination (`None` = the idle Home screen).
enum ServiceResult {
    Back,
    Leave(Option<NavTab>),
}

/// PWM config for the GPIO16 backlight: 8-bit `top`, non-inverted (high = lit), with
/// `duty` as the on-fraction. Shared by `main`'s initial (zero-duty) construction and
/// every live brightness change so the polarity always matches.
pub fn backlight_cfg(duty: u16) -> PwmConfig {
    // `PwmConfig` is `#[non_exhaustive]`, so build from Default and set fields.
    let mut cfg = PwmConfig::default();
    cfg.top = BL_TOP;
    cfg.compare_a = duty.min(BL_TOP);
    cfg
}

/// Map a brightness level (`1..=BRIGHTNESS_LEVELS`) to a backlight duty (compare).
fn level_duty(level: u8) -> u16 {
    let l = level.clamp(1, BRIGHTNESS_LEVELS) as u16;
    (l * BL_TOP) / BRIGHTNESS_LEVELS as u16
}

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
    /// GPIO16 backlight, driven as PWM for brightness (constructed at zero duty so
    /// the panel stays dark through init — no white flash).
    pub bl: Pwm<'static>,
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
    /// Backlight on GPIO16, driven as PWM for brightness control and held for the
    /// device's lifetime (dropping it disconnects the pad → black panel).
    bl: Pwm<'static>,
    // The CST328 reset (GPIO17), held so its pad isn't disconnected on drop (an
    // embassy `Output` sets funcsel = Null when dropped); never toggled after build.
    #[allow(dead_code)]
    tp_rst: Output<'static>,
    /// What is currently on screen, so the status loop only repaints on a change.
    shown: Option<Screen>,
    /// Read-only identity shown on the settings Info page.
    info: DeviceInfo,
    /// Current backlight level (`1..=BRIGHTNESS_LEVELS`), edited from the menu.
    brightness: u8,
    /// Whether the panel is blanked (backlight off + cleared) by the display-sleep
    /// timeout. A touch or the wake button restores it; a host ceremony wakes it too.
    asleep: bool,
    /// The display-sleep wake button (the board's BAT_PWR / a `WAKE_PIN` GPIO) paired
    /// with its `active_high` polarity, or `None` when `WAKE_PIN=none` (touch-only
    /// wake). Polled while asleep.
    wake_btn: Option<(Input<'static>, bool)>,
    /// Whether the on-device UI is locked (passkeys browser + settings need the device
    /// PIN to reopen). Set at boot, on a manual "Lock now", or on auto-sleep — all only
    /// when a PIN is set; cleared by a correct on-screen PIN. Gates only the panel UI —
    /// host CTAP ceremonies (confirm / built-in-UV) are unaffected and paint their own
    /// prompts over it.
    locked: bool,
    /// The shared flash store — the same `RefCell` the worker uses. The Passkeys tab
    /// borrows it to enumerate resident credentials; safe because the worker is parked
    /// (it never holds the borrow across an `.await`) while this thread-executor task
    /// runs.
    fs: &'static RefCell<Store>,
    /// Device identity for unboxing the resident-credential seed on demand.
    keys: DeviceKeys,
}

impl Ui {
    /// Build and initialize the panel + touch from the raw peripherals, show the
    /// boot splash and raise the backlight, and put the CST328 into normal mode.
    /// Blocking (~200 ms of panel/touch reset) — `main` calls this *after* the USB
    /// task is spawned, so the interrupt executor keeps enumerating while these
    /// busy-waits run on the thread executor; enumeration is never delayed.
    pub fn build(
        panel: PanelHw,
        touch: TouchHw,
        info: DeviceInfo,
        fs: &'static RefCell<Store>,
        keys: DeviceKeys,
        wake_btn: Option<(Input<'static>, bool)>,
    ) -> Ui {
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
        // Backlight up to full only now there is something to show (it was built at
        // zero duty, so the panel stayed dark through init — no white flash).
        bl.set_config(&backlight_cfg(level_duty(BRIGHTNESS_LEVELS)));

        // CST328 reset pulse (high → low → high), then normal reporting mode.
        tp_rst.set_high();
        block_for(Duration::from_millis(10));
        tp_rst.set_low();
        block_for(Duration::from_millis(10));
        tp_rst.set_high();
        block_for(Duration::from_millis(50));
        let mut touch = Touch { i2c };
        touch.normal_mode();

        // Boot locked when a device PIN is set: a security key should come up requiring
        // the PIN to reach its on-device UI, not open. Without a PIN there is nothing to
        // unlock with, so it boots open (the lock is a no-op then anyway).
        let locked = rsk_fido::passkeys::pin_is_set(&mut fs.borrow_mut());

        Ui {
            panel,
            touch,
            bl,
            tp_rst,
            shown: None,
            info,
            brightness: BRIGHTNESS_LEVELS,
            asleep: false,
            wake_btn,
            locked,
            fs,
            keys,
        }
    }

    /// Apply a brightness level (`1..=BRIGHTNESS_LEVELS`) to the backlight PWM and
    /// remember it for the menu's gauge.
    fn set_brightness(&mut self, level: u8) {
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
    fn wake(&mut self) {
        if !self.asleep {
            return;
        }
        self.bl
            .set_config(&backlight_cfg(level_duty(self.brightness)));
        self.asleep = false;
        self.shown = None;
    }

    /// One non-blocking sample of the wake button (if wired), honouring its polarity.
    fn wake_pressed(&self) -> bool {
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
    fn enter_sleep(&mut self) {
        if rsk_fido::passkeys::pin_is_set(&mut self.fs.borrow_mut()) {
            self.locked = true;
        }
        self.sleep();
    }

    /// Lock the on-device UI now (the Settings "Lock now" action): the panel stays awake
    /// and [`status_task`] paints the Locked screen. A no-op without a device PIN
    /// (nothing to unlock with).
    fn lock_now(&mut self) {
        if rsk_fido::passkeys::pin_is_set(&mut self.fs.borrow_mut()) {
            self.locked = true;
        }
    }

    /// The on-screen unlock flow, reached by a tap on the Locked screen. Reuses the
    /// device-PIN gate (the same `EF_PIN` retry ladder as the destructive-action gate):
    /// a correct PIN drops the lock, a wrong one re-prompts until the right PIN, a
    /// cancel / timeout, or the counter is spent — all of which leave it locked. Returns
    /// the panel to [`status_task`], which then paints Home (unlocked) or Locked again.
    fn run_unlock(&mut self) {
        // Let the unlock tap's finger lift before the pad starts reading digits.
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        // `local_pin_gate` returns true with no PIN set; that can only happen here if the
        // PIN vanished after the lock — and EF_PIN can only vanish via a factory reset,
        // which reboots into the unlocked state, so "no PIN ⇒ unlock" is never reachable
        // as a bypass (and is the correct behaviour: nothing to verify against).
        if self.local_pin_gate("Enter PIN") {
            self.locked = false;
        }
        self.end_modal();
    }

    /// Block until the wake button is released (bounded), so a single press toggles
    /// sleep exactly once rather than oscillating while the button is held down.
    fn wait_wake_release(&self) {
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
    fn sleep_button_pressed(&mut self) -> bool {
        if self.wake_pressed() {
            self.enter_sleep();
            self.wait_wake_release();
            true
        } else {
            false
        }
    }

    /// Paint a settings page, snapshotting the live brightness/timeout/identity into
    /// the view. Clears `shown` so the ambient loop repaints once the menu releases
    /// the panel.
    fn render_settings(&mut self, page: SettingsPage) {
        let view = SettingsView {
            page,
            brightness: self.brightness,
            timeout_secs: (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            sleep_secs: (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            version: self.info.version,
            chipid: self.info.chipid,
            pin_set: rsk_fido::passkeys::pin_is_set(&mut self.fs.borrow_mut()),
        };
        let _ = rsk_ui::render(&mut self.panel, &Screen::Settings(view));
        self.shown = None;
    }

    /// The interactive on-device settings menu. Synchronous and busy-waiting like the
    /// confirm / PIN modals, so it owns the panel with the same natural mutual
    /// exclusion against the worker (single thread executor: while this spins, no
    /// applet command is serviced — bounded by [`MENU_INACTIVITY_MS`]). Navigates
    /// Root → sub-pages, applies brightness/timeout live, and hands the panel back to
    /// the ambient status loop on Close / Back or after the inactivity timeout.
    fn run_settings(&mut self) -> Option<NavTab> {
        // Render first (so the switch feels instant), then let the opening finger lift
        // before polling so it isn't read as the first menu tap. Settings has no nav
        // bar, so it always returns to idle — `None` — but the signature matches the
        // other tabs for the [`status_task`] navigation dispatcher.
        let mut page = SettingsPage::Root;
        self.render_settings(page);
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);

        loop {
            // The power button sleeps from inside the menu too, not just on Home.
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                let mut repaint = true;
                match page {
                    SettingsPage::Root => {
                        // The title-bar back chevron exits the menu (the design's
                        // settings → back-to-Home flow; there is no "Close" row).
                        if rsk_ui::hit_title_back(p) {
                            break;
                        }
                        match rsk_ui::hit_settings_root(p) {
                            Some(RootEntry::Brightness) => page = SettingsPage::Brightness,
                            Some(RootEntry::Timeout) => page = SettingsPage::Timeout,
                            Some(RootEntry::Sleep) => page = SettingsPage::Sleep,
                            Some(RootEntry::Info) => page = SettingsPage::Info,
                            // Lock now: lock the UI (if a PIN is set) and close the menu —
                            // status_task then paints the Locked screen.
                            Some(RootEntry::LockNow) => {
                                self.lock_now();
                                break;
                            }
                            // Security drills into the Set/Change PIN + Factory reset
                            // sub-page (the destructive reset now lives one tap deeper).
                            Some(RootEntry::Security) => page = SettingsPage::Security,
                            None => repaint = false,
                        }
                    }
                    SettingsPage::Security => {
                        // The title-bar back chevron returns to the Root list.
                        if rsk_ui::hit_title_back(p) {
                            page = SettingsPage::Root;
                        } else {
                            match rsk_ui::hit_security(p) {
                                Some(SecurityEntry::ChangePin) => {
                                    self.run_set_pin();
                                    last = Instant::now();
                                }
                                Some(SecurityEntry::AuditLog) => {
                                    self.run_auditlog();
                                    last = Instant::now();
                                }
                                // A confirmed reset reboots and never returns; on cancel,
                                // fall back to this page (repaint below) with a fresh timeout.
                                Some(SecurityEntry::FactoryReset) => {
                                    self.run_factory_reset();
                                    last = Instant::now();
                                }
                                None => repaint = false,
                            }
                        }
                    }
                    SettingsPage::Brightness => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Minus) => {
                            self.set_brightness(rsk_ui::step_brightness(self.brightness, -1))
                        }
                        Some(AdjustKey::Plus) => {
                            self.set_brightness(rsk_ui::step_brightness(self.brightness, 1))
                        }
                        Some(AdjustKey::Back) => page = SettingsPage::Root,
                        None => repaint = false,
                    },
                    SettingsPage::Timeout => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Minus) => adjust_timeout(-1),
                        Some(AdjustKey::Plus) => adjust_timeout(1),
                        Some(AdjustKey::Back) => page = SettingsPage::Root,
                        None => repaint = false,
                    },
                    SettingsPage::Sleep => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Minus) => adjust_sleep(-1),
                        Some(AdjustKey::Plus) => adjust_sleep(1),
                        Some(AdjustKey::Back) => page = SettingsPage::Root,
                        None => repaint = false,
                    },
                    SettingsPage::Info => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Back) => page = SettingsPage::Root,
                        _ => repaint = false,
                    },
                }
                // A sub-modal (e.g. the audit log) may have slept + locked via the power
                // button; if so, unwind without repainting over the now-blanked panel —
                // status_task owns the asleep/Locked state from here.
                if self.asleep {
                    break;
                }
                // One tap = one action: wait for release (bounded) before the next.
                self.touch.wait_release(last, idle_limit);
                if repaint {
                    self.render_settings(page);
                }
            }
            // A host command is queued — yield to the parked worker at once, rather
            // than making it wait out the (now generous) inactivity bound.
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }

        self.end_modal();
        None
    }

    /// Hand the panel back to the ambient loop on a modal's exit. Closing a tab back to
    /// idle is repainted *immediately* by [`status_task`]'s dispatcher, and a tab → next
    /// tab hand-off renders the new tab directly, so neither needs the ambient-quiet
    /// window (that is only for the pad → confirm gap, set in `confirm_wait` /
    /// `collect_pin`). So this just clears the last-shown marker.
    fn end_modal(&mut self) {
        self.shown = None;
    }

    /// The Passkeys tab — list resident relying parties (read-only), with a drill-in to
    /// each RP's accounts. Enumerates from the shared flash store on entry (the worker is
    /// parked while this synchronous loop runs, so the borrow is safe). Returns the next
    /// nav destination so the [`status_task`] dispatcher can switch tabs directly:
    /// `Some(tab)` opens that tab, `None` returns to the idle Home screen.
    fn run_passkeys(&mut self) -> Option<NavTab> {
        // Snapshot the RP list and render first (so the switch feels instant), then let
        // the opening finger lift. `hashes` parallels `rows` (the UI model carries no
        // rpIdHash) so a drilled-in RP can enumerate its own credentials.
        let mut rows = [RpRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut hashes = [[0u8; 32]; rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_rps(&mut rows, &mut hashes, page);
        self.render_list(&rows[..n], page, total);
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));

        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let next = loop {
            // The power button sleeps from the list too, not just on Home.
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_rps(&mut rows, &mut hashes, page);
                    n = r.0;
                    total = r.1;
                    self.render_list(&rows[..n], page, total);
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    let row = rows[i as usize];
                    match self.run_service(&row.id, &row.nick, &hashes[i as usize]) {
                        ServiceResult::Back => {
                            // A deleted last-account removes its RP, so the total can shrink —
                            // reload this page and clamp it if it scrolled off the end.
                            let r = self.load_rps(&mut rows, &mut hashes, page);
                            n = r.0;
                            total = r.1;
                            let clamped = page.min(rsk_ui::page_count(total).saturating_sub(1));
                            if clamped != page {
                                page = clamped;
                                let r = self.load_rps(&mut rows, &mut hashes, page);
                                n = r.0;
                                total = r.1;
                            }
                            self.render_list(&rows[..n], page, total);
                            self.touch.wait_release(Instant::now(), idle_limit);
                            last = Instant::now();
                            continue;
                        }
                        ServiceResult::Leave(target) => break target,
                    }
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        // Already on this tab — ignore (don't drop to Home).
                        NavTab::Passkeys => {}
                        NavTab::Home => break None,
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            // Yield to the parked worker the instant a host command arrives, so
            // browsing never starves it — the timeout is only the walked-away backstop.
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One RP's detail: show its name (the device-local nickname if set, else the rpId),
    /// list its resident accounts, let a tap on an account start the Confirm-Delete flow
    /// ([`run_delete`]), and the title-bar pencil open the rename flow ([`run_rename`]).
    /// The back chevron (or a tap on the active Passkeys tab) returns to the list; another
    /// nav tab leaves the Passkeys tab; the back chevron only ever returns
    /// [`ServiceResult::Back`]. After a delete the set is reloaded — when the last account
    /// goes, the screen drops back to the list (whose RP row is gone too).
    fn run_service(&mut self, rp_id: &Label, nick0: &Label, hash: &[u8; 32]) -> ServiceResult {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut accts = [AccountRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut fids = [0u16; rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        // The shown title tracks the nickname (Copy), so a rename updates it live.
        let mut nick = *nick0;
        let title = |nick: &Label| if nick.is_empty() { *rp_id } else { *nick };
        let (mut n, mut total) = self.load_accts(hash, &mut accts, &mut fids, page);
        let _ = rsk_ui::render_service(&mut self.panel, &title(&nick), &accts[..n], page, total);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        let mut last = Instant::now();
        loop {
            // The power button sleeps from the detail view too, not just on Home.
            if self.sleep_button_pressed() {
                return ServiceResult::Leave(None);
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    return ServiceResult::Back;
                }
                if rsk_ui::hit_title_edit(p) {
                    // The pencil: rename this RP's device-local nickname, then repaint with
                    // the (possibly changed) title. The credential box is untouched.
                    if let Some(new_nick) = self.run_rename(&nick, hash) {
                        nick = new_nick;
                    }
                    let _ = rsk_ui::render_service(
                        &mut self.panel,
                        &title(&nick),
                        &accts[..n],
                        page,
                        total,
                    );
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(tab) = rsk_ui::hit_nav(p) {
                    return match tab {
                        // The active tab drills back out to its own list.
                        NavTab::Passkeys => ServiceResult::Back,
                        NavTab::Home => ServiceResult::Leave(None),
                        NavTab::Settings => ServiceResult::Leave(Some(NavTab::Settings)),
                    };
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_accts(hash, &mut accts, &mut fids, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_service(
                        &mut self.panel,
                        &title(&nick),
                        &accts[..n],
                        page,
                        total,
                    );
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    self.run_delete(&title(&nick), &accts[i as usize].name, fids[i as usize]);
                    let r = self.load_accts(hash, &mut accts, &mut fids, page);
                    n = r.0;
                    total = r.1;
                    if total == 0 {
                        return ServiceResult::Back; // last account gone — this RP vanished
                    }
                    // Clamp the page if the delete scrolled it off the end, then repaint.
                    let clamped = page.min(rsk_ui::page_count(total).saturating_sub(1));
                    if clamped != page {
                        page = clamped;
                        let r = self.load_accts(hash, &mut accts, &mut fids, page);
                        n = r.0;
                        total = r.1;
                    }
                    let _ = rsk_ui::render_service(
                        &mut self.panel,
                        &title(&nick),
                        &accts[..n],
                        page,
                        total,
                    );
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            // Same yield as the list: a pending host command takes priority over an
            // open read-only detail.
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                return ServiceResult::Leave(None);
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// The rename screen: edit a relying party's device-local nickname with the character
    /// wheel and persist it via [`rsk_fido::passkeys::set_rp_nickname`] — which seals the
    /// label at rest and never touches the credential box, so the passkey keeps working.
    /// Returns the committed nickname (empty = cleared) only when the store actually
    /// persisted it, or `None` on cancel (back chevron / power-button sleep / a queued host
    /// command / inactivity) *and* on a failed store (so the caller keeps the prior title
    /// rather than showing an unsaved rename). Pre-filled with
    /// the current nickname (empty if none); the wheel cycles `RENAME_CHARSET`, `+` appends
    /// the candidate, `⌫` deletes, and the buffer is capped at `RP_NICK_MAX_LEN`.
    fn run_rename(&mut self, current: &Label, hash: &[u8; 32]) -> Option<Label> {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let charset = rsk_ui::RENAME_CHARSET;
        let mut buf = [0u8; rsk_fido::passkeys::RP_NICK_MAX_LEN];
        let mut len = 0usize;
        for &b in current.as_str().as_bytes() {
            if len < buf.len() {
                buf[len] = b;
                len += 1;
            }
        }
        let mut cand = 0usize;
        let val = |buf: &[u8], len: usize| -> Label { Label::clamp(&buf[..len]) };
        let _ = rsk_ui::render_rename(&mut self.panel, val(&buf, len).as_str(), charset[cand]);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                return None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    return None; // cancel — no change persisted
                }
                if let Some(k) = rsk_ui::hit_rename(p) {
                    match k {
                        rsk_ui::RenameKey::Up => cand = (cand + 1) % charset.len(),
                        rsk_ui::RenameKey::Down => {
                            cand = (cand + charset.len() - 1) % charset.len()
                        }
                        rsk_ui::RenameKey::Insert => {
                            if len < buf.len() {
                                buf[len] = charset[cand];
                                len += 1;
                            }
                        }
                        rsk_ui::RenameKey::Backspace => len = len.saturating_sub(1),
                        rsk_ui::RenameKey::Save => {
                            let committed = val(&buf, len);
                            let dev = self.keys.device();
                            let saved = rsk_fido::passkeys::set_rp_nickname(
                                &dev,
                                &mut self.fs.borrow_mut(),
                                hash,
                                committed.as_str(),
                            );
                            // Only report the new title if it actually persisted — on a
                            // failed store (no seed / full flash / RP vanished) keep the
                            // prior title so the screen never claims an unsaved rename.
                            return saved.then_some(committed);
                        }
                    }
                    let _ = rsk_ui::render_rename(
                        &mut self.panel,
                        val(&buf, len).as_str(),
                        charset[cand],
                    );
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                return None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// Repaint the Passkeys list (a full-frame paint) and mark the panel for the ambient
    /// loop to refresh once the tab closes.
    fn render_list(&mut self, rows: &[RpRow], page: u16, total: u16) {
        let _ = rsk_ui::render_passkeys_list(&mut self.panel, rows, page, total);
        self.shown = None;
    }

    /// Enumerate resident RPs into `rows` (+ their rpIdHashes into `hashes`), returning
    /// the kept count and the true total. Reads + decrypts from the shared store; the
    /// seed is loaded and zeroized inside the enumerator (the display never holds it).
    fn load_rps(&self, rows: &mut [RpRow], hashes: &mut [[u8; 32]], page: u16) -> (usize, u16) {
        let dev = self.keys.device();
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut store = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let total = rsk_fido::passkeys::for_each_rp(&dev, &mut *store, |rp| {
            if idx >= offset && n < rows.len() {
                rows[n] = RpRow {
                    id: Label::clamp(rp.rp_id.as_bytes()),
                    nick: rp
                        .nickname
                        .map(|s| Label::clamp(s.as_bytes()))
                        .unwrap_or_default(),
                    accounts: rp.count,
                };
                hashes[n] = rp.rp_id_hash;
                n += 1;
            }
            idx += 1;
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// Snapshot the most recent journal events for the audit log, newest first. Each
    /// `EV_*` code maps to its display [`rsk_ui::AuditKind`], and an entry from the
    /// **current** power cycle also carries how long ago it happened — the journal's
    /// uptime is the same monotonic clock as `Instant::now()` but resets each boot, so a
    /// boot entry marks the session boundary and older rows show no time (no wall clock).
    /// Borrow-safe like [`Self::load_rps`] (the worker is parked while this modal runs).
    fn load_events(&self, rows: &mut [AuditRow], page: u16) -> (usize, u16) {
        let dev = self.keys.device();
        // Cap the live clock at the journal's own resolution: `build_entry` saturates the
        // stored `uptime_ms` to `u32::MAX`, so after ~49.7 days of continuous uptime both
        // sides saturate together and a just-logged event still reads "now" rather than a
        // delta measured from the saturation point.
        let now_ms = Instant::now().as_millis().min(u32::MAX as u64);
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut store = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let mut current_session = true;
        let total = rsk_fido::journal::for_each_event(&dev, &mut *store, |e| {
            if idx >= offset && n < rows.len() {
                let secs_ago = if current_session && (e.uptime_ms as u64) <= now_ms {
                    Some(((now_ms - e.uptime_ms as u64) / 1000) as u32)
                } else {
                    None
                };
                rows[n] = AuditRow {
                    kind: audit_kind(e.event),
                    secs_ago,
                };
                n += 1;
            }
            // Track the boot boundary for EVERY visited entry (including newer ones skipped
            // before the page window), so the current-session flag is correct by the time we
            // reach the page.
            if e.event == rsk_fido::journal::EV_BOOT {
                current_session = false; // everything older is a prior power cycle
            }
            idx += 1;
            n < rows.len() // stop once the page is full (older entries needn't be visited)
        });
        (n, total.min(u16::MAX as u32) as u16)
    }

    /// The read-only on-device audit log (Settings → Security → Audit log): snapshot the
    /// current page of journal events and show them until the back chevron, the power
    /// button (sleeps + locks), a queued host command, or the inactivity timeout. The
    /// pager arrows page through a longer log. Synchronous like the other browse modals
    /// (the worker is parked); read-only, so no tap mutates anything. After a power-button
    /// sleep the caller ([`Self::run_settings`]) sees `asleep` and unwinds without
    /// repainting over the blanked panel.
    fn run_auditlog(&mut self) {
        let mut rows = [AuditRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_events(&mut rows, page);
        let _ = rsk_ui::render_audit_log(&mut self.panel, &rows[..n], page, total);
        self.shown = None;
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                return;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    return;
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_events(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_audit_log(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                return;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// Enumerate the resident accounts under `hash` into `accts`, recording each one's
    /// `EF_CRED` slot fid into the parallel `fids` (the key [`run_delete`] takes to
    /// remove it). The label is the user name, else the display name, else a placeholder
    /// (a binary user id is not a legible label); credProtect ≥ 2 marks the row UV-gated.
    fn load_accts(
        &self,
        hash: &[u8; 32],
        accts: &mut [AccountRow],
        fids: &mut [u16],
        page: u16,
    ) -> (usize, u16) {
        let dev = self.keys.device();
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut store = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let total = rsk_fido::passkeys::for_each_cred(&dev, &mut *store, hash, |a| {
            if idx >= offset && n < accts.len() {
                let name = if !a.user_name.is_empty() {
                    Label::clamp(a.user_name.as_bytes())
                } else if !a.user_display_name.is_empty() {
                    Label::clamp(a.user_display_name.as_bytes())
                } else {
                    Label::clamp(b"(no name)")
                };
                accts[n] = AccountRow {
                    name,
                    protected: a.cred_protect >= 2,
                };
                fids[n] = a.ef_cred_fid;
                n += 1;
            }
            idx += 1;
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// Collect a PIN on the on-screen pad (the trusted built-in-UV input). Renders the
    /// masked keypad, block-polls the CST328 accumulating ASCII digits into `out`, and
    /// honours the same UP_PENDING / CANCEL_REQUESTED / timeout contract as the confirm
    /// wait. Owns the panel via `&mut self` (single thread executor → the worker is
    /// parked), so both the host built-in-UV path ([`TouchPresence::collect_pin`]) and a
    /// display-initiated gate ([`local_pin_gate`]) share one pad. Each key debounces to
    /// release; OK commits only at/above `min_len`, Del backspaces, Cancel declines. The
    /// entered digits are the caller's to zeroize after verifying.
    ///
    /// `yield_to_host`: on a *local* gate (delete / factory-reset / unlock) no host is
    /// waiting on this PIN, so a queued host command must not be starved while the user
    /// types — set it `true` to abandon entry ([`PinEntry::Cancelled`], no retry burned)
    /// the instant a command arrives, mirroring the browse modals. The host built-in-UV
    /// path sets it `false`: there the host *is* waiting on this exact PIN (its `REQ` is
    /// already consumed), so it blocks to the presence timeout as before.
    fn collect_pin(
        &mut self,
        title: &'static str,
        caption: Option<PinCaption>,
        min_len: usize,
        out: &mut [u8],
        yield_to_host: bool,
    ) -> rsk_fido::PinEntry {
        let saved = led::status();
        led::set_status(led::STATUS_TOUCH);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        UP_PENDING.store(true, Ordering::Relaxed);

        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let mut entered = 0usize;

        // A built-in-UV PIN entry can arrive while the panel slept — restore it first.
        self.wake();
        note_activity();
        let _ = rsk_ui::render(
            &mut self.panel,
            &Screen::Pin(PinPad::with_caption(entered, title, caption)),
        );
        self.shown = None; // force the status loop to repaint once we release it
        let outcome = loop {
            if let Some(p) = self.touch.read() {
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
                    _ => {
                        repaint = false;
                        None
                    }
                };
                if repaint && done.is_none() {
                    let _ = rsk_ui::render_pin_dots(&mut self.panel, entered);
                }
                self.touch.wait_release(start, timeout);
                if let Some(o) = done {
                    break o;
                }
            }
            if CANCEL_REQUESTED.load(Ordering::Relaxed) {
                break rsk_fido::PinEntry::Cancelled;
            }
            // A local gate must not starve the parked worker: abandon the moment a host
            // command queues (no host awaits this PIN). The host built-in-UV path keeps
            // `yield_to_host=false` and blocks to the timeout (the host awaits it).
            if yield_to_host && crate::worker::host_request_pending() {
                break rsk_fido::PinEntry::Cancelled;
            }
            if start.elapsed() >= timeout {
                break rsk_fido::PinEntry::Timeout;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };

        UP_PENDING.store(false, Ordering::Relaxed);
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        AMBIENT_QUIET_UNTIL_MS.store(
            (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
            Ordering::Relaxed,
        );
        note_activity(); // a long ceremony shouldn't immediately fall asleep on return
        led::set_status(saved);
        outcome
    }

    /// Gate a destructive local action behind the device PIN when one is set: collect it
    /// on the pad and verify it locally against the same `EF_PIN` and retry counter the
    /// host PIN path uses. A wrong entry re-prompts with a "Wrong PIN, N left" caption
    /// (the remaining attempts) until the right PIN, a decline / timeout, or the counter
    /// is spent. Returns whether the action may proceed (`true` = no PIN set, or the
    /// correct PIN was entered).
    fn local_pin_gate(&mut self, title: &'static str) -> bool {
        if !rsk_fido::passkeys::pin_is_set(&mut self.fs.borrow_mut()) {
            return true;
        }
        let mut pin = [0u8; 64];
        let mut caption = None;
        let mut blocked = false;
        let proceed = loop {
            // CTAP's 4-digit floor; `verify_local_pin` checks the exact PIN regardless,
            // so a higher `minPINLength` policy is still satisfied by typing it in full.
            match self.collect_pin(title, caption, 4, &mut pin, true) {
                rsk_fido::PinEntry::Entered(len) => {
                    let dev = self.keys.device();
                    let verdict = rsk_fido::passkeys::verify_local_pin(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        &pin[..len.min(pin.len())],
                    );
                    match verdict {
                        rsk_fido::passkeys::LocalPin::Ok => break true,
                        // Re-prompt showing the remaining attempts until the budget runs out.
                        rsk_fido::passkeys::LocalPin::Wrong { retries_left } => {
                            caption = Some(PinCaption::WrongPin { retries_left });
                        }
                        // Budget spent — note it and break; the notice is shown below, once
                        // the immutable `dev` borrow has been released.
                        rsk_fido::passkeys::LocalPin::Blocked => {
                            blocked = true;
                            break false;
                        }
                    }
                }
                // Cancel / timeout / cancelled-by-host: abandon the action.
                _ => break false,
            }
        };
        pin.zeroize();
        if blocked {
            self.show_pin_blocked();
        }
        proceed
    }

    /// After a local PIN gate exhausts the retry budget, show the "PIN blocked" notice
    /// rather than silently closing the pad. Held until a tap or ~5 s (or a queued host
    /// command), so the lockout — recoverable only by a host-side reset, since every
    /// on-device action shares the one blocked `EF_PIN` counter — is explained.
    fn show_pin_blocked(&mut self) {
        let _ = rsk_ui::render_pin_blocked(&mut self.panel);
        self.shown = None;
        // Let the final wrong-PIN tap lift, then hold the notice, dismissable by a fresh tap.
        let start = Instant::now();
        self.touch
            .wait_release(start, Duration::from_millis(MENU_INACTIVITY_MS));
        let show = Duration::from_millis(5000);
        let t0 = Instant::now();
        loop {
            if self.touch.read().is_some() {
                self.touch.wait_release(t0, show);
                break;
            }
            if crate::worker::host_request_pending() || t0.elapsed() >= show {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        note_activity();
    }

    /// Paint one of the design's success "pop" screens (approve / delete / wipe) and
    /// dismiss it. The circle pops in over static chrome (the 0.6 → 1.06 → 1.0 scale),
    /// painted once and never repainted so it can't flicker. With `hold_ms = None` the
    /// screen carries a **Done** button and waits for a tap — or a queued host command /
    /// the inactivity timeout, so an unattended success screen never starves the worker.
    /// With `Some(ms)` it auto-dismisses after the pop plus `ms` (used where there is no
    /// one to tap Done: the approve pop, which the host ceremony is waiting behind, and
    /// the wipe pop, which is followed by a reboot).
    fn show_success(&mut self, kind: SuccessKind, hold_ms: Option<u64>) {
        let wait_done = hold_ms.is_none();
        let _ = rsk_ui::render_success(&mut self.panel, kind, wait_done);
        for pct in [55u16, 85, 106, 100] {
            let _ = rsk_ui::render_success_circle(&mut self.panel, kind, pct);
            block_for(Duration::from_millis(70));
        }
        self.shown = None;
        note_activity();
        match hold_ms {
            Some(ms) => block_for(Duration::from_millis(ms)),
            None => {
                let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
                self.touch.wait_release(Instant::now(), idle_limit);
                let mut last = Instant::now();
                loop {
                    if let Some(p) = self.touch.read() {
                        if rsk_ui::hit_success_done(p) {
                            break;
                        }
                        last = Instant::now();
                    }
                    if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                        break;
                    }
                    block_for(Duration::from_millis(TOUCH_POLL_MS));
                }
                note_activity();
            }
        }
    }

    /// The Confirm-Delete flow for one resident passkey (mockup screens 6 → 10): gate on
    /// the device PIN (if set), then paint the trusted confirm screen naming the rp +
    /// account and require a deliberate **hold** on the delete button before removing the
    /// credential. The header back chevron, a slid-off finger, or the inactivity timeout
    /// all abandon it without a write. Synchronous like the other modals (the worker is
    /// parked), so the `self.fs` borrows can't race.
    fn run_delete(&mut self, rp: &Label, account: &Label, fid: u16) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        // Let the account-row tap's finger lift before the next touch is read.
        self.touch.wait_release(Instant::now(), idle_limit);
        // Gate on the device PIN first: when one is set the pad is shown straight away,
        // so the confirm screen below doesn't flash for a frame behind it. With no PIN,
        // `local_pin_gate` returns at once and the confirm screen is the first thing seen.
        if !self.local_pin_gate("Enter PIN") {
            return; // no PIN, wrong PIN, or declined — nothing removed
        }
        // The destructive-action screen: name the rp + account, then require the hold.
        let _ = rsk_ui::render_confirm_delete(&mut self.panel, rp, account);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        if self.hold_to_confirm("Hold to delete") {
            let removed = rsk_fido::passkeys::delete_cred(&mut self.fs.borrow_mut(), fid);
            if removed {
                self.show_success(SuccessKind::Deleted, None);
            }
        }
        self.end_modal();
    }

    /// The shared hold-to-confirm gesture on [`rsk_ui::DEL_HOLD_RECT`]: fill the
    /// button as the finger holds, returning `true` only once it is held the full
    /// [`HOLD_MS`] (so a brush can't commit). The header back chevron, a lifted or
    /// slid-off finger then the inactivity timeout, or a queued host command all
    /// return `false`. The caller paints the surrounding screen first; `label` is
    /// the button caption. Used by both the delete and factory-reset confirms.
    fn hold_to_confirm(&mut self, label: &str) -> bool {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut hold_start: Option<Instant> = None;
        let mut last_num: u16 = 0;
        let mut last = Instant::now();
        loop {
            let mut on_hold = false;
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_pk_back(p) {
                    return false; // cancel
                }
                if rsk_ui::hit_del_hold(p) {
                    on_hold = true;
                    let held = hold_start.get_or_insert_with(Instant::now).elapsed();
                    let num = held.as_millis().min(HOLD_MS) as u16;
                    let _ = rsk_ui::render_hold_fill(
                        &mut self.panel,
                        rsk_ui::DEL_HOLD_RECT,
                        label,
                        last_num,
                        num,
                        HOLD_MS as u16,
                        rsk_ui::theme::DENY,
                    );
                    last_num = num;
                    if held >= Duration::from_millis(HOLD_MS) {
                        return true;
                    }
                }
            }
            // Finger lifted or slid off the button: reset a building hold.
            if !on_hold && hold_start.take().is_some() {
                let _ = rsk_ui::render_hold_button(
                    &mut self.panel,
                    rsk_ui::DEL_HOLD_RECT,
                    label,
                    rsk_ui::theme::DENY,
                );
                last_num = 0;
            }
            // A queued host command aborts the (uncommitted) confirm so the worker can
            // run; nothing commits unless the hold actually completes.
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                return false; // timeout / yield
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// The on-device factory-reset flow (Settings → Factory reset): paint the danger
    /// confirm screen, gate on the device PIN (if set, exactly like delete), then
    /// require a deliberate hold before erasing every applet's data. The back
    /// chevron, a slid-off finger, or the inactivity timeout all abandon it without a
    /// write. On a completed hold it shows the wiping notice, erases all flash but the
    /// org attestation ([`rsk_fido::survives_factory_reset`]), and reboots — the next
    /// boot re-provisions a fresh seed, so the device returns blank. Diverges (resets)
    /// on confirm; returns only when cancelled.
    fn run_factory_reset(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        // Let the Settings-row tap's finger lift before the next touch is read.
        self.touch.wait_release(Instant::now(), idle_limit);
        // PIN gate first (when set) so the pad doesn't flash the confirm screen behind it;
        // no PIN returns at once and the confirm screen below is shown directly.
        if !self.local_pin_gate("Enter PIN") {
            return; // no PIN set is fine; a wrong PIN or decline aborts — nothing erased
        }
        // The destructive-action screen, then a deliberate hold to commit.
        let _ = rsk_ui::render_confirm_factory_reset(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        if self.hold_to_confirm("Hold to reset") {
            // The scrub blocks the panel for seconds, so paint the notice first, then
            // wipe everything but the attestation and reboot into a fresh device. The
            // reboot clears RAM and re-seeds at boot, so no rng/state is needed here.
            let _ = rsk_ui::render_erasing(&mut self.panel);
            let _ = self
                .fs
                .borrow_mut()
                .factory_wipe(rsk_fido::survives_factory_reset);
            // Confirm the wipe on the trusted screen before the reboot re-provisions a
            // fresh device (the grey rotate pop reads as "erased / restarting").
            self.show_success(SuccessKind::Wiped, Some(1100));
            cortex_m::peripheral::SCB::sys_reset();
        }
        self.end_modal();
    }

    /// The on-device Set / Change PIN flow (Settings → Security → Set/Change PIN). When a
    /// PIN is already set it is verified first via [`local_pin_gate`] (so a change still
    /// proves knowledge of the current PIN; a first-time set returns at once with no
    /// prompt), then the new PIN is entered twice and the two must match before it is
    /// written to `EF_PIN` with a fresh retry budget — the same verifier the host
    /// setPIN/changePIN path stores, so the host then sees a clientPIN unchanged. A wrong
    /// current PIN, a decline, a timeout, or a queued host command abandons it without a
    /// write; a mismatch clears both entries and re-prompts. Synchronous like the other
    /// modals (the worker is parked). The pad enforces the `minPINLength` floor and
    /// [`store_local_pin`] re-checks it.
    fn run_set_pin(&mut self) {
        // Let the Security-row tap's finger lift before the pad reads digits.
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        if !self.local_pin_gate("Current PIN") {
            return; // wrong current PIN, decline, timeout, or host yield — nothing changed
        }
        let min = rsk_fido::passkeys::min_pin_length(&mut self.fs.borrow_mut()) as usize;
        // Size the pad buffers to the host-representable maximum so the pad can't accept a
        // digit beyond it (`collect_pin` caps at `out.len()`); a PIN chosen here is then
        // always one the host clientPIN path can verify, and `store_local_pin` re-checks.
        let mut new = [0u8; rsk_fido::passkeys::MAX_PIN_LENGTH];
        let mut confirm = [0u8; rsk_fido::passkeys::MAX_PIN_LENGTH];
        // After a New ≠ Confirm mismatch, re-prompt "New PIN" with a visible reason.
        let mut new_caption = None;
        loop {
            new.zeroize();
            confirm.zeroize();
            let n1 = match self.collect_pin("New PIN", new_caption, min, &mut new, true) {
                rsk_fido::PinEntry::Entered(n) => n.min(new.len()),
                _ => break, // declined / timeout / host yield — nothing set
            };
            let n2 = match self.collect_pin("Confirm PIN", None, min, &mut confirm, true) {
                rsk_fido::PinEntry::Entered(n) => n.min(confirm.len()),
                _ => break, // confirm declined / timeout / host yield
            };
            if n1 == n2 && rsk_crypto::ct_eq(&new[..n1], &confirm[..n2]) {
                let dev = self.keys.device();
                // The pad already enforced the length floor; a flash error is the only
                // realistic failure and leaves no PIN set — abandon either way.
                let _ = rsk_fido::passkeys::store_local_pin(
                    &dev,
                    &mut self.fs.borrow_mut(),
                    &new[..n1],
                );
                break;
            }
            // Mismatch: re-prompt from "New PIN" with the reason; the loop clears both.
            new_caption = Some(PinCaption::Mismatch);
        }
        new.zeroize();
        confirm.zeroize();
        self.end_modal();
    }
}

/// Step the live presence/touch timeout to the next/previous menu choice and store
/// it (the seconds → ms atomic the waits read). Runtime-only: a reboot re-seeds it
/// from the phy record, so persisting it across boots is a later, flash-format change.
fn adjust_timeout(delta: i8) {
    let cur = (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_timeout(cur, delta);
    PRESENCE_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
}

/// Step the display-sleep timeout from the menu (−/+). `0` seconds = Off (never blanks).
fn adjust_sleep(delta: i8) {
    let cur = (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_sleep(cur, delta);
    SLEEP_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
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

/// Apply a pager tap to the current page, clamped to `0..page_count(total)` — a Prev on
/// page 0 or a Next on the last page is a harmless no-op (the arrow is drawn dimmed).
fn paged(page: u16, total: u16, k: rsk_ui::PagerKey) -> u16 {
    let last = rsk_ui::page_count(total).saturating_sub(1);
    match k {
        rsk_ui::PagerKey::Prev => page.saturating_sub(1),
        rsk_ui::PagerKey::Next => (page + 1).min(last),
    }
}

/// Map a journal event code to its on-device audit-log display class (the boundary
/// translation, the way an rpId is clamped into a `Label` — rsk-ui has no rsk-fido dep).
fn audit_kind(ev: u8) -> rsk_ui::AuditKind {
    use rsk_fido::journal as j;
    use rsk_ui::AuditKind as K;
    match ev {
        j::EV_GET_ASSERT | j::EV_U2F_AUTH => K::Login,
        j::EV_MAKE_CRED | j::EV_U2F_REGISTER => K::Register,
        j::EV_PIN_SET | j::EV_PIN_CHANGE => K::Pin,
        j::EV_PIN_LOCKOUT => K::Denied,
        j::EV_BOOT => K::Boot,
        j::EV_RESET => K::Reset,
        j::EV_LOCK_ENGAGE | j::EV_LOCK_RELEASE => K::Lock,
        j::EV_CFG_MIN_PIN | j::EV_CFG_EA | j::EV_CFG_ALWAYS_UV => K::Config,
        j::EV_BACKUP_EXPORT | j::EV_BACKUP_LOAD | j::EV_BACKUP_FINALIZE => K::Backup,
        _ => K::Other,
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
    note_activity(); // the fresh boot counts as activity, so the sleep clock starts now
    loop {
        // Wrap-safe deadline checks (millis truncated to u32 wrap every ~49 days).
        let now = Instant::now().as_millis() as u32;
        if let Ok(mut u) = ui.try_borrow_mut() {
            if u.asleep {
                // Blanked for retention: poll only the wake sources. A touch anywhere or
                // the wake button restores the panel — repainted right away so waking
                // shows Home, not the black sleep frame — and the gesture is consumed
                // (wait for release) so it isn't read as a tap / an instant re-sleep.
                if u.touch.read().is_some() || u.wake_pressed() {
                    u.wake();
                    note_activity();
                    // Wake to the Locked screen if the device locked on sleep; the wake
                    // gesture only wakes (it isn't read as the unlock tap — that comes
                    // after release). Otherwise wake straight to Home.
                    let screen = if u.locked {
                        Screen::Locked
                    } else {
                        Screen::Home(HomeView {
                            status: status_to_kind(led::status()),
                        })
                    };
                    let _ = rsk_ui::render(&mut u.panel, &screen);
                    u.shown = Some(screen);
                    u.touch
                        .wait_release(Instant::now(), Duration::from_millis(1000));
                    u.wait_wake_release();
                }
            } else {
                // Skip the ambient repaint while a modal hand-off is in flight, so the
                // status screen never flickers between the pad and the confirm prompt.
                let quiet_over =
                    now.wrapping_sub(AMBIENT_QUIET_UNTIL_MS.load(Ordering::Relaxed)) as i32 >= 0;
                if quiet_over {
                    let kind = status_to_kind(led::status());
                    // Working / awaiting-touch is activity — never sleep mid-operation.
                    if kind != StatusKind::Idle {
                        note_activity();
                    }
                    // When the on-device UI is locked, the Locked screen stands in for
                    // Home; a tap there starts the unlock PIN flow instead of nav. Host
                    // ceremonies still paint their own prompts over this (they don't
                    // consult `locked`).
                    let screen = if u.locked {
                        Screen::Locked
                    } else {
                        Screen::Home(HomeView { status: kind })
                    };
                    if u.shown != Some(screen) {
                        let _ = rsk_ui::render(&mut u.panel, &screen);
                        u.shown = Some(screen);
                    }
                    if kind == StatusKind::Idle {
                        if u.wake_pressed() {
                            // The wake button doubles as a manual "sleep now" while awake
                            // (also locks, like any sleep, when a PIN is set).
                            u.enter_sleep();
                            u.wait_wake_release();
                        } else if let Some(p) = u.touch.read() {
                            note_activity();
                            if u.locked {
                                // Locked: any tap opens the unlock pad. Repaint the result
                                // at once — Home if the correct PIN dropped the lock, else
                                // the Locked screen — so the pad's last frame never lingers
                                // through collect_pin's ambient-quiet window.
                                u.run_unlock();
                                note_activity();
                                let screen = if u.locked {
                                    Screen::Locked
                                } else {
                                    Screen::Home(HomeView {
                                        status: status_to_kind(led::status()),
                                    })
                                };
                                let _ = rsk_ui::render(&mut u.panel, &screen);
                                u.shown = Some(screen);
                            } else {
                                // A tap on the bottom nav opens a tab. Each tab modal returns
                                // the next nav destination, so the user switches tab→tab
                                // directly (e.g. Passkeys → Settings) without a Home detour.
                                let mut target = rsk_ui::hit_nav(p);
                                let opened_tab =
                                    matches!(target, Some(NavTab::Settings | NavTab::Passkeys));
                                while let Some(tab) = target {
                                    target = match tab {
                                        NavTab::Home => None,
                                        NavTab::Settings => u.run_settings(),
                                        NavTab::Passkeys => u.run_passkeys(),
                                    };
                                }
                                note_activity(); // a browse session just ended — restart clock
                                // "Lock now" inside Settings closes the menu with the lock set;
                                // repaint the Locked screen at once so the menu doesn't linger.
                                if u.locked {
                                    let screen = Screen::Locked;
                                    let _ = rsk_ui::render(&mut u.panel, &screen);
                                    u.shown = Some(screen);
                                } else if opened_tab && !crate::worker::host_request_pending() {
                                    // Closing a tab back to idle repaints Home now (not next
                                    // poll) so it feels instant. Skip if a host command is
                                    // queued — the worker paints next (no stale flash).
                                    let screen = Screen::Home(HomeView {
                                        status: status_to_kind(led::status()),
                                    });
                                    let _ = rsk_ui::render(&mut u.panel, &screen);
                                    u.shown = Some(screen);
                                }
                            }
                        } else {
                            // Idle this tick (no tap, no button): blank once past the
                            // (runtime) sleep timeout — `0` disables sleep. Auto-lock rides
                            // on sleep (enter_sleep), so a manually-locked-but-awake device
                            // still blanks here. Re-read the clock: a tab/menu modal *above*
                            // can run for many seconds, so the top-of-loop `now` would be
                            // stale and underflow against the freshly-bumped activity stamp.
                            let now = Instant::now().as_millis() as u32;
                            let sleep_ms = SLEEP_TIMEOUT_MS.load(Ordering::Relaxed);
                            if sleep_ms != 0
                                && now.wrapping_sub(LAST_ACTIVITY_MS.load(Ordering::Relaxed))
                                    >= sleep_ms
                            {
                                u.enter_sleep();
                            }
                        }
                    }
                }
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
            // A host ceremony can arrive while the panel slept — restore it so the
            // trusted prompt is actually visible, and count it as activity.
            u.wake();
            note_activity();
            let _ = rsk_ui::render(&mut u.panel, &Screen::Confirm(prompt));
            u.shown = None; // force the status loop to repaint once we release it
            // Deny is a single tap; Approve is a deliberate hold that fills the button
            // as it builds (an accidental brush can't approve). The base button was
            // painted by the `render(Screen::Confirm)` above; the fill then grows in
            // place (no per-poll card clear → no flicker). Lifting the finger — or
            // sliding off the button — repaints the base, clearing the fill.
            let mut hold_start: Option<Instant> = None;
            let mut last_num: u16 = 0;
            loop {
                match u.touch.read().and_then(rsk_ui::hit_confirm) {
                    Some(Button::Deny) => break Outcome::Declined,
                    Some(Button::Allow) => {
                        let held = hold_start.get_or_insert_with(Instant::now).elapsed();
                        let num = held.as_millis().min(HOLD_MS) as u16;
                        let _ = rsk_ui::render_hold_fill(
                            &mut u.panel,
                            ALLOW_RECT,
                            "Hold to approve",
                            last_num,
                            num,
                            HOLD_MS as u16,
                            rsk_ui::theme::APPROVE,
                        );
                        last_num = num;
                        if held >= Duration::from_millis(HOLD_MS) {
                            break Outcome::Confirmed;
                        }
                    }
                    // Finger lifted or slid off the buttons: reset a building hold.
                    None => {
                        if hold_start.take().is_some() {
                            let _ = rsk_ui::render_hold_button(
                                &mut u.panel,
                                ALLOW_RECT,
                                "Hold to approve",
                                rsk_ui::theme::APPROVE,
                            );
                            last_num = 0;
                        }
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
        // Hold the ambient status screen back briefly so this modal handing off to
        // another (pad → Approve/Deny) doesn't flash the idle screen between them.
        AMBIENT_QUIET_UNTIL_MS.store(
            (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
            Ordering::Relaxed,
        );
        note_activity(); // a long ceremony shouldn't immediately fall asleep on return
        led::set_status(saved);
        outcome
    }

    /// Collect a PIN on the on-screen pad for the host built-in-UV path (clientPIN 0x06).
    /// The pad loop lives on [`Ui`] (which owns the panel + touch); borrow the shared
    /// `Ui` and run it there, so the host path and a display-initiated gate
    /// ([`Ui::run_delete`]) share one implementation.
    fn collect_pin_impl(&mut self, min_len: usize, out: &mut [u8]) -> rsk_fido::PinEntry {
        self.ui
            .borrow_mut()
            .collect_pin("Enter PIN", None, min_len, out, false)
    }
}

impl rsk_fido::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_fido::Confirm<'_>) -> rsk_fido::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => {
                // A granted WebAuthn approval gets the design's brief "Approved" pop.
                // Scoped to the FIDO ceremony path (one request per make/getAssertion),
                // NOT the shared `confirm_wait`: OpenPGP/PIV touch policies call request()
                // once per signature, so flashing this — and paying its ~0.4 s — on every
                // PGP/PIV op would be both wrong-worded and a latency regression. The
                // `confirm_wait` borrow is already released, so this re-borrow is safe.
                self.ui
                    .borrow_mut()
                    .show_success(SuccessKind::Approved, Some(150));
                rsk_fido::Presence::Confirmed
            }
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
