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

use embassy_rp::gpio::Output;
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C1, SPI1};
use embassy_rp::pwm::{Config as PwmConfig, Pwm};
use embassy_rp::spi::{Blocking as SpiBlocking, Spi};
use embassy_time::{Delay, Duration, Instant, Timer, block_for};
use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::ColorInversion;
use mipidsi::{Builder, Display};
use rsk_crypto::Device;
use rsk_sdk::Confirm;
use rsk_ui::{
    ALLOW_RECT, AccountRow, AdjustKey, BRIGHTNESS_LEVELS, Button, ConfirmPrompt, HomeView, Label,
    NavTab, PinKey, PinPad, RootEntry, RpRow, Screen, SettingsPage, SettingsView, StatusKind,
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

/// Auto-close the settings menu after this long without a tap, returning to idle.
/// While the menu is open it busy-waits on the thread executor, so the worker is
/// parked and a host command waits behind it — this bound caps that to a walked-away
/// user's worst case (and is shorter than a normal touch-confirm wait).
const MENU_INACTIVITY_MS: u64 = 15_000;

/// How long the user must hold the on-screen approve button before it confirms — long
/// enough that an accidental brush can't approve, short enough to feel responsive. The
/// button fills as the hold builds, and lifting the finger early resets it.
const HOLD_MS: u64 = 800;

/// Backlight PWM `top` (8-bit, like the LED): a brightness level maps to a compare
/// value `0..=BL_TOP`.
const BL_TOP: u16 = 255;

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

        Ui {
            panel,
            touch,
            bl,
            tp_rst,
            shown: None,
            info,
            brightness: BRIGHTNESS_LEVELS,
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

    /// Paint a settings page, snapshotting the live brightness/timeout/identity into
    /// the view. Clears `shown` so the ambient loop repaints once the menu releases
    /// the panel.
    fn render_settings(&mut self, page: SettingsPage) {
        let view = SettingsView {
            page,
            brightness: self.brightness,
            timeout_secs: (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            version: self.info.version,
            chipid: self.info.chipid,
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
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                let mut repaint = true;
                match page {
                    SettingsPage::Root => match rsk_ui::hit_settings_root(p) {
                        Some(RootEntry::Brightness) => page = SettingsPage::Brightness,
                        Some(RootEntry::Timeout) => page = SettingsPage::Timeout,
                        Some(RootEntry::Info) => page = SettingsPage::Info,
                        Some(RootEntry::Close) => break,
                        None => repaint = false,
                    },
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
                    SettingsPage::Info => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Back) => page = SettingsPage::Root,
                        _ => repaint = false,
                    },
                }
                // One tap = one action: wait for release (bounded) before the next.
                self.touch.wait_release(last, idle_limit);
                if repaint {
                    self.render_settings(page);
                }
            }
            if last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }

        self.end_modal();
        None
    }

    /// Hand the panel back to the ambient loop on a modal's exit, briefly holding the
    /// status repaint back so a hand-off (modal → idle, or modal → next tab) doesn't
    /// flash a stale frame.
    fn end_modal(&mut self) {
        AMBIENT_QUIET_UNTIL_MS.store(
            (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
            Ordering::Relaxed,
        );
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
        let (n, total) = self.load_rps(&mut rows, &mut hashes);
        self.render_list(&rows[..n], total);
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));

        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let next = loop {
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    match self.run_service(&rows[i as usize].id, &hashes[i as usize]) {
                        ServiceResult::Back => {
                            self.render_list(&rows[..n], total);
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
            if last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One RP's read-only detail: list its resident accounts. The back chevron (or a tap
    /// on the active Passkeys tab) returns to the list; another nav tab leaves the
    /// Passkeys tab; the back chevron only ever returns [`ServiceResult::Back`].
    fn run_service(&mut self, title: &Label, hash: &[u8; 32]) -> ServiceResult {
        let mut accts = [AccountRow::default(); rsk_ui::PK_ROWS_MAX];
        let (n, total) = self.load_accts(hash, &mut accts);
        let _ = rsk_ui::render_service(&mut self.panel, title, &accts[..n], total);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));

        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        loop {
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_pk_back(p) {
                    return ServiceResult::Back;
                }
                if let Some(tab) = rsk_ui::hit_nav(p) {
                    return match tab {
                        // The active tab drills back out to its own list.
                        NavTab::Passkeys => ServiceResult::Back,
                        NavTab::Home => ServiceResult::Leave(None),
                        NavTab::Settings => ServiceResult::Leave(Some(NavTab::Settings)),
                    };
                }
                self.touch.wait_release(last, idle_limit);
            }
            if last.elapsed() >= idle_limit {
                return ServiceResult::Leave(None);
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// Repaint the Passkeys list (a full-frame paint) and mark the panel for the ambient
    /// loop to refresh once the tab closes.
    fn render_list(&mut self, rows: &[RpRow], total: u16) {
        let _ = rsk_ui::render_passkeys_list(&mut self.panel, rows, total);
        self.shown = None;
    }

    /// Enumerate resident RPs into `rows` (+ their rpIdHashes into `hashes`), returning
    /// the kept count and the true total. Reads + decrypts from the shared store; the
    /// seed is loaded and zeroized inside the enumerator (the display never holds it).
    fn load_rps(&self, rows: &mut [RpRow], hashes: &mut [[u8; 32]]) -> (usize, u16) {
        let dev = self.keys.device();
        let mut store = self.fs.borrow_mut();
        let mut n = 0usize;
        let total = rsk_fido::passkeys::for_each_rp(&dev, &mut *store, |rp| {
            if n < rows.len() {
                rows[n] = RpRow {
                    id: Label::clamp(rp.rp_id.as_bytes()),
                    accounts: rp.count,
                };
                hashes[n] = rp.rp_id_hash;
                n += 1;
            }
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// Enumerate the resident accounts under `hash` into `accts`. The label is the user
    /// name, else the display name, else a placeholder (a binary user id is not a legible
    /// label); credProtect ≥ 2 marks the row UV-gated.
    fn load_accts(&self, hash: &[u8; 32], accts: &mut [AccountRow]) -> (usize, u16) {
        let dev = self.keys.device();
        let mut store = self.fs.borrow_mut();
        let mut n = 0usize;
        let total = rsk_fido::passkeys::for_each_cred(&dev, &mut *store, hash, |a| {
            if n < accts.len() {
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
                n += 1;
            }
        });
        (n, total.min(u16::MAX as usize) as u16)
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
        // Skip the ambient repaint while a modal hand-off is in flight, so the
        // status screen never flickers between the pad and the confirm prompt.
        // Wrap-safe deadline check (millis truncated to u32 wrap every ~49 days).
        let now = Instant::now().as_millis() as u32;
        let quiet_over =
            now.wrapping_sub(AMBIENT_QUIET_UNTIL_MS.load(Ordering::Relaxed)) as i32 >= 0;
        if quiet_over && let Ok(mut u) = ui.try_borrow_mut() {
            let kind = status_to_kind(led::status());
            let screen = Screen::Home(HomeView { status: kind });
            if u.shown != Some(screen) {
                let _ = rsk_ui::render(&mut u.panel, &screen);
                u.shown = Some(screen);
            }
            // Interactive idle: a tap on the bottom nav opens a tab. Only while idle —
            // a confirm/PIN modal owns this executor synchronously, so this loop can't
            // even run mid-ceremony to begin with. Each tab modal returns the next nav
            // destination, so the user can switch tab→tab directly (e.g. Passkeys →
            // Settings) without first dropping back to Home.
            if kind == StatusKind::Idle
                && let Some(p) = u.touch.read()
            {
                let mut target = rsk_ui::hit_nav(p);
                while let Some(tab) = target {
                    target = match tab {
                        // Home is the idle ambient screen — end the nav session.
                        NavTab::Home => None,
                        NavTab::Settings => u.run_settings(),
                        NavTab::Passkeys => u.run_passkeys(),
                    };
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
                        // Partial update: only the masked-entry row changes per
                        // keystroke, so repaint just that strip — no full-frame
                        // clear, no flicker.
                        let _ = rsk_ui::render_pin_dots(&mut u.panel, entered);
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
        // Hold the ambient status screen back briefly so this modal handing off to
        // another (pad → Approve/Deny) doesn't flash the idle screen between them.
        AMBIENT_QUIET_UNTIL_MS.store(
            (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
            Ordering::Relaxed,
        );
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
