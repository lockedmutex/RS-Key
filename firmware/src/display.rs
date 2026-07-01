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
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{Dimensions, Point as EgPoint, Size},
    pixelcolor::Rgb565,
    prelude::RgbColor,
    primitives::Rectangle,
};
use embedded_hal_bus::spi::ExclusiveDevice;
use zeroize::Zeroize;

use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::ColorInversion;
use mipidsi::{Builder, Display};
use rsk_crypto::Device;
use rsk_sdk::Confirm;
use rsk_ui::{
    ALLOW_RECT, AccountRow, AdjustKey, AppEntry, AuditRow, BRIGHTNESS_LEVELS, BackupView, Button,
    ConfirmPrompt, DisplayEntry, HomeView, Label, NavTab, PinCaption, PinKey, PinPad, RootEntry,
    RpRow, Screen, SecurityEntry, SettingsPage, SettingsView, StatusKind, SuccessKind,
};

use crate::handler::{FidoRng, Store};
use crate::led;
use crate::presence::{CANCEL_REQUESTED, PRESENCE_TIMEOUT_MS, UP_PENDING};

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;
/// Touch poll cadence during a confirm wait; `block_for` keeps interrupts on, so
/// the high-priority USB executor runs between polls (mirrors the BOOTSEL wait).
const TOUCH_POLL_MS: u64 = 16;

/// Status-spinner arc step per ~100ms status-loop tick (≈1.5s per revolution — the
/// design's ~1.4s request spinner).
const SPIN_STEP_DEG: i32 = 24;
/// Repaint cadence for the on-device keygen spinner. The hook fires far more often than this
/// (once per prime candidate); time-gating to ~100ms keeps the panel repaint off the keygen's
/// hot path so the search isn't slowed by SPI traffic.
const KEYGEN_SPIN_MS: u64 = 100;
/// PIV PIN/PUK length floor for the on-panel change/unblock pads — the PIV minimum (the
/// default PIN `123456` is six). The applet stores up to eight; `rsk_piv::pad_pin` pads the
/// rest to the 8-byte `0xFF` wire form so a host VERIFY (which always pads) matches.
const PIV_PIN_MIN: usize = 6;
/// The locked-hint breathe advances one shade every this many ~100ms status-loop ticks, so
/// the 8-shade ramp cycles in ~2.4s (the design's breathe period).
const BREATHE_TICKS: u32 = 3;
/// Rename caret blink half-period: the caret toggles on/off every this many ms (~1s full
/// cycle, the design's `steps(1)` 1s blink).
const CARET_BLINK_MS: u64 = 500;

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

/// How long a revealed PIN stays shown on the pad without a key press before it auto
/// re-masks, so a device left mid-entry with the PIN revealed doesn't keep the cleartext
/// digits lit for the whole presence timeout.
const REVEAL_MASK_MS: u64 = 4_000;

/// PIN-title marquee: hold the head of an overflowing title visible this long, then scroll
/// one pixel per [`MARQUEE_MS_PER_PX`] ms (≈45 px/s) so a long title like "OpenPGP Sign
/// PIN" reads in full without colliding with the back chevron.
const MARQUEE_PAUSE_MS: u64 = 800;
const MARQUEE_MS_PER_PX: u64 = 22;
/// Bytes for the 1-bit off-screen mask the marquee composites into (one bit per band
/// pixel: set = title glyph, clear = background). The whole band then blits in a single
/// `fill_contiguous` transaction, so the panel never shows the cleared-then-redrawn flash
/// that a direct per-frame clear+draw produces (the reported flicker).
const MARQUEE_MASK_BYTES: usize =
    (rsk_ui::PIN_TITLE_BAND.w as usize * rsk_ui::PIN_TITLE_BAND.h as usize).div_ceil(8);

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

/// Persisted display-settings record: the backlight level and display-sleep timeout
/// edited in Settings → Display, read at boot ([`Ui::build`]) and rewritten on
/// Settings exit ([`Ui::persist_settings`]) so they survive a reboot. In the system
/// config FID range next to `EF_PHY` (`0xE020`) / `EF_META`, outside every applet's
/// reset scope; not reachable by any host APDU. The touch timeout is *not* here — it
/// rides `EF_PHY`'s `PresenceTimeout` tag, the same record `rsk hw --touch-timeout`
/// writes (see [`rsk_ui::DisplayConfig`]).
const EF_DISPLAY: u16 = 0xE030;

/// Device identity shown read-only on the settings Firmware screen + its list row.
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

/// Which PIN a trusted-display gate or set/change flow operates on. The **device PIN**
/// gates local control (unlock, on-device delete, factory reset) and is independent of the
/// **FIDO** clientPIN (WebAuthn / built-in UV). The on-screen pad and verify logic are
/// shared; only the backing record (`EF_DEVICE_PIN` vs `EF_PIN`) and floor differ.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PinScope {
    Device,
    Fido,
}

impl PinScope {
    /// The PIN-screen header for this scope — so every pad names *which* credential it
    /// is collecting (the user's reported confusion: the same bare "Enter PIN" served
    /// the device lock, the FIDO clientPIN, and the PIV PIN). The step (New / Confirm /
    /// current) rides in the caption line, so this stays a stable scope label.
    fn pin_title(self) -> &'static str {
        match self {
            PinScope::Device => "Device PIN",
            PinScope::Fido => "FIDO PIN",
        }
    }
}

/// The PIN-screen header for a PIV reference (the application PIN or the PUK), the
/// PIV analog of [`PinScope::pin_title`]. Matches the CCID secure-PIN path's "PIV PIN"
/// title so a host VERIFY and an on-panel change name the same thing.
fn piv_ref_title(which: rsk_piv::PinRef) -> &'static str {
    match which {
        rsk_piv::PinRef::Pin => "PIV PIN",
        rsk_piv::PinRef::Puk => "PIV PUK",
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

/// A 1-bit off-screen `DrawTarget` over the PIN title band: rsk-ui's `render_pin_title`
/// composites into it (one bit per band pixel — set = a title glyph, clear = background),
/// then the firmware blits the whole band in a single `fill_contiguous`. Because our text
/// is 1-bit (no anti-aliasing) the band is exactly two colours, so a mask captures it
/// losslessly, and the single-transaction blit removes the per-frame clear→draw flash that
/// made the marquee flicker. Coordinates are absolute (panel space) so the generic
/// `render_pin_title` — which draws at the band's real position — lands correctly.
struct BandMask<'a> {
    bits: &'a mut [u8],
    band: Rectangle,
}

impl<'a> BandMask<'a> {
    fn new(bits: &'a mut [u8], band: rsk_ui::Rect) -> Self {
        bits.fill(0);
        Self {
            bits,
            band: Rectangle::new(
                EgPoint::new(band.x as i32, band.y as i32),
                Size::new(band.w as u32, band.h as u32),
            ),
        }
    }
}

impl Dimensions for BandMask<'_> {
    fn bounding_box(&self) -> Rectangle {
        self.band
    }
}

impl DrawTarget for BandMask<'_> {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        let w = self.band.size.width as i32;
        for Pixel(p, c) in pixels {
            let x = p.x - self.band.top_left.x;
            let y = p.y - self.band.top_left.y;
            if x >= 0 && y >= 0 && x < w && (y as u32) < self.band.size.height {
                let idx = y as usize * w as usize + x as usize;
                // The only colours drawn are the background fill and the FG glyph; any
                // non-background pixel is a glyph → set its bit.
                if c != rsk_ui::theme::PANEL_BG {
                    self.bits[idx >> 3] |= 1 << (idx & 7);
                } else {
                    self.bits[idx >> 3] &= !(1 << (idx & 7));
                }
            }
        }
        Ok(())
    }
}

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
    /// Read-only identity shown on the settings Firmware screen.
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
    /// PIN to reopen). Set at boot or on auto-sleep — both only when a PIN is set; cleared
    /// by a correct on-screen PIN. Gates only the panel UI — host CTAP ceremonies (confirm
    /// / built-in-UV) are unaffected and paint their own prompts over it.
    locked: bool,
    /// The first-run onboarding prompt is active: a fresh, PIN-less device that hasn't yet
    /// offered (and had dismissed) the "set a device PIN?" screen. While set, the idle loop
    /// shows [`Screen::Onboard`] instead of Home and a tap routes to [`Ui::run_onboarding`];
    /// cleared once the user sets a PIN or chooses to continue without one. Mutually
    /// exclusive with `locked` (onboarding only exists when no device PIN is set).
    onboarding: bool,
    /// The persisted "continue without a device PIN" choice ([`rsk_ui::DisplayConfig`]'s
    /// `pin_declined`), held so every `EF_DISPLAY` write preserves it. Set true (and flushed)
    /// when the user dismisses onboarding; a factory reset wipes the record back to false.
    pin_declined: bool,
    /// The shared flash store — the same `RefCell` the worker uses. The Passkeys tab
    /// borrows it to enumerate resident credentials; safe because the worker is parked
    /// (it never holds the borrow across an `.await`) while this thread-executor task
    /// runs.
    fs: &'static RefCell<Store>,
    /// Device identity for unboxing the resident-credential seed on demand.
    keys: DeviceKeys,
    /// The shared DRBG — the same `RefCell` the worker uses. Borrowed only to draw the
    /// randomness an on-device SLIP-39 split needs (the share identifier + Shamir random
    /// shares); the worker is parked while this thread-executor task runs, so no race.
    rng: &'static RefCell<FidoRng>,
    /// 1-bit scratch for the flicker-free PIN-title marquee blit ([`BandMask`]).
    marquee_mask: [u8; MARQUEE_MASK_BYTES],
    /// Cached Home status-card facts (device-PIN-set + resident passkey count), refreshed
    /// by [`Ui::refresh_home_stats`] only at modal boundaries — boot, wake, a closed tab
    /// modal — so the idle Home frame never triggers a per-paint flash enumeration.
    home_pin_set: bool,
    home_passkeys: u16,
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
        rng: &'static RefCell<FidoRng>,
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

        // Restore the persisted display settings before lighting the panel, so it
        // comes up at the saved brightness (no full-bright flash then dim) and the
        // saved sleep timeout. Absent (fresh device) keeps the live defaults.
        let mut dcfg = rsk_ui::DisplayConfig::default();
        {
            let mut buf = [0u8; rsk_ui::DISPLAY_CONF_LEN];
            if let Some(n) = fs.borrow_mut().read(EF_DISPLAY, &mut buf) {
                dcfg.apply_block(&buf[..n.min(buf.len())]);
            }
        }
        SLEEP_TIMEOUT_MS.store(dcfg.sleep_secs as u32 * 1000, Ordering::Relaxed);
        let brightness = dcfg.brightness.clamp(1, BRIGHTNESS_LEVELS);

        // Backlight up to the saved level only now there is something to show (it was
        // built at zero duty, so the panel stayed dark through init — no white flash).
        bl.set_config(&backlight_cfg(level_duty(brightness)));

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
        let locked = rsk_fido::passkeys::device_pin_is_set(&mut fs.borrow_mut());
        // A fresh, PIN-less device that hasn't already had the prompt dismissed comes up on
        // the onboarding screen offering to set a device PIN (declining is remembered in
        // `EF_DISPLAY`, so it's a one-time first-run offer). Mutually exclusive with `locked`.
        let onboarding = !locked && !dcfg.pin_declined;

        Ui {
            panel,
            touch,
            bl,
            tp_rst,
            shown: None,
            info,
            brightness,
            asleep: false,
            wake_btn,
            locked,
            onboarding,
            pin_declined: dcfg.pin_declined,
            fs,
            keys,
            rng,
            marquee_mask: [0; MARQUEE_MASK_BYTES],
            // Seeded from the cheap PIN bit (== `locked`); the count is filled by the first
            // `refresh_home_stats` before Home is ever painted.
            home_pin_set: locked,
            home_passkeys: 0,
        }
    }

    /// Refresh the Home status-card facts — whether a device PIN is set and how many
    /// resident passkeys are stored — into the cache the idle Home frame reads. Enumerates
    /// flash (the seed-unboxing RP walk), so it runs only at modal boundaries (boot, wake,
    /// a closed tab modal), never per idle frame: a per-paint partition scan would stall the
    /// panel, the lesson the PIV `has_data` lag taught. Borrow-safe like [`Self::load_rps`]
    /// (the worker is parked while this thread-executor task runs).
    fn refresh_home_stats(&mut self) {
        let dev = self.keys.device();
        let mut store = self.fs.borrow_mut();
        self.home_pin_set = rsk_fido::passkeys::device_pin_is_set(&mut store);
        let mut creds = 0u16;
        let _ = rsk_fido::passkeys::for_each_rp(&dev, &mut store, |rp| {
            creds = creds.saturating_add(rp.count as u16);
        });
        self.home_passkeys = creds;
    }

    /// Composite one marquee frame of `title` (scrolled by `off` px) into the 1-bit mask,
    /// then blit the whole title band in a single `fill_contiguous` — no per-frame
    /// clear→draw flash, so the scroll is flicker-free. Only called for titles that
    /// overflow the band; a fitting title is drawn once, centred, by `render`.
    fn render_marquee_frame(&mut self, title: &str, off: u32) {
        let band = rsk_ui::PIN_TITLE_BAND;
        let Self {
            panel,
            marquee_mask,
            ..
        } = self;
        {
            let mut mask = BandMask::new(marquee_mask, band);
            let _ = rsk_ui::render_pin_title(&mut mask, title, off);
        }
        let area = Rectangle::new(
            EgPoint::new(band.x as i32, band.y as i32),
            Size::new(band.w as u32, band.h as u32),
        );
        let n = band.w as usize * band.h as usize;
        let colors = (0..n).map(|i| {
            if marquee_mask[i >> 3] & (1 << (i & 7)) != 0 {
                rsk_ui::theme::TEXT
            } else {
                rsk_ui::theme::PANEL_BG
            }
        });
        let _ = panel.fill_contiguous(&area, colors);
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
        if rsk_fido::passkeys::device_pin_is_set(&mut self.fs.borrow_mut()) {
            self.locked = true;
        }
        self.sleep();
    }

    /// The on-screen unlock flow, reached by a tap on the Locked screen. Reuses the
    /// device-PIN gate (the `EF_DEVICE_PIN` retry ladder, same as the destructive-action
    /// gate): a correct PIN drops the lock, a wrong one re-prompts until the right PIN, a
    /// cancel / timeout, or the counter is spent — all of which leave it locked. Returns
    /// the panel to [`status_task`], which then paints Home (unlocked) or Locked again.
    fn run_unlock(&mut self) {
        // Let the unlock tap's finger lift before the pad starts reading digits.
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        // `local_pin_gate` returns true with no device PIN set; that can only happen here if
        // EF_DEVICE_PIN vanished after the lock — only via a touch-confirmed host
        // authenticatorReset (clears it in place) or the device-PIN-gated on-device factory
        // reset (reboots). Both are authorized resets, so "no PIN ⇒ unlock" is the correct
        // post-reset behaviour (nothing to verify against), never a bypass.
        if self.local_pin_gate(PinScope::Device) {
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
        // Read every store-backed flag under ONE borrow: multiple `self.fs.borrow_mut()`
        // temporaries in a single expression all live to the end of the statement, so a
        // second one would panic the RefCell (`already borrowed`).
        let (device_pin_set, fido_pin_set, backup_sealed) = {
            let mut fs = self.fs.borrow_mut();
            (
                rsk_fido::passkeys::device_pin_is_set(&mut fs),
                rsk_fido::passkeys::pin_is_set(&mut fs),
                rsk_fido::passkeys::backup_sealed(&mut fs),
            )
        };
        let view = SettingsView {
            page,
            brightness: self.brightness,
            timeout_secs: (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            sleep_secs: (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            version: self.info.version,
            chipid: self.info.chipid,
            device_pin_set,
            fido_pin_set,
            backup_sealed,
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
        // before polling so it isn't read as the first menu tap. The Root page now carries
        // the four-tab nav (Settings is a top-level tab), so it returns the next nav
        // destination like the other tabs; sub-pages still exit via their back chevron.
        let mut page = SettingsPage::Root;
        self.render_settings(page);
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);

        // Track whether the user actually changed a knob, so the persist on exit is one
        // flash write per editing session (on every exit path), not one per −/+ tap.
        let mut display_dirty = false;
        let mut presence_dirty = false;

        let next = loop {
            // The power button sleeps from inside the menu too, not just on Home.
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                let mut repaint = true;
                match page {
                    SettingsPage::Root => {
                        // The bottom nav switches tabs directly (Settings is a top-level tab
                        // now): Home → idle, the others hand off to that tab's modal.
                        if let Some(tab) = rsk_ui::hit_nav(p) {
                            match tab {
                                NavTab::Settings => repaint = false,
                                NavTab::Home => break None,
                                NavTab::Passkeys => break Some(NavTab::Passkeys),
                                NavTab::Apps => break Some(NavTab::Apps),
                            }
                        } else {
                            match rsk_ui::hit_settings_root(p) {
                                // Display drills into the brightness / sleep / touch-timeout
                                // panel knobs.
                                Some(RootEntry::Display) => page = SettingsPage::Display,
                                // Security drills into the Set/Change PIN + Factory reset
                                // sub-page (the destructive reset now lives one tap deeper).
                                Some(RootEntry::Security) => page = SettingsPage::Security,
                                // Firmware (last): drill into the installed-version +
                                // reboot-to-update sub-flow. A completed update hold queues a
                                // reboot and returns `true` — break out of the menu so the
                                // ambient loop can park and hand the executor to the worker,
                                // which scrubs + resets. A cancel falls back to this list.
                                Some(RootEntry::Firmware) => {
                                    if self.run_firmware() {
                                        break None;
                                    }
                                    last = Instant::now();
                                }
                                None => repaint = false,
                            }
                        }
                    }
                    SettingsPage::Display => {
                        // The title-bar back chevron returns to the Root list; each row drills
                        // into its −/+ adjust page (which backs out to here).
                        if rsk_ui::hit_title_back(p) {
                            page = SettingsPage::Root;
                        } else {
                            match rsk_ui::hit_display(p) {
                                Some(DisplayEntry::Brightness) => page = SettingsPage::Brightness,
                                Some(DisplayEntry::Sleep) => page = SettingsPage::Sleep,
                                Some(DisplayEntry::Timeout) => page = SettingsPage::Timeout,
                                None => repaint = false,
                            }
                        }
                    }
                    SettingsPage::Security => {
                        // The title-bar back chevron returns to the Root list.
                        if rsk_ui::hit_title_back(p) {
                            page = SettingsPage::Root;
                        } else {
                            match rsk_ui::hit_security(p) {
                                Some(SecurityEntry::DevicePin) => {
                                    self.run_set_pin(PinScope::Device);
                                    last = Instant::now();
                                }
                                Some(SecurityEntry::FidoPin) => {
                                    self.run_set_pin(PinScope::Fido);
                                    last = Instant::now();
                                }
                                Some(SecurityEntry::PivPin) => {
                                    self.run_piv_pins();
                                    last = Instant::now();
                                }
                                Some(SecurityEntry::AuditLog) => {
                                    self.run_auditlog();
                                    last = Instant::now();
                                }
                                Some(SecurityEntry::Backup) => {
                                    self.run_backup();
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
                            let was = self.brightness;
                            self.set_brightness(rsk_ui::step_brightness(self.brightness, -1));
                            display_dirty |= self.brightness != was;
                        }
                        Some(AdjustKey::Plus) => {
                            let was = self.brightness;
                            self.set_brightness(rsk_ui::step_brightness(self.brightness, 1));
                            display_dirty |= self.brightness != was;
                        }
                        Some(AdjustKey::Back) => page = SettingsPage::Display,
                        None => repaint = false,
                    },
                    SettingsPage::Timeout => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Minus) => presence_dirty |= adjust_timeout(-1),
                        Some(AdjustKey::Plus) => presence_dirty |= adjust_timeout(1),
                        Some(AdjustKey::Back) => page = SettingsPage::Display,
                        None => repaint = false,
                    },
                    SettingsPage::Sleep => match rsk_ui::hit_adjust(p) {
                        Some(AdjustKey::Minus) => display_dirty |= adjust_sleep(-1),
                        Some(AdjustKey::Plus) => display_dirty |= adjust_sleep(1),
                        Some(AdjustKey::Back) => page = SettingsPage::Display,
                        None => repaint = false,
                    },
                }
                // A sub-modal (e.g. the audit log) may have slept + locked via the power
                // button; if so, unwind without repainting over the now-blanked panel —
                // status_task owns the asleep/Locked state from here.
                if self.asleep {
                    break None;
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
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };

        self.persist_settings(display_dirty, presence_dirty);
        self.end_modal();
        next
    }

    /// Persist the display settings the user edited so they survive a reboot. Called
    /// once on Settings exit (every exit path — Back, a tab switch, the inactivity
    /// timeout, the power button), not per −/+ tap, so a tweak costs one flash write
    /// rather than one per step. Brightness + display-sleep live in `EF_DISPLAY`; the
    /// touch timeout shares `EF_PHY`'s `PresenceTimeout` tag with
    /// `rsk hw --touch-timeout`, so it is read-modify-written there (preserving the
    /// other phy fields) to keep a single source of truth — last writer wins, and an
    /// on-panel edit snaps to the menu's choices, so it overwrites a custom value a
    /// host set. Synchronous, like the other display-task flash writes — the worker is
    /// parked while this runs.
    fn persist_settings(&mut self, save_display: bool, save_presence: bool) {
        if save_display {
            self.save_display_config();
        }
        if save_presence {
            let secs = (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u8;
            let mut fs = self.fs.borrow_mut();
            let mut phy = rsk_rescue::phy::load(&mut fs).unwrap_or_default();
            phy.presence_timeout = Some(secs);
            let _ = rsk_rescue::phy::save(&mut fs, &phy);
        }
    }

    /// Write the live display settings (brightness + sleep) plus the persisted
    /// `pin_declined` flag to `EF_DISPLAY` in one record. Every `EF_DISPLAY` write goes
    /// through here so the onboarding flag is never dropped by a brightness/sleep save (and
    /// vice-versa) — the record carries all three fields. Synchronous; the worker is parked.
    fn save_display_config(&mut self) {
        let cfg = rsk_ui::DisplayConfig {
            brightness: self.brightness,
            sleep_secs: (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            pin_declined: self.pin_declined,
        };
        let _ = self.fs.borrow_mut().put(EF_DISPLAY, &cfg.encode());
    }

    /// Handle a tap on the first-run onboarding screen ([`Screen::Onboard`]). **Set a PIN**
    /// opens the device-PIN set flow; if a PIN ends up set, onboarding is done (and the
    /// device is unlocked for this session — the user just proved presence). **Continue
    /// without PIN** records the choice in `EF_DISPLAY` so the prompt is never shown again
    /// (until a factory reset), then drops to Home. A tap that misses both buttons, or a
    /// queued host command / timeout reaching here, leaves onboarding pending — it re-shows
    /// on the next idle frame, so the offer is never silently lost. `p` is the opening tap.
    fn run_onboarding(&mut self, p: rsk_ui::Point) {
        match rsk_ui::hit_onboard(p) {
            Some(rsk_ui::OnboardChoice::SetPin) => {
                // `run_set_pin` waits for the opening finger to lift, gates (a no-op with no
                // PIN set yet), then collects New + Confirm; it writes only on a match.
                self.run_set_pin(PinScope::Device);
                if rsk_fido::passkeys::device_pin_is_set(&mut self.fs.borrow_mut()) {
                    self.onboarding = false;
                    self.refresh_home_stats();
                }
            }
            Some(rsk_ui::OnboardChoice::Skip) => {
                self.pin_declined = true;
                self.save_display_config();
                self.onboarding = false;
                // Refresh the Home cache before the caller paints Home: a host ceremony can
                // have added/removed a resident passkey while the panel sat on Onboard (it
                // paints over Onboard without consulting `onboarding`), so the count could be
                // stale — the same reason the unlock path refreshes. (The SetPin branch above
                // already refreshes.)
                self.refresh_home_stats();
                // Let the choosing finger lift before the next idle read paints Home, so the
                // same touch isn't re-read as a nav tap.
                self.touch
                    .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
            }
            None => {}
        }
        self.end_modal();
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
                        NavTab::Apps => break Some(NavTab::Apps),
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
                        NavTab::Apps => ServiceResult::Leave(Some(NavTab::Apps)),
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

    /// Snapshot the per-applet item counts for the Apps chooser. One borrow covers all
    /// three reads (the device is taken first, so the OATH unseal-walk and the `fs` borrow
    /// don't overlap). Borrow-safe like [`Self::load_rps`] — the worker is parked here.
    fn load_apps(&self) -> rsk_ui::AppsView {
        let dev = self.keys.device();
        let mut fs = self.fs.borrow_mut();
        let openpgp_keys = rsk_openpgp::info::read_info(&mut fs).key_count();
        let piv_slots = rsk_piv::info::read_info(&mut fs).populated();
        let oath_codes =
            rsk_oath::for_each_cred(&dev, &mut fs, |_| {}).min(u16::MAX as usize) as u16;
        rsk_ui::AppsView {
            openpgp_keys,
            piv_slots,
            oath_codes,
        }
    }

    /// The Apps tab: a chooser for the credential applets. Reuses the tab modal shape — a
    /// drill-in per applet, the bottom nav for direct tab switches, the power button to
    /// sleep, and a break the moment a host command queues so a browse never starves the
    /// worker. Returns the next nav destination (`None` = back to idle Home).
    fn run_apps(&mut self) -> Option<NavTab> {
        let view = self.load_apps();
        let _ = rsk_ui::render_apps(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if let Some(entry) = rsk_ui::hit_apps(p) {
                    let leave = match entry {
                        AppEntry::OpenPgp => self.run_openpgp(),
                        AppEntry::Piv => self.run_piv(),
                        AppEntry::Oath => self.run_oath(),
                    };
                    if self.asleep {
                        break None;
                    }
                    if leave.is_some() {
                        break leave;
                    }
                    // Back from an applet: re-snapshot (a host op may have run while parked)
                    // and repaint the chooser.
                    let view = self.load_apps();
                    let _ = rsk_ui::render_apps(&mut self.panel, &view);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => {}
                        NavTab::Home => break None,
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// Build the OpenPGP overview from the applet's plaintext metadata (no PIN / DEK).
    fn load_openpgp(&self) -> rsk_ui::OpenpgpView {
        let mut fs = self.fs.borrow_mut();
        let info = rsk_openpgp::info::read_info(&mut fs);
        let mut slots = [rsk_ui::PgpSlotRow::default(); 3];
        for (i, s) in info.slots.iter().enumerate() {
            slots[i] = rsk_ui::PgpSlotRow {
                present: s.present,
                algo: if s.present {
                    Label::clamp(s.algo.label().as_bytes())
                } else {
                    Label::default()
                },
                touch: s.touch,
            };
        }
        let cardholder_name = Label::clamp(rsk_openpgp::info::read_cardholder(&mut fs).name());
        rsk_ui::OpenpgpView {
            slots,
            cardholder_name,
            sig_count: info.sig_count,
            pw1: info.pw1_retries,
            pw3: info.pw3_retries,
        }
    }

    /// Build the OpenPGP card-holder detail (name / login / URL / language), all plaintext.
    fn load_openpgp_cardholder(&self) -> rsk_ui::CardholderView {
        let mut fs = self.fs.borrow_mut();
        let ch = rsk_openpgp::info::read_cardholder(&mut fs);
        rsk_ui::CardholderView {
            name: Label::clamp(ch.name()),
            login: Label::clamp(ch.login()),
            url: Label::clamp(ch.url()),
            lang: Label::clamp(ch.lang()),
            any: ch.any(),
        }
    }

    /// Build one OpenPGP key's detail (algorithm / touch / fingerprint).
    fn load_openpgp_key(&self, slot: usize) -> rsk_ui::PgpKeyView {
        let mut fs = self.fs.borrow_mut();
        let s = rsk_openpgp::info::read_info(&mut fs).slots[slot];
        rsk_ui::PgpKeyView {
            slot: slot as u8,
            present: s.present,
            algo: Label::clamp(s.algo.label().as_bytes()),
            touch: s.touch,
            created: s.created,
            fingerprint: s.fingerprint.unwrap_or([0u8; 20]),
            has_fp: s.fingerprint.is_some(),
        }
    }

    /// The OpenPGP overview (read-only): the three key slots + a drill-in to each present
    /// slot's detail. Same modal shape as [`Self::run_apps`]; `None` returns to the Apps
    /// chooser, `Some(tab)` leaves the hub to that tab.
    fn run_openpgp(&mut self) -> Option<NavTab> {
        let view = self.load_openpgp();
        let _ = rsk_ui::render_openpgp(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break None;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, rsk_ui::OPENPGP_ROWS) {
                    // Rows 0..2 are the key slots (each drills in — an empty slot's detail
                    // explains its role); row 3 opens the card-holder detail.
                    if (i as usize) < view.slots.len() {
                        self.run_openpgp_key(i as usize);
                    } else {
                        self.run_openpgp_cardholder();
                    }
                    if self.asleep {
                        break None;
                    }
                    let _ = rsk_ui::render_openpgp(&mut self.panel, &view);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => break None,
                        NavTab::Home => break Some(NavTab::Home),
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One OpenPGP key's detail screen (back-only, no nav). Read-only; back chevron / power
    /// button / a queued host command / inactivity all return to the overview.
    fn run_openpgp_key(&mut self, slot: usize) {
        let view = self.load_openpgp_key(slot);
        let _ = rsk_ui::render_openpgp_key(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// The OpenPGP card-holder detail screen (back-only, no nav). Read-only; back chevron /
    /// power button / a queued host command / inactivity all return to the overview.
    fn run_openpgp_cardholder(&mut self) {
        let view = self.load_openpgp_cardholder();
        let _ = rsk_ui::render_openpgp_cardholder(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// Build the PIV overview from the applet's slot metadata (no PIN / management key).
    fn load_piv(&self) -> rsk_ui::PivView {
        let mut fs = self.fs.borrow_mut();
        let info = rsk_piv::info::read_info(&mut fs);
        let mut slots = [rsk_ui::PivSlotRow::default(); 4];
        for (i, s) in info.slots.iter().enumerate() {
            slots[i] = rsk_ui::PivSlotRow {
                slot: s.slot,
                present: s.present,
                cert: s.cert,
                algo: if s.present {
                    Label::clamp(rsk_piv::info::algo_name(s.algo).as_bytes())
                } else {
                    Label::default()
                },
            };
        }
        let extra = rsk_piv::info::extra_count(&mut fs);
        rsk_ui::PivView {
            slots,
            extra,
            pin: info.pin_retries,
            puk: info.puk_retries,
        }
    }

    /// Build one PIV slot's detail (algorithm / policies / origin / cert) by wire slot —
    /// any slot, primary or retired / F9.
    fn load_piv_slot(&self, slot: u8) -> rsk_ui::PivSlotView {
        let mut fs = self.fs.borrow_mut();
        let s = rsk_piv::info::read_slot(&mut fs, slot);
        rsk_ui::PivSlotView {
            slot: s.slot,
            present: s.present,
            cert: s.cert,
            algo: Label::clamp(rsk_piv::info::algo_name(s.algo).as_bytes()),
            pin_policy: Label::clamp(rsk_piv::info::pin_policy_name(s.pin_policy).as_bytes()),
            touch_policy: Label::clamp(rsk_piv::info::touch_policy_name(s.touch_policy).as_bytes()),
            origin: Label::clamp(rsk_piv::info::origin_name(s.origin).as_bytes()),
        }
    }

    /// The PIV overview (read-only): the four primary slots + a drill-in to each populated
    /// slot's detail. Mirrors [`Self::run_openpgp`].
    fn run_piv(&mut self) -> Option<NavTab> {
        let view = self.load_piv();
        let _ = rsk_ui::render_piv(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break None;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, rsk_ui::PIV_ROWS) {
                    // Rows 0..3 are the primary slots (each drills in — an empty slot's
                    // detail explains its role); row 4 opens the retired / F9 screen.
                    if (i as usize) < view.slots.len() {
                        self.run_piv_slot(view.slots[i as usize].slot);
                    } else {
                        self.run_piv_extra();
                    }
                    if self.asleep {
                        break None;
                    }
                    let view = self.load_piv();
                    let _ = rsk_ui::render_piv(&mut self.panel, &view);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                } else if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => break None,
                        NavTab::Home => break Some(NavTab::Home),
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// One PIV slot's detail screen (back-only, no nav). Read-only. `slot` is the wire
    /// reference (primary `0x9A…`, retired `0x82…0x95`, or F9).
    fn run_piv_slot(&mut self, slot: u8) {
        let view = self.load_piv_slot(slot);
        let _ = rsk_ui::render_piv_slot(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// Build one page of the "Retired & F9" list: every populated retired slot + F9, then a
    /// trailing "Generate key" action row when a retired slot is free. Returns the kept count
    /// and the true total (slots + the optional action).
    fn load_piv_extra(&self, rows: &mut [rsk_ui::PivExtraRow], page: u16) -> (usize, u16) {
        let mut fs = self.fs.borrow_mut();
        let mut slots = [rsk_piv::info::PivSlot::default(); rsk_piv::info::MAX_EXTRA_SLOTS];
        let nslots = rsk_piv::info::read_extra(&mut fs, &mut slots);
        let can_gen = rsk_piv::info::next_free_retired(&mut fs).is_some();
        let total = nslots + can_gen as usize;
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut n = 0;
        let mut i = offset;
        while i < total && n < rows.len() {
            rows[n] = if i < nslots {
                let s = slots[i];
                rsk_ui::PivExtraRow {
                    slot: s.slot,
                    present: s.present,
                    cert: s.cert,
                    algo: if s.present {
                        Label::clamp(rsk_piv::info::algo_name(s.algo).as_bytes())
                    } else {
                        Label::default()
                    },
                    generate: false,
                }
            } else {
                rsk_ui::PivExtraRow {
                    generate: true,
                    ..Default::default()
                }
            };
            n += 1;
            i += 1;
        }
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// The "Retired & F9" screen (back-only): the populated retired slots + F9, paged, each
    /// drilling into the shared slot-detail, plus a "Generate key" action when a slot is free.
    /// Mirrors [`Self::run_oath`] — pager, sleep, host-yield; no nav (a sub-screen of PIV).
    fn run_piv_extra(&mut self) {
        let mut rows = [rsk_ui::PivExtraRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_piv_extra(&mut rows, page);
        let _ = rsk_ui::render_piv_extra(&mut self.panel, &rows[..n], page, total);
        self.shown = None;
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_piv_extra(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_piv_extra(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    let row = rows[i as usize];
                    if row.generate {
                        self.run_piv_generate();
                    } else {
                        self.run_piv_slot(row.slot);
                    }
                    if self.asleep {
                        break;
                    }
                    let r = self.load_piv_extra(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_piv_extra(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
    }

    /// The on-device PIV key-generate flow (from the "Retired & F9" screen's Generate row):
    /// target the next free retired slot, gate on the device PIN (when set), pick an EC curve,
    /// require a deliberate hold, then generate + seal the key. EC only — RSA's prime search
    /// would block the panel. Physical presence here is the authorisation (no management key),
    /// and generation only ever *adds* a key to an empty slot. Returns when done or cancelled.
    fn run_piv_generate(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let slot = match rsk_piv::info::next_free_retired(&mut self.fs.borrow_mut()) {
            Some(s) => s,
            None => return,
        };
        // PIN gate first (when set) so the chooser doesn't flash behind the pad.
        if !self.local_pin_gate(PinScope::Device) {
            return;
        }
        // Algorithm chooser: the curves are instant; the RSA row drills into a size
        // sub-picker (2048/3072/4096), each run by the firmware's dual-core prime search.
        let algo = loop {
            let _ = rsk_ui::render_piv_keygen_pick(&mut self.panel, slot);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            // `None` selects the RSA row (open the size sub-picker); `Some` is a concrete algo.
            let main_pick = loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        return;
                    }
                    if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PIV_KEYGEN_PICK_TOP, 5) {
                        break match i {
                            0 => Some((rsk_piv::files::ALGO_ECCP256, "NIST P-256")),
                            1 => Some((rsk_piv::files::ALGO_ECCP384, "NIST P-384")),
                            2 => Some((rsk_piv::files::ALGO_ED25519, "Ed25519")),
                            3 => Some((rsk_piv::files::ALGO_X25519, "X25519")),
                            _ => None,
                        };
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            };
            if let Some(a) = main_pick {
                break a;
            }
            // RSA size sub-picker; its back chevron returns to the main chooser.
            let _ = rsk_ui::render_piv_keygen_rsa_pick(&mut self.panel, slot);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            let sub_pick = loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        break None;
                    }
                    if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PIV_KEYGEN_PICK_TOP, 3) {
                        break Some(match i {
                            0 => (rsk_piv::files::ALGO_RSA2048, "RSA 2048"),
                            1 => (rsk_piv::files::ALGO_RSA3072, "RSA 3072"),
                            _ => (rsk_piv::files::ALGO_RSA4096, "RSA 4096"),
                        });
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            };
            if let Some(a) = sub_pick {
                break a;
            }
            // Otherwise the user backed out of the sub-picker — re-show the main chooser.
        };
        // A deliberate hold before the write.
        let _ = rsk_ui::render_piv_keygen_confirm(&mut self.panel, slot, algo.1);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if !self.hold_to_confirm("Hold to generate", rsk_ui::theme::ACCENT_FILL) {
            return;
        }
        // The keygen + seal holds the dev/rng/fs borrows across a synchronous, no-await
        // span, so the worker can't preempt and the borrows stay safe. The free slot is
        // re-checked under the borrow in case state moved while the chooser was open.
        let rsa_nbits = match algo.0 {
            rsk_piv::files::ALGO_RSA2048 => Some(2048usize),
            rsk_piv::files::ALGO_RSA3072 => Some(3072),
            rsk_piv::files::ALGO_RSA4096 => Some(4096),
            _ => None,
        };
        let ok = if let Some(nbits) = rsa_nbits {
            // RSA's prime search is slow (seconds for 2048, up to minutes for 4096): paint a
            // "generating" screen, then run it dual-core. The search is a blocking busy-loop
            // (no await), so the panel can't repaint on its own — instead the search's per-
            // candidate hook spins the indicator arc (throttled to KEYGEN_SPIN_MS) so it reads
            // as actively working, not hung. USB + CCID keepalives stay interrupt-driven.
            let _ = rsk_ui::render_piv_keygen_working(&mut self.panel);
            self.shown = None;
            let key = {
                let mut rng = self.rng.borrow_mut();
                let panel = &mut self.panel;
                let mut spin = rsk_ui::STATUS_ARC_START;
                let mut last_paint = Instant::now();
                let mut tick = || {
                    if last_paint.elapsed() >= Duration::from_millis(KEYGEN_SPIN_MS) {
                        spin = spin.wrapping_add(SPIN_STEP_DEG);
                        let _ = rsk_ui::render_status_arc(panel, StatusKind::Processing, spin);
                        last_paint = Instant::now();
                    }
                };
                crate::core1::run_rsa_search_progress(nbits, &mut *rng, &mut tick)
            };
            match key {
                Some(key) => {
                    let dev = self.keys.device();
                    let mut rng = self.rng.borrow_mut();
                    let mut fs = self.fs.borrow_mut();
                    match rsk_piv::info::next_free_retired(&mut fs) {
                        Some(s) => {
                            rsk_piv::info::store_retired_rsa(&dev, &mut fs, &mut *rng, s, &key)
                                .is_ok()
                        }
                        None => false,
                    }
                }
                None => false,
            }
        } else {
            // EC / Ed25519 / X25519 are instant.
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            match rsk_piv::info::next_free_retired(&mut fs) {
                Some(s) => {
                    rsk_piv::info::generate_slot_key(&dev, &mut fs, &mut *rng, s, algo.0).is_ok()
                }
                None => false,
            }
        };
        if ok {
            self.show_success(SuccessKind::Generated, Some(1100));
        }
    }

    /// Enumerate stored OATH credentials into `rows` (one page), returning the kept count
    /// and the true total. Each credential is device-unsealed inside the enumerator (the
    /// display never holds the secret); borrow-safe like [`Self::load_rps`].
    fn load_oath(&self, rows: &mut [rsk_ui::OathRow], page: u16) -> (usize, u16) {
        let dev = self.keys.device();
        let offset = page as usize * rsk_ui::PK_ROWS_MAX;
        let mut fs = self.fs.borrow_mut();
        let mut idx = 0usize;
        let mut n = 0usize;
        let total = rsk_oath::for_each_cred(&dev, &mut fs, |c| {
            if idx >= offset && n < rows.len() {
                rows[n] = rsk_ui::OathRow {
                    name: Label::clamp(c.name),
                    hotp: c.hotp,
                    touch: c.touch,
                };
                n += 1;
            }
            idx += 1;
        });
        (n, total.min(u16::MAX as usize) as u16)
    }

    /// The OATH list (read-only): one row per stored credential, paged. No code is shown
    /// (the device has no clock for TOTP); the footer points at the host app. Mirrors
    /// [`Self::run_passkeys`] — pager, nav, sleep, host-yield.
    fn run_oath(&mut self) -> Option<NavTab> {
        let mut rows = [rsk_ui::OathRow::default(); rsk_ui::PK_ROWS_MAX];
        let mut page: u16 = 0;
        let (mut n, mut total) = self.load_oath(&mut rows, page);
        let _ = rsk_ui::render_oath(&mut self.panel, &rows[..n], page, total);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        let next = loop {
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break None;
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = paged(page, total, k);
                    let r = self.load_oath(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_oath(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PK_LIST_TOP, n as u16) {
                    // Drill into the credential's detail (paged index → global position).
                    self.run_oath_cred(page as usize * rsk_ui::PK_ROWS_MAX + i as usize);
                    if self.asleep {
                        break None;
                    }
                    let r = self.load_oath(&mut rows, page);
                    n = r.0;
                    total = r.1;
                    let _ = rsk_ui::render_oath(&mut self.panel, &rows[..n], page, total);
                    self.shown = None;
                    self.touch.wait_release(Instant::now(), idle_limit);
                    last = Instant::now();
                    continue;
                }
                if let Some(tab) = rsk_ui::hit_nav(p) {
                    match tab {
                        NavTab::Apps => break None,
                        NavTab::Home => break Some(NavTab::Home),
                        NavTab::Passkeys => break Some(NavTab::Passkeys),
                        NavTab::Settings => break Some(NavTab::Settings),
                    }
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };
        self.end_modal();
        next
    }

    /// Build one OATH credential's detail by its global list position. Re-enumerates (the
    /// display holds no secret), clamps the picked credential's metadata for display.
    fn load_oath_cred(&self, idx: usize) -> rsk_ui::OathDetailView {
        let dev = self.keys.device();
        let mut fs = self.fs.borrow_mut();
        let mut view = rsk_ui::OathDetailView::default();
        let mut i = 0usize;
        rsk_oath::for_each_cred(&dev, &mut fs, |c| {
            if i == idx {
                view = rsk_ui::OathDetailView {
                    name: Label::clamp(c.name),
                    hotp: c.hotp,
                    algo: Label::clamp(rsk_oath::algo_name(c.algo).as_bytes()),
                    digits: c.digits,
                    period: c.period,
                    touch: c.touch,
                };
            }
            i += 1;
        });
        view
    }

    /// One OATH credential's detail screen (back-only, no nav). Read-only; back chevron /
    /// power button / a queued host command / inactivity all return to the list.
    fn run_oath_cred(&mut self, idx: usize) {
        let view = self.load_oath_cred(idx);
        let _ = rsk_ui::render_oath_cred(&mut self.panel, &view);
        self.shown = None;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        self.end_modal();
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
        // Blink the field caret: a full render leaves it on, then it toggles every
        // `CARET_BLINK_MS` via the in-place [`render_rename_caret`].
        let mut caret_on = true;
        let mut blink_at = Instant::now();
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
                    // A fresh frame draws the caret on — restart the blink from there.
                    caret_on = true;
                    blink_at = Instant::now();
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            if blink_at.elapsed() >= Duration::from_millis(CARET_BLINK_MS) {
                caret_on = !caret_on;
                let v = val(&buf, len);
                let _ = rsk_ui::render_rename_caret(&mut self.panel, v.as_str(), caret_on);
                blink_at = Instant::now();
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

    /// The read-only on-device backup status (Settings → Security → Backup): snapshot the
    /// seed-backup flags and show them until the back chevron, the power button (sleeps +
    /// locks), a queued host command, or the inactivity timeout. Synchronous like the other
    /// browse modals (the worker is parked); read-only — no tap mutates anything and it
    /// shows no secret, only whether a recovery seed is present and its export window sealed.
    /// Snapshot the seed-backup status into the view model. `can_reveal` decides whether the
    /// on-device recovery-phrase + seal actions are offered: only while the window is open and
    /// the seed is actually readable (present, exportable build, not soft-locked).
    fn load_backup(&self) -> BackupView {
        // Both reads under ONE borrow (multiple `borrow_mut()` in one statement would panic).
        let (st, device_pin_set) = {
            let mut fs = self.fs.borrow_mut();
            (
                rsk_fido::passkeys::backup_status(&mut fs),
                rsk_fido::passkeys::device_pin_is_set(&mut fs),
            )
        };
        BackupView {
            sealed: st.sealed,
            has_seed: st.has_seed,
            exportable: st.exportable,
            // The reveal exposes the master secret, so it requires a device PIN to be set (the
            // hold is the second factor, not the only one); the seal shares the gate. Without a
            // device PIN the device never locks, so a bare hold would let anyone with physical
            // access read the seed.
            can_reveal: st.has_seed && st.exportable && !st.sealed && !st.locked && device_pin_set,
        }
    }

    /// The Backup screen (Settings → Security → Backup): the seed-backup status, plus — while
    /// the window is open — the on-device **Show recovery phrase** and **Seal backup** actions.
    /// The phrase is shown on the trusted panel and never crosses USB. Reloads the status after
    /// each action so a seal flips the screen to sealed. Synchronous (worker parked); the back
    /// chevron, power button, a queued host command, or the inactivity timeout exit.
    fn run_backup(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        'screen: loop {
            let view = self.load_backup();
            let _ = rsk_ui::render_backup(&mut self.panel, &view);
            self.shown = None;
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
                    if view.can_reveal
                        && let Some(k) = rsk_ui::hit_backup(p)
                    {
                        match k {
                            rsk_ui::BackupKey::Reveal => self.run_reveal_recovery(),
                            rsk_ui::BackupKey::Seal => self.run_seal_backup(),
                        }
                        if self.asleep {
                            return; // a sub-modal slept + locked via the power button
                        }
                        continue 'screen; // reload status (a seal flips it) and repaint
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }
    }

    /// Reveal the recovery seed on the trusted display — read and rendered **on-device**, never
    /// over USB. Gated by the device PIN (re-auth before any secret is shown), then a format
    /// chooser: a single 24-word BIP-39 phrase, or `T`-of-`N` SLIP-39 Shamir shares. The PIN is
    /// entered once; the chooser re-shows after each format flow so the user can view both. The
    /// back chevron / power button / a queued host command / the inactivity timeout exit.
    fn run_reveal_recovery(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        // Re-authenticate with the device PIN before any recovery secret is shown (no PIN set
        // returns true at once; a wrong PIN / decline / timeout aborts with nothing revealed).
        if !self.local_pin_gate(PinScope::Device) {
            return;
        }
        'chooser: loop {
            let _ = rsk_ui::render_backup_format(&mut self.panel);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_pk_back(p) {
                        return;
                    }
                    if let Some(fmt) = rsk_ui::hit_backup_format(p) {
                        match fmt {
                            rsk_ui::BackupFormat::Phrase => self.reveal_phrase(),
                            rsk_ui::BackupFormat::Shares => self.reveal_shares(),
                        }
                        if self.asleep {
                            return; // a sub-modal slept + locked via the power button
                        }
                        continue 'chooser; // re-show the chooser after the format flow
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }
    }

    /// Show the 24-word BIP-39 recovery phrase (the chooser's "Single phrase" choice). A
    /// deliberate hold over the warning, then the paged words. The seed is zeroized the instant
    /// the indices are derived; the indices + word slots on exit, and the screen auto-clears on
    /// the inactivity timeout (walked-away guard). The device PIN was already checked.
    fn reveal_phrase(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let _ = rsk_ui::render_reveal_warning(&mut self.panel, rsk_ui::RevealKind::Phrase);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if !self.hold_to_confirm("Hold to reveal", rsk_ui::theme::DANGER_FILL) {
            return;
        }
        // Read + derive. The seed lives only long enough to compute the indices, then is wiped.
        let dev = self.keys.device();
        let mut seed_opt = {
            let mut fs = self.fs.borrow_mut();
            rsk_fido::passkeys::load_keydev(&dev, &mut fs)
        };
        let mut indices = match seed_opt {
            // `Option<[u8;32]>` is `Copy`, so this copies the seed out — derive, then wipe BOTH
            // the copy here and the original `seed_opt` below, or a seed remnant lingers.
            Some(mut seed) => {
                let idx = rsk_bip39::entropy_to_indices(&seed);
                seed.zeroize();
                idx
            }
            None => return, // no seed / soft-locked — nothing to show
        };
        seed_opt.zeroize();
        let mut words: [&str; rsk_bip39::WORD_COUNT] = [""; rsk_bip39::WORD_COUNT];
        for (w, &i) in words.iter_mut().zip(indices.iter()) {
            *w = rsk_bip39::word(i);
        }
        let pages: u16 = 2;
        let mut page: u16 = 0;
        let _ = rsk_ui::render_seed_phrase(&mut self.panel, &words, page, pages);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        let mut last = Instant::now();
        loop {
            if self.sleep_button_pressed() {
                break;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                if rsk_ui::hit_title_back(p) {
                    break;
                }
                if let Some(k) = rsk_ui::hit_pager(p) {
                    page = match k {
                        rsk_ui::PagerKey::Prev => page.saturating_sub(1),
                        rsk_ui::PagerKey::Next => (page + 1).min(pages - 1),
                    };
                    let _ = rsk_ui::render_seed_phrase(&mut self.panel, &words, page, pages);
                    self.shown = None;
                    self.touch.wait_release(last, idle_limit);
                    last = Instant::now();
                    continue;
                }
                self.touch.wait_release(last, idle_limit);
            }
            // A queued host command or the idle timeout exits + wipes — the master secret must
            // never linger on a walked-away panel.
            if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
        // Wipe both secrets from RAM: the indices (the canonical secret) via `Zeroize`, and the
        // word slots (which also encode the order) via a black-boxed fill so it isn't elided.
        indices.zeroize();
        words.fill("");
        let _ = core::hint::black_box(&words);
        note_activity();
        self.end_modal();
    }

    /// Show the recovery seed as `T`-of-`N` SLIP-39 Shamir shares (the chooser's "Shamir
    /// shares" choice). A `T`/`N` picker (default 2-of-3), a deliberate hold over the warning,
    /// then the shares page-by-page **on-device** (never over USB). The shares are split from
    /// the device DRBG and are bit-for-bit recombinable by `rsk backup restore --scheme
    /// slip39`. The seed is wiped the instant the shares are derived; the share words on exit.
    fn reveal_shares(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let (mut threshold, mut total): (u8, u8) = (2, 3); // default 2-of-3
        'picker: loop {
            let _ = rsk_ui::render_share_picker(&mut self.panel, threshold, total);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_pk_back(p) {
                        return; // back to the format chooser
                    }
                    if let Some(k) = rsk_ui::hit_share_picker(p) {
                        if k == rsk_ui::ShareAdjust::Continue {
                            break 'picker;
                        }
                        let (t, n) = rsk_ui::step_share_params(threshold, total, k);
                        threshold = t;
                        total = n;
                        continue 'picker; // re-render the picker with the new values
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }

        // A deliberate hold over the warning before any secret is shown.
        self.touch.wait_release(Instant::now(), idle_limit);
        let _ = rsk_ui::render_reveal_warning(&mut self.panel, rsk_ui::RevealKind::Shares);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if !self.hold_to_confirm("Hold to reveal", rsk_ui::theme::DANGER_FILL) {
            return;
        }

        // Read the seed and split it on-device; the seed lives only long enough to generate the
        // shares, then is wiped (both the copied-out seed and the original `Option`).
        let dev = self.keys.device();
        let mut seed_opt = {
            let mut fs = self.fs.borrow_mut();
            rsk_fido::passkeys::load_keydev(&dev, &mut fs)
        };
        let mut shares = [[0u16; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES];
        let ok = match seed_opt {
            Some(mut seed) => {
                let r = {
                    let mut rng = self.rng.borrow_mut();
                    let mut fill = |b: &mut [u8]| rsk_fido::Rng::fill(&mut *rng, b);
                    rsk_slip39::generate(&seed, threshold, total, &mut fill, &mut shares)
                };
                seed.zeroize();
                r.is_ok()
            }
            None => false, // no seed / soft-locked — nothing to show
        };
        seed_opt.zeroize();
        if ok {
            self.show_shares(&shares, total);
        }
        shares.zeroize();
        note_activity();
        self.end_modal();
    }

    /// Page through the generated SLIP-39 shares: "Share i/N" with that share's words, a global
    /// pager walking every share's pages in order (3 pages of ≤12 words per 33-word share). The
    /// back chevron / power button / a queued host command / the inactivity timeout exit; the
    /// word slots are wiped on exit (the caller zeroizes the share indices).
    fn show_shares(
        &mut self,
        shares: &[[u16; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES],
        total: u8,
    ) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let total = total as u16;
        let per_share: u16 = (rsk_slip39::WORDS_PER_SHARE as u16).div_ceil(12); // 3 pages/share
        let pages = total * per_share;
        let mut words: [&str; rsk_slip39::WORDS_PER_SHARE] = [""; rsk_slip39::WORDS_PER_SHARE];
        let mut page: u16 = 0;
        let mut shown_share = u16::MAX;
        'paged: loop {
            let share = page / per_share;
            if share != shown_share {
                for (w, &i) in words.iter_mut().zip(shares[share as usize].iter()) {
                    *w = rsk_slip39::word(i);
                }
                shown_share = share;
            }
            let _ =
                rsk_ui::render_slip39_share(&mut self.panel, &words, share + 1, total, page, pages);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle_limit);
            let mut last = Instant::now();
            loop {
                if self.sleep_button_pressed() {
                    break 'paged;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        break 'paged;
                    }
                    if let Some(k) = rsk_ui::hit_pager(p) {
                        page = match k {
                            rsk_ui::PagerKey::Prev => page.saturating_sub(1),
                            rsk_ui::PagerKey::Next => (page + 1).min(pages - 1),
                        };
                        continue 'paged; // repaint (rebuilds words when the share changes)
                    }
                    self.touch.wait_release(last, idle_limit);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle_limit {
                    break 'paged;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            }
        }
        // The share words encode the (secret) share order — wipe the slots on exit. A
        // black-boxed fill so the compiler can't elide it; the indices are the caller's to wipe.
        words.fill("");
        let _ = core::hint::black_box(&words);
    }

    /// Seal the backup window on-device (Settings → Security → Backup → Seal backup): a
    /// deliberate hold, then write the seal marker so the seed can no longer be shown or
    /// exported until a factory reset. Exposes no secret, so a hold (not the PIN) gates it;
    /// Settings access is already device-PIN-locked.
    fn run_seal_backup(&mut self) {
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        let _ = rsk_ui::render_seal_confirm(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if self.hold_to_confirm("Hold to seal", rsk_ui::theme::DANGER_FILL) {
            let _ = rsk_fido::passkeys::mark_backup_sealed(&mut self.fs.borrow_mut());
        }
        self.end_modal();
    }

    /// The on-device Firmware flow (Settings → Firmware): show the installed build and the
    /// honest update story, then take a deliberate (blue) hold to reboot into the BOOTSEL
    /// bootloader so the RS-Key host app can flash a new signed image. The signature is only
    /// verified by the boot ROM when secure boot is fused, so the screen reads the *real* OTP
    /// state and states the check as fact only then. The back chevron, a slid-off finger, or
    /// the inactivity timeout abandon it without rebooting. On a completed hold it *queues* a
    /// secure reboot rather than calling the ROM directly: the worker owns the live RAM
    /// secrets (FIDO auth state, the DRBG), so only it can scrub them before dropping to
    /// BOOTSEL. Returns `true` once a reboot is queued so the caller exits the menu — the
    /// worker shares this thread-mode executor and only runs once this busy-waiting UI yields,
    /// so the ambient loop must park (on `reboot_pending`) and hand the executor over to it.
    fn run_firmware(&mut self) -> bool {
        use rsk_rescue::Platform as _;
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle_limit);
        // A pure OTP read (no flash / no shared borrow) — true only on a fused, secure-boot
        // device, where the boot ROM actually verifies the image signature on next boot.
        let secure_boot = crate::rescue_platform::RescuePlatform
            .secure_boot_status()
            .enabled;
        let _ = rsk_ui::render_firmware(
            &mut self.panel,
            self.info.version,
            self.info.chipid,
            secure_boot,
        );
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);
        if self.hold_to_confirm("Verify & install", rsk_ui::theme::ACCENT_FILL) {
            let _ = rsk_ui::render_rebooting(&mut self.panel);
            crate::vendor::request_reboot(true);
            return true;
        }
        self.end_modal();
        false
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
    /// release; OK commits only at/above `min_len`, Del backspaces, Cancel declines, and the
    /// eye toggle reveals/hides the typed digits (auto re-masking after a short idle). The
    /// entered digits are the caller's to zeroize after verifying.
    ///
    /// `yield_to_host`: on a *local* gate (delete / factory-reset / unlock) no host is
    /// waiting on this PIN, so a queued host command must not be starved while the user
    /// types — set it `true` to abandon entry ([`PinEntry::Cancelled`], no retry burned)
    /// the instant a command arrives, mirroring the browse modals. The host built-in-UV
    /// path sets it `false`: there the host *is* waiting on this exact PIN (its `REQ` is
    /// already consumed), so it blocks to the presence timeout as before.
    ///
    /// `expected` is the number of placeholder dots the entry row outlines before any are
    /// filled (the policy minimum length) — the design's fixed indicator. The caller
    /// supplies it rather than this fn re-reading `fs`, because the host built-in-UV path
    /// runs while the worker already holds `fs` borrowed (a re-read there would panic).
    fn collect_pin(
        &mut self,
        title: &'static str,
        caption: Option<PinCaption>,
        min_len: usize,
        expected: u8,
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
        // The entry starts masked; the eye toggle flips this. `last_input` tracks the last
        // key so a revealed PIN can auto re-mask after a short idle.
        let mut reveal = false;
        let mut last_input = Instant::now();

        // A built-in-UV PIN entry can arrive while the panel slept — restore it first.
        self.wake();
        note_activity();
        let _ = rsk_ui::render(
            &mut self.panel,
            &Screen::Pin(PinPad::with_caption(entered, title, caption).expecting(expected)),
        );
        self.shown = None; // force the status loop to repaint once we release it
        // A title too wide for the band (e.g. "OpenPGP Sign PIN") scrolls as a marquee so
        // it can't slide under the back chevron; a short one stays centred and static.
        let scroll_title = rsk_ui::pin_title_overflows(title);
        let mut last_off = u32::MAX; // != any real offset, so the first frame always draws
        let outcome = loop {
            if scroll_title {
                let ms = start.elapsed().as_millis();
                let off = (ms.saturating_sub(MARQUEE_PAUSE_MS) / MARQUEE_MS_PER_PX) as u32;
                // Redraw only when the scroll actually advances a pixel (the loop polls far
                // faster than the marquee moves), so the blit — and SPI traffic — is minimal.
                if off != last_off {
                    self.render_marquee_frame(title, off);
                    last_off = off;
                }
            }
            if let Some(p) = self.touch.read() {
                last_input = Instant::now();
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
                    Some(PinKey::Reveal) => {
                        reveal = !reveal;
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
                    let shown = if reveal { Some(&out[..entered]) } else { None };
                    let _ = rsk_ui::render_pin_dots(&mut self.panel, entered, expected, shown);
                }
                self.touch.wait_release(start, timeout);
                if let Some(o) = done {
                    break o;
                }
            }
            // Auto re-mask a revealed PIN after a short idle (a walked-away device must not
            // keep the cleartext digits lit until the presence timeout).
            if reveal && last_input.elapsed() >= Duration::from_millis(REVEAL_MASK_MS) {
                reveal = false;
                let _ = rsk_ui::render_pin_dots(&mut self.panel, entered, expected, None);
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

    /// Gate a destructive local action behind a PIN when one is set: collect it on the pad
    /// and verify it against the chosen `scope`'s record and retry counter (the device PIN
    /// for local control, or the FIDO clientPIN for the FIDO-PIN change flow). A wrong entry
    /// re-prompts with a "Wrong PIN, N left" caption until the right PIN, a decline /
    /// timeout, or the counter is spent. Returns whether the action may proceed (`true` =
    /// no PIN of that scope set, or the correct PIN was entered).
    fn local_pin_gate(&mut self, scope: PinScope) -> bool {
        let title = scope.pin_title();
        let (retries, expected) = {
            let mut fs = self.fs.borrow_mut();
            let is_set = match scope {
                PinScope::Device => rsk_fido::passkeys::device_pin_is_set(&mut fs),
                PinScope::Fido => rsk_fido::passkeys::pin_is_set(&mut fs),
            };
            if !is_set {
                return true;
            }
            let retries = match scope {
                PinScope::Device => rsk_fido::passkeys::device_pin_retries_left(&mut fs),
                PinScope::Fido => rsk_fido::passkeys::pin_retries_left(&mut fs),
            };
            // The placeholder-dot count: the FIDO PIN shows its `minPINLength` policy; the
            // device PIN has no host policy, so it shows the compile-time MIN_PIN_LENGTH
            // floor (4 by default, 6 under `fips-profile`) — the floor `store_device_pin`
            // enforces. The OK floor stays 4 (below) — these can differ, hence the arg.
            let expected = match scope {
                PinScope::Device => rsk_fido::passkeys::MIN_PIN_LENGTH,
                PinScope::Fido => rsk_fido::passkeys::min_pin_length(&mut fs),
            };
            (retries, expected)
        };
        let mut pin = [0u8; 64];
        // Show the remaining attempts up front (the design's enterpin "N tries
        // remaining"); a wrong entry then swaps it for the danger "Wrong PIN, N left".
        let mut caption = retries.map(|left| PinCaption::TriesRemaining { left });
        let mut blocked = false;
        let proceed = loop {
            // CTAP's 4-digit floor; the verify checks the exact PIN regardless, so a higher
            // `minPINLength` policy is still satisfied by typing it in full. (A PIN set
            // before the policy was raised may be shorter than `expected`.)
            match self.collect_pin(title, caption, 4, expected, &mut pin, true) {
                rsk_fido::PinEntry::Entered(len) => {
                    let dev = self.keys.device();
                    let verdict = match scope {
                        PinScope::Device => rsk_fido::passkeys::verify_device_pin(
                            &dev,
                            &mut self.fs.borrow_mut(),
                            &pin[..len.min(pin.len())],
                        ),
                        PinScope::Fido => rsk_fido::passkeys::verify_local_pin(
                            &dev,
                            &mut self.fs.borrow_mut(),
                            &pin[..len.min(pin.len())],
                        ),
                    };
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
    /// command), so the lockout — recoverable only by a host-side reset — is explained. Each
    /// scope has its own persistent counter (the device PIN's `EF_DEVICE_PIN`, the FIDO
    /// clientPIN's `EF_PIN`); a host `authenticatorReset` clears both.
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
        if !self.local_pin_gate(PinScope::Device) {
            return; // no PIN, wrong PIN, or declined — nothing removed
        }
        // The destructive-action screen: name the rp + account, then require the hold.
        let _ = rsk_ui::render_confirm_delete(&mut self.panel, rp, account);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        if self.hold_to_confirm("Hold to delete", rsk_ui::theme::DANGER_FILL) {
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
    /// the button caption and `fill` its solid base colour (red [`rsk_ui::theme::DANGER_FILL`]
    /// for the destructive / reveal holds, blue [`rsk_ui::theme::ACCENT_FILL`] for the firmware
    /// update); the lighter progress wash is derived from it inside `render_hold_fill`.
    fn hold_to_confirm(&mut self, label: &str, fill: Rgb565) -> bool {
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
                        fill,
                    );
                    last_num = num;
                    if held >= Duration::from_millis(HOLD_MS) {
                        return true;
                    }
                }
            }
            // Finger lifted or slid off the button: reset a building hold.
            if !on_hold && hold_start.take().is_some() {
                let _ =
                    rsk_ui::render_hold_button(&mut self.panel, rsk_ui::DEL_HOLD_RECT, label, fill);
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
        if !self.local_pin_gate(PinScope::Device) {
            return; // no PIN set is fine; a wrong PIN or decline aborts — nothing erased
        }
        // The destructive-action screen, then a deliberate hold to commit.
        let _ = rsk_ui::render_confirm_factory_reset(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle_limit);

        if self.hold_to_confirm("Hold to wipe", rsk_ui::theme::DANGER_FILL) {
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

    /// The on-device Set / Change PIN flow for `target` (Settings → Security → Device/FIDO
    /// PIN). When that PIN is already set it is verified first via [`local_pin_gate`] (so a
    /// change still proves knowledge of the current PIN; a first-time set returns at once
    /// with no prompt), then the new PIN is entered twice and the two must match before it
    /// is written with a fresh retry budget. The **device** PIN goes to its own
    /// `EF_DEVICE_PIN` (independent local-control PIN, the compile-time `MIN_PIN_LENGTH`
    /// floor); the **FIDO** PIN goes to `EF_PIN` as the same verifier the host
    /// setPIN/changePIN path stores (so the host then sees a clientPIN unchanged,
    /// `minPINLength` floor). A wrong current PIN,
    /// a decline, a timeout, or a queued host command abandons it without a write; a
    /// mismatch clears both entries and re-prompts. Synchronous (the worker is parked).
    fn run_set_pin(&mut self, target: PinScope) {
        // Let the Security-row tap's finger lift before the pad reads digits.
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        if !self.local_pin_gate(target) {
            return; // wrong current PIN, decline, timeout, or host yield — nothing changed
        }
        // The device PIN has no host policy → the compile-time MIN_PIN_LENGTH floor (4, or 6
        // under `fips-profile`) that `store_device_pin` enforces, so a set the user types is
        // actually stored; the FIDO PIN honours `minPINLength` so a panel-set clientPIN stays
        // host-usable.
        let min = match target {
            PinScope::Device => rsk_fido::passkeys::MIN_PIN_LENGTH as usize,
            PinScope::Fido => {
                rsk_fido::passkeys::min_pin_length(&mut self.fs.borrow_mut()) as usize
            }
        };
        // Size the pad buffers to the host-representable maximum so the pad can't accept a
        // digit beyond it (`collect_pin` caps at `out.len()`); a PIN chosen here is then
        // always one the store path can verify, and the store re-checks.
        let mut new = [0u8; rsk_fido::passkeys::MAX_PIN_LENGTH];
        let mut confirm = [0u8; rsk_fido::passkeys::MAX_PIN_LENGTH];
        // The header names the scope ("Device PIN" / "FIDO PIN"); the step rides in the
        // caption — a muted "Choose a PIN" on the first entry, "Re-enter to confirm" on the
        // second, or the danger-coloured "PINs don't match" after a mismatch.
        let title = target.pin_title();
        let mut new_caption = Some(PinCaption::ChoosePin);
        loop {
            new.zeroize();
            confirm.zeroize();
            let expected = min.min(u8::MAX as usize) as u8;
            let n1 = match self.collect_pin(title, new_caption, min, expected, &mut new, true) {
                rsk_fido::PinEntry::Entered(n) => n.min(new.len()),
                _ => break, // declined / timeout / host yield — nothing set
            };
            let n2 = match self.collect_pin(
                title,
                Some(PinCaption::Reenter),
                min,
                expected,
                &mut confirm,
                true,
            ) {
                rsk_fido::PinEntry::Entered(n) => n.min(confirm.len()),
                _ => break, // confirm declined / timeout / host yield
            };
            if n1 == n2 && rsk_crypto::ct_eq(&new[..n1], &confirm[..n2]) {
                let dev = self.keys.device();
                // The pad already enforced the length floor; a flash error is the only
                // realistic failure and leaves no PIN set — abandon either way. Route to the
                // device PIN's own record or the FIDO clientPIN's by target.
                let _ = match target {
                    PinScope::Device => rsk_fido::passkeys::store_device_pin(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        &new[..n1],
                    ),
                    PinScope::Fido => rsk_fido::passkeys::store_local_pin(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        &new[..n1],
                    ),
                };
                break;
            }
            // Mismatch: re-prompt from "New PIN" with the reason; the loop clears both.
            new_caption = Some(PinCaption::Mismatch);
        }
        new.zeroize();
        confirm.zeroize();
        self.end_modal();
    }

    /// The PIV PIN/PUK sub-menu (Settings → Security → "PIV PIN"): change the PIV PIN, change
    /// the PUK, or unblock a blocked PIN with the PUK. A modal picker like the keygen chooser;
    /// the title-bar chevron backs out to the Security list. Each op is gated by knowledge of
    /// the current PIN/PUK — exactly the host APDU's authorisation, no device-PIN gate.
    fn run_piv_pins(&mut self) {
        let idle = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle);
        // Materialise the PIV defaults if no host has ever selected the applet — a display
        // unit used only for FIDO never triggers the lazy first-SELECT scan, so EF_PIN / EF_PUK
        // / EF_RETRIES wouldn't exist for the gate to verify against (it would dead-end on the
        // missing retry counter). Idempotent: every step is has-data guarded.
        {
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            let _ = rsk_piv::files::scan_files(&dev, &mut fs, &mut *rng);
        }
        loop {
            let _ = rsk_ui::render_piv_pin_menu(&mut self.panel);
            self.shown = None;
            self.touch.wait_release(Instant::now(), idle);
            let mut last = Instant::now();
            let pick = loop {
                if self.sleep_button_pressed() {
                    return;
                }
                if let Some(p) = self.touch.read() {
                    last = Instant::now();
                    if rsk_ui::hit_title_back(p) {
                        return;
                    }
                    if let Some(i) = rsk_ui::hit_list(p, rsk_ui::PIV_KEYGEN_PICK_TOP, 4) {
                        break i;
                    }
                    self.touch.wait_release(last, idle);
                }
                if crate::worker::host_request_pending() || last.elapsed() >= idle {
                    return;
                }
                block_for(Duration::from_millis(TOUCH_POLL_MS));
            };
            match pick {
                0 => self.run_change_piv_ref(rsk_piv::PinRef::Pin),
                1 => self.run_change_piv_ref(rsk_piv::PinRef::Puk),
                2 => self.run_unblock_piv_pin(),
                _ => self.run_protect_mgm_key(),
            }
            // Each sub-flow ends in a success pop or a cancel; re-show this menu afterwards.
        }
    }

    /// Collect and verify the current PIV PIN or PUK on the pad, re-prompting with the
    /// remaining-attempts caption until it's right, the user backs out, or the counter is
    /// spent. Returns the secret padded to the 8-byte PIV wire form on success (for the
    /// following change/unblock), or `None` on cancel / timeout / blocked (the latter shows
    /// the lockout notice). The retry counter is the PIV applet's own (`EF_RETRIES`).
    fn gate_piv_ref(&mut self, which: rsk_piv::PinRef, buf: &mut [u8]) -> Option<[u8; 8]> {
        let title = piv_ref_title(which);
        let mut caption = rsk_piv::reference_retries_left(&mut self.fs.borrow_mut(), which)
            .map(|left| PinCaption::TriesRemaining { left });
        loop {
            let n =
                match self.collect_pin(title, caption, PIV_PIN_MIN, PIV_PIN_MIN as u8, buf, true) {
                    rsk_fido::PinEntry::Entered(n) => n.min(buf.len()),
                    _ => return None,
                };
            // `n <= buf.len() == 8`, so `pad_pin` only returns `None` defensively. The padded
            // copy is the cleartext current secret — zeroize it on every path (the PUK is the
            // recovery secret), matching `run_set_pin` / `collect_new_piv_pin` hygiene.
            let mut pad = rsk_piv::pad_pin(&buf[..n])?;
            let sw = {
                let dev = self.keys.device();
                rsk_piv::verify_reference(&dev, &mut self.fs.borrow_mut(), which, &pad)
            };
            if sw == rsk_sdk::Sw::OK {
                let out = pad;
                pad.zeroize();
                return Some(out);
            }
            if sw == rsk_sdk::Sw::PIN_BLOCKED {
                pad.zeroize();
                self.show_pin_blocked();
                return None;
            }
            let left =
                rsk_piv::reference_retries_left(&mut self.fs.borrow_mut(), which).unwrap_or(0);
            caption = Some(PinCaption::WrongPin { retries_left: left });
            pad.zeroize();
        }
    }

    /// Collect a new PIV PIN/PUK twice on the pad and return it padded to the wire form, or
    /// `None` on cancel / timeout / host-yield. The `title` names the scope ("PIV PIN" /
    /// "PIV PUK"); the New vs Confirm step rides in the caption (a muted "Choose a PIN" then
    /// "Re-enter to confirm"). A New ≠ Confirm mismatch re-prompts in place; both pad buffers
    /// are zeroized on every iteration and at exit.
    fn collect_new_piv_pin(&mut self, title: &'static str) -> Option<[u8; 8]> {
        let mut new = [0u8; 8];
        let mut confirm = [0u8; 8];
        let mut new_caption = Some(PinCaption::ChoosePin);
        let out = loop {
            new.zeroize();
            confirm.zeroize();
            let n1 = match self.collect_pin(
                title,
                new_caption,
                PIV_PIN_MIN,
                PIV_PIN_MIN as u8,
                &mut new,
                true,
            ) {
                rsk_fido::PinEntry::Entered(n) => n.min(new.len()),
                _ => break None,
            };
            let n2 = match self.collect_pin(
                title,
                Some(PinCaption::Reenter),
                PIV_PIN_MIN,
                PIV_PIN_MIN as u8,
                &mut confirm,
                true,
            ) {
                rsk_fido::PinEntry::Entered(n) => n.min(confirm.len()),
                _ => break None,
            };
            if n1 == n2 && rsk_crypto::ct_eq(&new[..n1], &confirm[..n2]) {
                break rsk_piv::pad_pin(&new[..n1]);
            }
            new_caption = Some(PinCaption::Mismatch);
        };
        new.zeroize();
        confirm.zeroize();
        out
    }

    /// Change the PIV application PIN or PUK from the panel: verify the current value, then
    /// collect the new one twice. Both are padded to the PIV wire form so a host VERIFY (which
    /// always pads to 8 with `0xFF`) accepts the result. Mirrors [`Self::run_set_pin`] but
    /// against the PIV applet's own PIN/PUK records, not the device/FIDO PIN.
    fn run_change_piv_ref(&mut self, which: rsk_piv::PinRef) {
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut cur = [0u8; 8];
        let gated = self.gate_piv_ref(which, &mut cur);
        cur.zeroize();
        let mut cur_pad = match gated {
            Some(p) => p,
            None => {
                self.end_modal();
                return;
            }
        };
        let applied = match self.collect_new_piv_pin(piv_ref_title(which)) {
            Some(mut new_pad) => {
                let sw = {
                    let dev = self.keys.device();
                    rsk_piv::change_reference(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        which,
                        &cur_pad,
                        &new_pad,
                    )
                };
                new_pad.zeroize();
                sw == rsk_sdk::Sw::OK
            }
            None => false,
        };
        cur_pad.zeroize();
        if applied {
            self.show_success(SuccessKind::Approved, Some(1100));
        } else {
            self.end_modal();
        }
    }

    /// Unblock a blocked PIV PIN with the PUK (Settings → Security → PIV PIN → Unblock PIN):
    /// verify the PUK, then set a new PIN — the on-device RESET RETRY COUNTER. The shared
    /// `unblock_pin_with_puk` resets the PIN's retry counter on success.
    fn run_unblock_piv_pin(&mut self) {
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut puk = [0u8; 8];
        let gated = self.gate_piv_ref(rsk_piv::PinRef::Puk, &mut puk);
        puk.zeroize();
        let mut puk_pad = match gated {
            Some(p) => p,
            None => {
                self.end_modal();
                return;
            }
        };
        let applied = match self.collect_new_piv_pin(piv_ref_title(rsk_piv::PinRef::Pin)) {
            Some(mut new_pad) => {
                let sw = {
                    let dev = self.keys.device();
                    rsk_piv::unblock_pin_with_puk(
                        &dev,
                        &mut self.fs.borrow_mut(),
                        &puk_pad,
                        &new_pad,
                    )
                };
                new_pad.zeroize();
                sw == rsk_sdk::Sw::OK
            }
            None => false,
        };
        puk_pad.zeroize();
        if applied {
            self.show_success(SuccessKind::Approved, Some(1100));
        } else {
            self.end_modal();
        }
    }

    /// "Protect management key" (Settings → Security → PIV PIN → Protect mgmt key): generate a
    /// fresh random AES-256 management key, seal it, and mark it PIN-protected (ykman
    /// `--protect`) so a host can use it with just the PIV PIN. Gated by the device PIN (when
    /// set) and a deliberate hold — physical presence at the trusted panel is the authorisation
    /// (no management-key auth). It REPLACES the current management key, and afterwards the PIV
    /// PIN alone grants PIV admin (the confirm screen states this).
    fn run_protect_mgm_key(&mut self) {
        let idle = Duration::from_millis(MENU_INACTIVITY_MS);
        self.touch.wait_release(Instant::now(), idle);
        // Materialise the PIV defaults first (a never-host-selected display unit) so the host
        // can later VERIFY the PIN to read the protected key. Idempotent.
        {
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            let _ = rsk_piv::files::scan_files(&dev, &mut fs, &mut *rng);
        }
        if !self.local_pin_gate(PinScope::Device) {
            return;
        }
        let _ = rsk_ui::render_piv_protect_confirm(&mut self.panel);
        self.shown = None;
        self.touch.wait_release(Instant::now(), idle);
        if !self.hold_to_confirm("Hold to protect", rsk_ui::theme::ACCENT_FILL) {
            return;
        }
        // The generate + seal holds the dev/rng/fs borrows across a synchronous, no-await span
        // (no key search — AES key gen is instant), so the worker can't preempt.
        let ok = {
            let dev = self.keys.device();
            let mut rng = self.rng.borrow_mut();
            let mut fs = self.fs.borrow_mut();
            rsk_piv::protect_mgm_key(&dev, &mut fs, &mut *rng) == rsk_sdk::Sw::OK
        };
        if ok {
            self.show_success(SuccessKind::Approved, Some(1100));
        } else {
            self.end_modal();
        }
    }
}

/// Step the live presence/touch timeout to the next/previous menu choice and store
/// it (the seconds → ms atomic the waits read). [`Ui::persist_settings`] writes the
/// new value back to the phy record's `PresenceTimeout` tag on Settings exit, so it
/// survives a reboot (the same tag `rsk hw --touch-timeout` and boot both read).
/// Returns whether the value actually changed, so a no-op tap at a clamp boundary
/// doesn't mark the session dirty (and thus doesn't trigger a redundant flash write).
fn adjust_timeout(delta: i8) -> bool {
    let cur = (PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_timeout(cur, delta);
    PRESENCE_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
    next != cur
}

/// Step the display-sleep timeout from the menu (−/+). `0` seconds = Off (never blanks).
/// Returns whether the value actually changed (see [`adjust_timeout`]).
fn adjust_sleep(delta: i8) -> bool {
    let cur = (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_sleep(cur, delta);
    SLEEP_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
    next != cur
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
    // Prime the Home status-card cache once before the first idle paint (boot has settled
    // the flash; the worker is parked here while this task runs, so the borrow is safe).
    ui.borrow_mut().refresh_home_stats();
    // Liveness animation state: the spinner arc angle (advanced while busy) and the
    // locked-hint breathe phase (advanced every few ticks), plus a tick counter to pace
    // the breathe. These pulse a small region on top of the already-painted frame, so
    // they never trigger a full repaint and can't flicker the idle hot path.
    let mut spin = rsk_ui::STATUS_ARC_START;
    let mut breathe: u8 = 0;
    let mut tick: u32 = 0;
    loop {
        // A Settings → Firmware update queued a reboot: stop driving the panel and just yield
        // so the worker (same thread-mode executor) gets scheduled to scrub the live secrets
        // and reset to BOOTSEL on its next tick. Parking here — before any repaint — keeps the
        // "Rebooting" notice on screen instead of flashing Home over it.
        if crate::vendor::reboot_pending() {
            Timer::after_millis(10).await;
            continue;
        }
        tick = tick.wrapping_add(1);
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
                    // Wake to the Locked screen if the device locked on sleep, or the
                    // onboarding screen on a fresh PIN-less device; the wake gesture only
                    // wakes (it isn't read as the unlock/onboard tap — that comes after
                    // release). Otherwise wake straight to Home.
                    let screen = if u.locked {
                        Screen::Locked
                    } else if u.onboarding {
                        Screen::Onboard
                    } else {
                        // Woke from sleep: a host ceremony may have added/removed a passkey
                        // while the panel was dark, so refresh the card before painting.
                        u.refresh_home_stats();
                        Screen::Home(HomeView {
                            status: status_to_kind(led::status()),
                            pin_set: u.home_pin_set,
                            passkeys: u.home_passkeys,
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
                    // Home; a tap there starts the unlock PIN flow instead of nav. A fresh
                    // PIN-less device stands on the Onboard screen instead, until the user
                    // sets a PIN or continues without. Host ceremonies still paint their own
                    // prompts over either (they don't consult `locked` / `onboarding`).
                    let screen = if u.locked {
                        Screen::Locked
                    } else if u.onboarding {
                        Screen::Onboard
                    } else {
                        // Idle hot path: cached stats only — never a per-frame flash scan.
                        Screen::Home(HomeView {
                            status: kind,
                            pin_set: u.home_pin_set,
                            passkeys: u.home_passkeys,
                        })
                    };
                    if u.shown != Some(screen) {
                        let _ = rsk_ui::render(&mut u.panel, &screen);
                        u.shown = Some(screen);
                    }
                    // Liveness: pulse a small region over the (already-painted) frame — the
                    // spinner arc while busy, the breathe hint while locked. Both redraw in
                    // place (no clear), so they never flicker and the idle frame is untouched.
                    match screen {
                        Screen::Home(v) if v.status != StatusKind::Idle => {
                            spin = spin.wrapping_add(SPIN_STEP_DEG);
                            let _ = rsk_ui::render_status_arc(&mut u.panel, v.status, spin);
                        }
                        Screen::Locked if tick.is_multiple_of(BREATHE_TICKS) => {
                            breathe = breathe.wrapping_add(1);
                            let _ = rsk_ui::render_locked_breathe(&mut u.panel, breathe);
                        }
                        _ => {}
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
                                    // Just unlocked: a host op during the lock may have
                                    // changed the count, so refresh before painting Home.
                                    u.refresh_home_stats();
                                    Screen::Home(HomeView {
                                        status: status_to_kind(led::status()),
                                        pin_set: u.home_pin_set,
                                        passkeys: u.home_passkeys,
                                    })
                                };
                                let _ = rsk_ui::render(&mut u.panel, &screen);
                                u.shown = Some(screen);
                            } else if u.onboarding {
                                // Fresh PIN-less device: route the tap to the onboarding
                                // buttons (Set a PIN / Continue without). Repaint at once —
                                // Onboard again if it's still pending (a missed-button tap or
                                // an abandoned set), else Home now that the offer is resolved.
                                // `run_onboarding` refreshes the Home cache on whichever branch
                                // resolves the prompt, so the cached stats are current here.
                                u.run_onboarding(p);
                                note_activity();
                                let screen = if u.onboarding {
                                    Screen::Onboard
                                } else {
                                    Screen::Home(HomeView {
                                        status: status_to_kind(led::status()),
                                        pin_set: u.home_pin_set,
                                        passkeys: u.home_passkeys,
                                    })
                                };
                                let _ = rsk_ui::render(&mut u.panel, &screen);
                                u.shown = Some(screen);
                            } else {
                                // A tap on the bottom nav opens a tab. Each tab modal returns
                                // the next nav destination, so the user switches tab→tab
                                // directly (e.g. Passkeys → Settings) without a Home detour.
                                let mut target = rsk_ui::hit_nav(p);
                                let opened_tab = matches!(
                                    target,
                                    Some(NavTab::Settings | NavTab::Passkeys | NavTab::Apps)
                                );
                                while let Some(tab) = target {
                                    target = match tab {
                                        NavTab::Home => None,
                                        NavTab::Settings => u.run_settings(),
                                        NavTab::Passkeys => u.run_passkeys(),
                                        NavTab::Apps => u.run_apps(),
                                    };
                                }
                                note_activity(); // a browse session just ended — restart clock
                                // If the menu closed with the UI locked (the power button slept
                                // + locked it from inside Settings), keep Locked as the shown
                                // state so the menu can't linger.
                                if u.locked {
                                    let screen = Screen::Locked;
                                    let _ = rsk_ui::render(&mut u.panel, &screen);
                                    u.shown = Some(screen);
                                } else if opened_tab && !crate::worker::host_request_pending() {
                                    // Closing a tab back to idle repaints Home now (not next
                                    // poll) so it feels instant. Skip if a host command is
                                    // queued — the worker paints next (no stale flash). The
                                    // tab modal may have added/deleted a passkey or set the
                                    // PIN, so refresh the card facts first.
                                    u.refresh_home_stats();
                                    let screen = Screen::Home(HomeView {
                                        status: status_to_kind(led::status()),
                                        pin_set: u.home_pin_set,
                                        passkeys: u.home_passkeys,
                                    });
                                    let _ = rsk_ui::render(&mut u.panel, &screen);
                                    u.shown = Some(screen);
                                }
                            }
                        } else {
                            // Idle this tick (no tap, no button): blank once past the
                            // (runtime) sleep timeout — `0` disables sleep. Auto-lock rides
                            // on sleep (enter_sleep). Re-read the clock: a tab/menu modal *above*
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

/// Common entry for a touch ceremony: switch the LED to the touch indicator, drop any
/// stale cancel left from an earlier wait, and arm `UP_PENDING` so the CTAPHID
/// keepalive reports `UPNEEDED`. Returns the LED status [`ceremony_end`] restores.
fn ceremony_begin() -> u8 {
    let saved = led::status();
    led::set_status(led::STATUS_TOUCH);
    CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    UP_PENDING.store(true, Ordering::Relaxed);
    saved
}

/// Common exit: clear the presence flags, briefly hold the ambient status screen back
/// (so a hand-off to a following modal — pad, approve hold — doesn't flash idle), note
/// activity so a long ceremony doesn't immediately sleep, and restore the LED.
fn ceremony_end(saved_led: u8) {
    UP_PENDING.store(false, Ordering::Relaxed);
    CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    AMBIENT_QUIET_UNTIL_MS.store(
        (Instant::now().as_millis() as u32).wrapping_add(AMBIENT_QUIET_MS),
        Ordering::Relaxed,
    );
    note_activity();
    led::set_status(saved_led);
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
        let saved = ceremony_begin();

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

        ceremony_end(saved);
        outcome
    }

    /// The WebAuthn registration ceremony: the design's "Save new passkey?" card, with
    /// Cancel / Save (a tap, not a hold — registration is the lower-stakes action; the
    /// deliberate hold is reserved for the sign-in approve). Save confirms.
    fn run_add_passkey(&mut self, confirm: Confirm<'_>) -> Outcome {
        let rp = Label::clamp(confirm.primary);
        let account = Label::clamp(confirm.secondary);
        let saved = ceremony_begin();
        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        let outcome = {
            let mut u = self.ui.borrow_mut();
            u.wake();
            note_activity();
            let _ = rsk_ui::render_add_passkey(&mut u.panel, &rp, &account);
            u.shown = None;
            loop {
                match u.touch.read().and_then(rsk_ui::hit_confirm) {
                    Some(Button::Allow) => break Outcome::Confirmed,
                    Some(Button::Deny) => break Outcome::Declined,
                    None => {}
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
        ceremony_end(saved);
        outcome
    }

    /// Collect a PIN on the on-screen pad for the host built-in-UV path (clientPIN 0x06).
    /// The pad loop lives on [`Ui`] (which owns the panel + touch); borrow the shared
    /// `Ui` and run it there, so the host path and a display-initiated gate
    /// ([`Ui::run_delete`]) share one implementation.
    fn collect_pin_impl(&mut self, min_len: usize, out: &mut [u8]) -> rsk_fido::PinEntry {
        // No up-front "N tries remaining" caption here, unlike the local unlock gate: the
        // worker already holds the shared `fs` RefCell borrowed across this CTAP call
        // (clientPIN 0x06 → get_uv_token), so re-reading the counter would double-borrow
        // and panic. The placeholder dots (sized from `min_len`) still show; the host
        // already exposes the retry count via getPINRetries / getUVRetries.
        let expected = min_len.min(u8::MAX as usize) as u8;
        // The host built-in-UV PIN is the FIDO clientPIN — name it, so the user knows it
        // isn't the device-unlock or PIV PIN (the reported confusion behind a reset).
        self.ui
            .borrow_mut()
            .collect_pin("FIDO PIN", None, min_len, expected, out, false)
    }

    /// Collect a PIN on the on-screen pad for a host CCID secure-PIN-entry request
    /// (OpenPGP / PIV VERIFY over a pinpad reader). Like [`Self::collect_pin_impl`]
    /// but with a per-PIN `title` so the trusted screen names which PIN is asked for.
    /// The host is waiting on this exact PIN (its `PC_to_RDR_Secure` is in flight,
    /// the CCID transport streaming time-extensions), so it blocks to the presence
    /// timeout (`yield_to_host = false`), exactly like the FIDO built-in-UV path. The
    /// worker holds `fs` borrowed across this call, so this — like `collect_pin_impl`
    /// — must never read `fs` (it touches only the panel's `Ui` RefCell).
    pub fn collect_pin_titled(
        &mut self,
        title: &'static str,
        min_len: usize,
        out: &mut [u8],
    ) -> rsk_fido::PinEntry {
        let expected = min_len.min(u8::MAX as usize) as u8;
        self.ui
            .borrow_mut()
            .collect_pin(title, None, min_len, expected, out, false)
    }
}

impl rsk_fido::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_fido::Confirm<'_>) -> rsk_fido::Presence {
        // The design's incoming ceremony, picked by the request kind:
        //  - Register (makeCredential) → "Save new passkey?" card (Cancel/Save tap)
        //  - Generic (sign-in / selection / probe) → the trusted Approve/Hold prompt
        let outcome = match confirm.kind {
            rsk_fido::ConfirmKind::Register => self.run_add_passkey(confirm),
            rsk_fido::ConfirmKind::Generic => self.confirm_wait(confirm),
        };
        match outcome {
            Outcome::Confirmed => {
                // A granted WebAuthn approval gets the design's brief "Approved" pop.
                // Scoped to the FIDO ceremony path (one request per make/getAssertion),
                // NOT the shared `confirm_wait`: OpenPGP/PIV touch policies call request()
                // once per signature, so flashing this — and paying its ~0.4 s — on every
                // PGP/PIV op would be both wrong-worded and a latency regression. The
                // ceremony borrow is already released, so this re-borrow is safe.
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

impl rsk_rescue::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_rescue::Confirm<'_>) -> rsk_rescue::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_rescue::Presence::Confirmed,
            Outcome::Declined => rsk_rescue::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_rescue::Presence::Timeout,
        }
    }
}

impl rsk_mgmt::UserPresence for TouchPresence {
    fn request(&mut self, confirm: rsk_mgmt::Confirm<'_>) -> rsk_mgmt::Presence {
        match self.confirm_wait(confirm) {
            Outcome::Confirmed => rsk_mgmt::Presence::Confirmed,
            Outcome::Declined => rsk_mgmt::Presence::Declined,
            Outcome::Timeout | Outcome::Cancelled => rsk_mgmt::Presence::Timeout,
        }
    }
}
