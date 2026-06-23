// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display task for the `display` build: it drives the Waveshare
//! RP2350-Touch-LCD-2.8 (ST7789 over SPI1, CST328 touch over I2C1) and mirrors the
//! device status the onboard LED would otherwise show. The *what to draw* and the
//! *touch-report parse* live in `rsk-ui` (host-tested); this file is the thin HAL
//! glue. Phase 1 (bringup): a boot splash, the idle/working status screen, and a
//! marker at each raw touch so the panel + touch can be verified on hardware. The
//! trusted Allow/Deny prompt and on-screen PIN come in later phases.
//!
//! It runs on the THREAD executor (alongside the worker), NOT the high-priority USB
//! executor: mipidsi is a blocking driver, and a full-frame SPI write must never
//! stall USB. On the thread executor a repaint blocks only the worker, while USB on
//! the interrupt executor preempts it and keeps streaming keepalives.

use embassy_rp::gpio::Output;
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C1, SPI1};
use embassy_rp::spi::{Blocking as SpiBlocking, Spi};
use embassy_time::{Delay, Timer};
use embedded_graphics::{
    Drawable,
    geometry::Point as EgPoint,
    pixelcolor::Rgb565,
    prelude::RgbColor,
    primitives::{Circle, Primitive, PrimitiveStyle},
};
use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::Builder;
use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::ColorInversion;
use rsk_ui::{Screen, StatusKind};

use crate::led;

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;

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

/// The CST328 touch controller on I2C1. Owns only the bus; the reset pin is pulsed
/// once at startup in the task before this is built.
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
    /// controller serves the next one. Any I2C error reads as "no touch".
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
}

/// The panel's SPI bus + control pins + pixel buffer, bundled so the task stays
/// within embassy's argument cap.
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

/// The display + touch task. The panel is built and initialized here (not in
/// `main`) so its multi-millisecond reset/init sequence runs after USB has
/// attached, never delaying enumeration.
#[embassy_executor::task]
pub async fn display_task(panel: PanelHw, touch: TouchHw) {
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

    // Present the SPI bus + CS as one `SpiDevice`; the panel is write-only, so the
    // only way this errors is a CS-toggle programming bug.
    let spi_dev = ExclusiveDevice::new(spi, cs, Delay).unwrap();
    let di = SpiInterface::new(spi_dev, dc, buf);

    // ST7789 is native 240×320 portrait, matching rsk-ui's panel geometry. BRINGUP
    // TUNABLES if the first flash is blank/garbled or wrong-colored: the SPI mode +
    // clock (in `main`), and `ColorInversion` here — the IPS modules on these
    // boards usually need `Inverted`.
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
    Timer::after_millis(10).await;
    tp_rst.set_low();
    Timer::after_millis(10).await;
    tp_rst.set_high();
    Timer::after_millis(50).await;
    let mut touch = Touch { i2c };
    touch.normal_mode();

    Timer::after_millis(600).await; // let the splash linger before the status screen
    let mut shown: Option<Screen> = None;
    loop {
        let screen = Screen::Status(status_to_kind(led::status()));
        if shown != Some(screen) {
            let _ = rsk_ui::render(&mut panel, &screen);
            shown = Some(screen);
        }
        // Phase-1 bringup aid: mark each raw touch so the panel + touch driver can
        // be checked on hardware (axis orientation, range). Phase 2 replaces this
        // with `rsk_ui::hit_confirm` against the Allow/Deny rects.
        if let Some(p) = touch.read() {
            let _ = Circle::new(EgPoint::new(p.x as i32 - 3, p.y as i32 - 3), 6)
                .into_styled(PrimitiveStyle::with_fill(Rgb565::CYAN))
                .draw(&mut panel);
        }
        Timer::after_millis(30).await;
    }
}
