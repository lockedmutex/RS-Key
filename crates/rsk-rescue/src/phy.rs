// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `phy` device-configuration blob: a TLV record in `EF_PHY` holding USB
//! identity (VID/PID, product string), LED wiring and options. The rescue applet
//! reads/writes it verbatim; at boot the firmware applies the USB identity AND the
//! LED hardware — pin (`led_gpio`), driver (`led_driver`), brightness/steady, and
//! the WS2812 wire order (`led_order`). The pico-fido tags below match PicoForge;
//! `led_order` (tag `0x0D`) is an RS-Key extension PicoForge skips as unknown.

use rsk_fs::{Fs, Storage};

/// The phy record file. Outside every applet reset scope — it survives FIDO
/// reset / OpenPGP TERMINATE / PIV reset, like the device key.
pub const EF_PHY: u16 = 0xE020;

// Wire format: one-byte tag, one-byte length. VIDPID = VID ‖ PID big-endian;
// USB_PRODUCT counts a trailing NUL in its length.
const TAG_VIDPID: u8 = 0x0;
const TAG_LED_GPIO: u8 = 0x4;
const TAG_LED_BRIGHTNESS: u8 = 0x5;
const TAG_OPTS: u8 = 0x6;
// Tag `0x08` matches pico-fido / PicoForge `PresenceTimeout`: the touch-wait
// timeout in seconds. (RS-Key once read this as a presence-button GPIO, but the
// button is always BOOTSEL, so that was never used — realigned to pico-fido.)
const TAG_PRESENCE_TIMEOUT: u8 = 0x8;
const TAG_USB_PRODUCT: u8 = 0x9;
const TAG_ENABLED_CURVES: u8 = 0xA;
const TAG_ENABLED_USB_ITF: u8 = 0xB;
const TAG_LED_DRIVER: u8 = 0xC;
// RS-Key vendor tag (not in pico-fido / PicoForge): WS2812 wire byte order —
// 0 = rgb (passthrough), 1 = grb (red/green swapped). PicoForge skips it as
// unknown and drops it on a read-modify-write; RS-Key's own tools preserve it.
const TAG_LED_ORDER: u8 = 0xD;
// RS-Key vendor tag: number of physically-connected addressable LEDs.
// 0 = unset (use the build's MAX_LEDS default).
const TAG_LED_NUM: u8 = 0xE;

/// `led_order` wire value: a standard WS2812B (GRB) part, red↔green swapped.
pub const LED_ORDER_GRB: u8 = 1;

pub const OPT_WCID: u16 = 0x1;
pub const OPT_DIMM: u16 = 0x2;
pub const OPT_DISABLE_POWER_RESET: u16 = 0x4;
pub const OPT_LED_STEADY: u16 = 0x8;

pub const USB_ITF_CCID: u8 = 0x1;
pub const USB_ITF_WCID: u8 = 0x2;
pub const USB_ITF_HID: u8 = 0x4;
pub const USB_ITF_KB: u8 = 0x8;
pub const USB_ITF_LWIP: u8 = 0x10;
pub const USB_ITF_ALL: u8 = USB_ITF_CCID | USB_ITF_WCID | USB_ITF_HID | USB_ITF_KB | USB_ITF_LWIP;

/// The interfaces this firmware can instantiate (WCID/LWIP are not built).
pub const USB_ITF_SUPPORTED: u8 = USB_ITF_CCID | USB_ITF_HID | USB_ITF_KB;

/// The boot-effective interface mask. A stored mask that disables every
/// interface we have would leave the device USB-dead — and with CCID gone the
/// rescue applet that could rewrite the record is unreachable, so the only way
/// back would be a full flash wipe. Such a mask falls back to ALL.
pub fn effective_usb_itf(phy: &PhyData) -> u8 {
    let mask = phy.enabled_usb_itf.unwrap_or(USB_ITF_ALL);
    if mask & USB_ITF_SUPPORTED == 0 {
        USB_ITF_ALL
    } else {
        mask
    }
}

/// Largest serialized record (every TLV present, 32-byte product). The trailing
/// `(2 + 1) × 2` covers the RS-Key `led_order` and `led_num` tags.
pub const PHY_MAX_SIZE: usize = (2 + 4)
    + (2 + 1)
    + (2 + 1)
    + (2 + 2)
    + (2 + 1)
    + (2 + 33)
    + (2 + 4)
    + (2 + 1)
    + (2 + 1)
    + (2 + 1)
    + (2 + 1); // led_num

const PRODUCT_CAP: usize = 32;

/// The USB product string: raw bytes as stored on the wire, NUL excluded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Product {
    buf: [u8; PRODUCT_CAP],
    len: u8,
}

impl Product {
    pub fn new(s: &[u8]) -> Option<Self> {
        if s.is_empty() || s.len() > PRODUCT_CAP {
            return None;
        }
        let mut buf = [0u8; PRODUCT_CAP];
        buf[..s.len()].copy_from_slice(s);
        Some(Product {
            buf,
            len: s.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

/// The parsed phy record; absent TLVs are `None`. `opts` has no presence
/// flag — absent means 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PhyData {
    pub vid_pid: Option<(u16, u16)>,
    pub led_gpio: Option<u8>,
    pub led_brightness: Option<u8>,
    pub opts: u16,
    /// Touch-wait timeout in seconds (tag `0x08`, pico-fido `PresenceTimeout`);
    /// `None` / `0` keeps the firmware's built-in 30 s default.
    pub presence_timeout: Option<u8>,
    pub usb_product: Option<Product>,
    pub enabled_curves: Option<u32>,
    pub enabled_usb_itf: Option<u8>,
    pub led_driver: Option<u8>,
    /// RS-Key WS2812 wire order (tag `0x0D`): `0` = rgb, `1` = grb.
    pub led_order: Option<u8>,
    /// Number of physically connected addressable LEDs (tag `0x0E`);
    /// `None` / `0` = use the build's `MAX_LEDS` default.
    pub led_num: Option<u8>,
}

impl PhyData {
    /// Unknown tags are skipped; a TLV running past the end of the input ends
    /// the parse — the parser must never overread. A record without
    /// ENABLED_USB_ITF gets ALL.
    pub fn parse(data: &[u8]) -> PhyData {
        let mut phy = PhyData::default();
        let mut p = data;
        while p.len() >= 2 {
            let tag = p[0];
            let tlen = p[1] as usize;
            p = &p[2..];
            if tlen > p.len() {
                break;
            }
            let v = &p[..tlen];
            match (tag, tlen) {
                (TAG_VIDPID, 4) => {
                    let vid = u16::from_be_bytes([v[0], v[1]]);
                    let pid = u16::from_be_bytes([v[2], v[3]]);
                    phy.vid_pid = Some((vid, pid));
                }
                (TAG_LED_GPIO, 1) => phy.led_gpio = Some(v[0]),
                (TAG_LED_BRIGHTNESS, 1) => phy.led_brightness = Some(v[0]),
                (TAG_OPTS, 2) => phy.opts = u16::from_be_bytes([v[0], v[1]]),
                (TAG_PRESENCE_TIMEOUT, 1) => phy.presence_timeout = Some(v[0]),
                (TAG_USB_PRODUCT, 1..=33) => {
                    // Length includes a trailing NUL; the string also stops at
                    // an embedded NUL.
                    let s = &v[..v.iter().position(|&b| b == 0).unwrap_or(tlen)];
                    phy.usb_product = Product::new(s);
                }
                (TAG_ENABLED_CURVES, 4) => {
                    phy.enabled_curves = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                }
                (TAG_ENABLED_USB_ITF, 1) => phy.enabled_usb_itf = Some(v[0]),
                (TAG_LED_DRIVER, 1) => phy.led_driver = Some(v[0]),
                (TAG_LED_ORDER, 1) => phy.led_order = Some(v[0]),
                (TAG_LED_NUM, 1) => phy.led_num = Some(v[0]),
                _ => {}
            }
            p = &p[tlen..];
        }
        if phy.enabled_usb_itf.is_none() {
            phy.enabled_usb_itf = Some(USB_ITF_ALL);
        }
        phy
    }

    /// Emit a TLV per present field; OPTS always. Returns the length, or `None`
    /// if `out` is too small (`PHY_MAX_SIZE` always fits).
    pub fn serialize(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer { out, len: 0 };
        if let Some((vid, pid)) = self.vid_pid {
            w.tlv(
                TAG_VIDPID,
                &[(vid >> 8) as u8, vid as u8, (pid >> 8) as u8, pid as u8],
            )?;
        }
        if let Some(g) = self.led_gpio {
            w.tlv(TAG_LED_GPIO, &[g])?;
        }
        if let Some(b) = self.led_brightness {
            w.tlv(TAG_LED_BRIGHTNESS, &[b])?;
        }
        w.tlv(TAG_OPTS, &self.opts.to_be_bytes())?;
        if let Some(t) = self.presence_timeout {
            w.tlv(TAG_PRESENCE_TIMEOUT, &[t])?;
        }
        if let Some(p) = &self.usb_product {
            let s = p.as_bytes();
            w.raw(&[TAG_USB_PRODUCT, (s.len() + 1) as u8])?;
            w.raw(s)?;
            w.raw(&[0])?;
        }
        if let Some(c) = self.enabled_curves {
            w.tlv(TAG_ENABLED_CURVES, &c.to_be_bytes())?;
        }
        if let Some(i) = self.enabled_usb_itf {
            w.tlv(TAG_ENABLED_USB_ITF, &[i])?;
        }
        if let Some(d) = self.led_driver {
            w.tlv(TAG_LED_DRIVER, &[d])?;
        }
        if let Some(o) = self.led_order {
            w.tlv(TAG_LED_ORDER, &[o])?;
        }
        if let Some(n) = self.led_num {
            w.tlv(TAG_LED_NUM, &[n])?;
        }
        Some(w.len)
    }
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn raw(&mut self, b: &[u8]) -> Option<()> {
        if self.len + b.len() > self.out.len() {
            return None;
        }
        self.out[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Some(())
    }

    fn tlv(&mut self, tag: u8, v: &[u8]) -> Option<()> {
        self.raw(&[tag, v.len() as u8])?;
        self.raw(v)
    }
}

/// Load the phy record; `None` when none was ever written.
pub fn load<S: Storage>(fs: &mut Fs<S>) -> Option<PhyData> {
    let mut buf = [0u8; PHY_MAX_SIZE];
    // Fs::read returns the value's full stored length; clamp before slicing so an
    // over-long EF_PHY record can never push the slice past the fixed buffer.
    let n = fs.read(EF_PHY, &mut buf)?.min(buf.len());
    Some(PhyData::parse(&buf[..n]))
}

/// Persist the phy record.
pub fn save<S: Storage>(fs: &mut Fs<S>, phy: &PhyData) -> rsk_sdk::error::Result<()> {
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy
        .serialize(&mut buf)
        .ok_or(rsk_sdk::error::Error::NoMemory)?;
    fs.put(EF_PHY, &buf[..n])
}

/// Kani proof harnesses (`cargo kani -p rsk-rescue`): the phy record is parsed
/// from flash at every boot and round-trips through the rescue applet's
/// read-modify-write — both directions are small total functions over
/// attacker-/corruption-reachable bytes, so prove them outright (the house
/// rule from docs/testing.md).
#[cfg(kani)]
#[path = "phy_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "phy_tests.rs"]
mod tests;
