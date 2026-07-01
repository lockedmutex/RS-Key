// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn roundtrip_all_fields() {
    let phy = PhyData {
        vid_pid: Some((0x1050, 0x0407)),
        led_gpio: Some(16),
        led_brightness: Some(200),
        opts: OPT_LED_STEADY | OPT_DIMM,
        presence_timeout: Some(20),
        usb_product: Product::new(b"RSK Custom"),
        enabled_curves: Some(0x3FF),
        enabled_usb_itf: Some(USB_ITF_CCID | USB_ITF_HID),
        led_driver: Some(3),
        led_order: Some(LED_ORDER_GRB),
        led_num: Some(4),
    };
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).unwrap();
    assert_eq!(PhyData::parse(&buf[..n]), phy);
}

#[test]
fn vidpid_wire_is_big_endian() {
    let phy = PhyData {
        vid_pid: Some((0x1050, 0x0407)),
        ..Default::default()
    };
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).unwrap();
    // VIDPID TLV first: tag 0, len 4, VID be, PID be.
    assert_eq!(
        &buf[..n],
        &[
            0x00, 0x04, 0x10, 0x50, 0x04, 0x07, TAG_OPTS, 0x02, 0x00, 0x00
        ]
    );
}

#[test]
fn parse_defaults_usb_itf_to_all() {
    let phy = PhyData::parse(&[]);
    assert_eq!(phy.enabled_usb_itf, Some(USB_ITF_ALL));
    assert_eq!(phy.vid_pid, None);
    assert_eq!(phy.opts, 0);
}

#[test]
fn effective_usb_itf_applies_mask_but_guards_lockout() {
    let mut phy = PhyData::default();
    // No record / no TLV → ALL.
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
    // Any mask keeping at least one supported interface applies verbatim.
    phy.enabled_usb_itf = Some(USB_ITF_CCID | USB_ITF_HID);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_CCID | USB_ITF_HID);
    phy.enabled_usb_itf = Some(USB_ITF_KB);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_KB);
    // A mask with no supported interface (zero, or only WCID/LWIP bits we
    // do not build) would soft-brick USB → falls back to ALL.
    phy.enabled_usb_itf = Some(0);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
    phy.enabled_usb_itf = Some(USB_ITF_WCID | USB_ITF_LWIP);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
}

#[test]
fn parse_skips_unknown_tags_and_truncation_is_safe() {
    // Unknown tag 0x7F (3 bytes), then a valid LED_GPIO, then a TLV whose
    // length runs past the input.
    let phy = PhyData::parse(&[0x7F, 3, 1, 2, 3, TAG_LED_GPIO, 1, 9, TAG_OPTS, 2, 0xAA]);
    assert_eq!(phy.led_gpio, Some(9));
    assert_eq!(phy.opts, 0); // truncated OPTS ignored
}

#[test]
fn product_string_stops_at_nul_and_caps_at_32() {
    let phy = PhyData::parse(&[TAG_USB_PRODUCT, 5, b'a', b'b', 0, b'c', 0]);
    assert_eq!(phy.usb_product.unwrap().as_bytes(), b"ab");
    assert!(Product::new(&[b'x'; 33]).is_none());
    assert!(Product::new(b"").is_none());
}

#[test]
fn save_and_load() {
    let mut fs = rsk_fs::Fs::new(rsk_fs::storage::ram::RamStorage::new(), &[]);
    assert!(load(&mut fs).is_none());
    let phy = PhyData {
        led_brightness: Some(50),
        opts: OPT_LED_STEADY,
        ..Default::default()
    };
    save(&mut fs, &phy).unwrap();
    let got = load(&mut fs).unwrap();
    assert_eq!(got.led_brightness, Some(50));
    assert_eq!(got.opts, OPT_LED_STEADY);
    // The load-time default materializes ITF_ALL.
    assert_eq!(got.enabled_usb_itf, Some(USB_ITF_ALL));
}
