// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CCID transport framing (`rsk_usb::ccid::process_message`): the
//! whole 10-byte CCID header + payload comes off the USB bulk-OUT endpoint
//! attacker-controlled, so parsing `dwLength` / the message type and writing the
//! response header must never panic — only ever produce a (possibly empty)
//! response. `process_message` handles only the framing (power on/off, slot
//! status, params); the XfrBlock applet dispatch is driven and fuzzed separately
//! (`openpgp_apdu` / `mgmt_apdu`).

use libfuzzer_sys::fuzz_target;
use rsk_usb::ccid::process_message;

fuzz_target!(|data: &[u8]| {
    const ATR: &[u8] = &[0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03];
    let mut status = 0u8;
    let mut out = [0u8; 2048];
    let _ = process_message(data, ATR, &mut status, &mut out);
});
