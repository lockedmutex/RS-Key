// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the rescue applet dispatch (`RescueApplet::process`) — phy write/read,
//! flash info, secure-boot status, time set/get, reboot and the keydev paths
//! are all reachable from a length-prefixed APDU replay. The keydev sign/pubkey
//! commands run real secp256k1 ops over the fuzzer-driven flash state; none may
//! panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::storage::ram::RamStorage;
use rsk_fs::Fs;
use rsk_rescue::{Platform, RescueApplet, Rng, SecureBootStatus};
use rsk_sdk::{Apdu, Applet, ResBuf};

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

struct FakePlatform {
    time: Option<u32>,
}
impl Platform for FakePlatform {
    fn secure_boot_status(&self) -> SecureBootStatus {
        SecureBootStatus { enabled: false, locked: false, bootkey: 0xFF }
    }
    fn now(&self) -> Option<u32> {
        self.time
    }
    fn set_time(&mut self, epoch: u32) {
        self.time = Some(epoch);
    }
    fn request_reboot(&mut self, _bootsel: bool) {}
    fn read_page58_lock_raw(&self) -> Option<u32> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        true
    }
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let platform = RefCell::new(FakePlatform { time: None });
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        64 * 1024,
        4 * 1024 * 1024,
    );

    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        let end = (i + len).min(data.len());
        if let Ok(apdu) = Apdu::parse(&data[i..end]) {
            let mut buf = [0u8; 2048];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
        i = end;
    }
});
