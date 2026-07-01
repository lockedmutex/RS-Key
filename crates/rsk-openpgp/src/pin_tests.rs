// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::init::scan_files;
use rsk_fs::storage::ram::RamStorage;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x33; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn setup() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

const OTP_KEY: [u8; 32] = [0x66; 32];

fn otp_dev() -> Device<'static> {
    Device {
        otp_key: Some(&OTP_KEY),
        ..dev()
    }
}

#[test]
fn pin_and_dek_migrate_to_otp_kbase_at_verify() {
    // State written by a pre-OTP firmware…
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(0);
    let d = otp_dev();

    // …verifies under the OTP build via the fallback, without burning a retry
    // and with a working session (the DEK copy was re-wrapped).
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert!(sess.has_pw1);
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    // The stored verifier is now the OTP-arm one: a fresh session verifies
    // directly, and a wrong PIN still sees the full retry budget (C2 = 3-1).
    let mut sess2 = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess2,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut sess3 = Session::new();
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess3, &mut rng, 0x00, PW1_MODE81, b"000000"
        ),
        Sw::new(0x63, 0xC2)
    );

    // PW3 migrates independently at its own verify.
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut dek3 = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek3).unwrap();
    // Same underlying DEK either way.
    assert_eq!(dek, dek3);

    // A pre-OTP device can no longer verify against the migrated verifier
    // (counter sits at 2 after the sess3 miss, so this burns it to 1).
    let mut sess4 = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess4,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::new(0x63, 0xC1)
    );
}

#[test]
fn verify_default_pw1_and_load_dek() {
    let mut fs = setup();
    let mut sess = Session::new();
    // PW1 default "123456", mode 0x81.
    let sw = verify(
        &dev(),
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    assert_eq!(sw, Sw::OK);
    assert!(sess.has_pw1);
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&dev(), &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn verify_wrong_pin_decrements_then_blocks() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    // Wrong PW3 ("12345678" is right); 3 tries → block.
    for expect in [0xC2u8, 0xC1, 0x00] {
        let sw = verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            b"99999999",
        );
        if expect == 0 {
            assert_eq!(sw, Sw::PIN_BLOCKED);
        } else {
            assert_eq!(sw, Sw::new(0x63, expect));
        }
    }
    assert!(!sess.has_pw3);
}

#[test]
fn verify_resets_counter_on_success() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    // Two wrong, then correct, then wrong again → counter is back at C2.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        b"00000000",
    );
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        b"00000000",
    );
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            b"00000000"
        ),
        Sw::new(0x63, 0xC2)
    );
}

#[test]
fn logout_clears_flag() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    assert!(sess.has_pw1);
    assert_eq!(
        verify(&d, &mut fs, &mut sess, &mut rng, 0xFF, PW1_MODE81, &[]),
        Sw::OK
    );
    assert!(!sess.has_pw1);
}

#[test]
fn change_pw1_then_new_pin_works_and_dek_survives() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(99);
    // The DEK as unwrapped before the change.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    let mut dek_before = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek_before).unwrap();
    sess.reset();

    // CHANGE PIN PW1: old "123456" -> new "654321".
    let mut data = Vec::new();
    data.extend_from_slice(PW1_DEFAULT);
    data.extend_from_slice(b"654321");
    assert_eq!(
        change_pin(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    sess.reset();

    // Old PIN now fails, new PIN verifies + unwraps the SAME DEK.
    assert_ne!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"654321"
        ),
        Sw::OK
    );
    let mut dek_after = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek_after).unwrap();
    assert_eq!(dek_before, dek_after);
}

#[test]
fn reset_retry_via_pw3_unblocks_pw1() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(7);
    // Block PW1 (3 wrong tries).
    for _ in 0..3 {
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"000000",
        );
    }
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::PIN_BLOCKED
    );
    // Admin (PW3) resets PW1 to "111111".
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    assert_eq!(
        reset_retry(
            &d, &mut fs, &mut sess, &mut rng, 0x02, PW1_MODE81, b"111111"
        ),
        Sw::OK
    );
    sess.reset();
    // PW1 works again with the new value, and the DEK is intact.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    ); // restore pw3
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"111111"
        ),
        Sw::OK
    );
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn reset_retry_via_pw3_needs_pw3() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0x02,
            PW1_MODE81,
            b"111111"
        ),
        Sw::CONDITIONS_NOT_SATISFIED
    );
}

#[test]
fn reset_retry_via_rc_resets_pw1() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(7);
    // The default reset code equals the admin PIN (12345678). RESET RETRY P1=0
    // with `RC || new-PW1` resets PW1 without needing an admin session.
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(PW3_DEFAULT);
    data[8..].copy_from_slice(b"111111");
    assert_eq!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    sess.reset();
    // PW1 now verifies with the new value and the DEK is recoverable.
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"111111"
        ),
        Sw::OK
    );
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn put_reset_code_then_reset_retry_via_rc() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(7);
    // Admin sets a custom reset code, which then unlocks a PW1 reset.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    assert_eq!(
        put_reset_code(&d, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    sess.reset();
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"resetme0");
    data[8..].copy_from_slice(b"222222");
    assert_eq!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    sess.reset();
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"222222"
        ),
        Sw::OK
    );
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn put_reset_code_requires_pw3() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // A bad reset code is rejected by RESET RETRY P1=0.
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"wrongrc0");
    data[8..].copy_from_slice(b"222222");
    let sw = reset_retry(
        &dev(),
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW1_MODE81,
        &data,
    );
    assert_ne!(sw, Sw::OK);
}
