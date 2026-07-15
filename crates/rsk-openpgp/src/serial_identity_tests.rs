// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Characterization test for a latent robustness weakness surfaced while
//! investigating issue #25 (OpenPGP "Bad PIN" / card unusable after a replug on
//! a Waveshare RP2350-Zero, secure boot off).
//!
//! On a board with no provisioned OTP key the OpenPGP PIN verifier and the card
//! AID are both derived from the device serial: the PIN KDF roots on
//! `serial_hash` (`kbase = HKDF(SALT_NOOTP, serial_hash)`, see
//! `rsk_crypto::kdf`), and `full_aid` splices `serial_id[..4]` in at offset 10.
//! `firmware/src/main.rs` computes both from a single boot-time read,
//! `serial_id = get_chipid().unwrap_or(0)`, `serial_hash = sha256(serial_id)`.
//!
//! These tests pin the *consequence* of that coupling: if the boot serial ever
//! differed across a power cycle, then against the SAME flash after a replug
//!   * `pin_derive_verifier` yields a different verifier → the *correct* PIN is
//!     rejected as `63 Cx` (gpg: `Bad PIN`), unrecoverably (no serial fallback in
//!     `check_pin` on a no-OTP board), and
//!   * `full_aid` carries a different serial → GET DATA `0x4F` returns a
//!     different AID (scdaemon keys the card off this → "card not available").
//!
//! SCOPE — read before trusting this as issue #25's cause. These tests
//! *demonstrate the consequence* by hardcoding the serial change (`CHIPID_B`);
//! they do NOT establish that the serial actually changes across a replug — but
//! that trigger is *plausible* (not, as first thought, implausible):
//! `embassy_rp::otp::get_chipid` reads the chip id through the UNGUARDED ECC alias
//! (`read_ecc_word`), which checks only the raw read for the all-ones permission
//! lock and does NOT surface an uncorrectable ECC error on the corrected read. So a
//! marginal/aging CHIPID OTP cell can silently return a *different* value across a
//! power cycle (a 2-bit-or-worse fault is mis-corrected, not an `Err`), and
//! `unwrap_or(0)` at `firmware/src/main.rs` only catches the `Err` path — a
//! silently-wrong chip id flows straight into `serial_hash`. That is a real
//! *fail-explicitly* smell AND a board-specific, intermittent brick matching #25
//! (and why it does not reproduce on a healthy board). Competing hypotheses (torn
//! KV persistence; host PC/SC artifact) stay open. Confirmation is device-side:
//! read the chip id (`picotool otp get`) or the `GET DATA 0x4F` AID serial across a
//! real replug — if it moves, this is the cause. Kept as a characterization +
//! regression guard for the identity-stability fix.

use super::*;
use rsk_fs::storage::ram::RamStorage;

/// Deterministic counter RNG, as in the sibling test modules.
struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

/// Two identities for the SAME physical board across two boots: `A` = the chip
/// id read succeeded; `B` = it failed and `get_chipid().unwrap_or(0)` fell back
/// to 0. `serial_hash = sha256(serial_id)` exactly as `firmware/src/main.rs`.
const CHIPID_A: [u8; 8] = [0xCD, 0xC7, 0x0A, 0xF4, 0xD3, 0x74, 0x99, 0xA2];
const CHIPID_B: [u8; 8] = [0u8; 8];

fn boot(serial_id: [u8; 8]) -> ([u8; 8], [u8; 32]) {
    (serial_id, rsk_crypto::sha256(&serial_id))
}

fn dev<'a>(serial_id: &'a [u8; 8], serial_hash: &'a [u8; 32]) -> Device<'a> {
    Device {
        serial_hash,
        serial_id,
        otp_key: None,
    }
}

/// A fresh RAM-backed OpenPGP filesystem provisioned under `serial` — writes the
/// default PIN verifiers + DEK bound to that serial's derivation.
fn provision(serial_id: &[u8; 8], serial_hash: &[u8; 32]) -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(serial_id, serial_hash), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

fn applet<'a>(
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    rng: &'a RefCell<CountRng>,
    presence: &'a RefCell<crate::AlwaysConfirm>,
) -> OpenpgpApplet<'a> {
    OpenpgpApplet::new(serial_id, serial_hash, None, rng, presence)
}

/// VERIFY PW1 (mode 0x81) with `pin`, through the full APDU dispatch — the exact
/// path scdaemon drives.
fn verify_pw1(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, pin: &[u8]) -> Sw {
    let mut a = vec![
        0x00,
        consts::INS_VERIFY,
        0x00,
        consts::PW1_MODE81,
        pin.len() as u8,
    ];
    a.extend_from_slice(pin);
    let apdu = Apdu::parse(&a).unwrap();
    let mut buf = [0u8; SCRATCH];
    let mut res = ResBuf::new(&mut buf);
    app.process(&apdu, fs, &mut res)
}

/// GET DATA `0x4F` → the 16-byte application AID (`D2 76 00 01 24 01 …
/// serial(4) …`), the card serial scdaemon reads on connect.
fn get_aid(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>) -> Vec<u8> {
    let apdu = Apdu::parse(&[0x00, consts::INS_GET_DATA, 0x00, 0x4F]).unwrap();
    let mut buf = [0u8; SCRATCH];
    let mut res = ResBuf::new(&mut buf);
    assert_eq!(app.process(&apdu, fs, &mut res), Sw::OK, "GET DATA 0x4F");
    res.as_slice().to_vec()
}

#[test]
fn serial_change_rejects_the_correct_pin() {
    let (id_a, hash_a) = boot(CHIPID_A);
    let (id_b, hash_b) = boot(CHIPID_B);
    let mut fs = provision(&id_a, &hash_a); // set up under boot A's serial

    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);

    // Boot A (card still plugged in, as during setup): the default PIN verifies.
    let mut app_a = applet(id_a, hash_a, &rng, &presence);
    assert_eq!(
        verify_pw1(&mut app_a, &mut fs, consts::PW1_DEFAULT),
        Sw::OK,
        "the correct PIN must work right after setup"
    );

    // A boot whose serial differs (modelled as the unwrap_or(0) fallback), same
    // flash, same correct PIN → rejected as 63 C2 (gpg: "Bad PIN").
    let mut app_b = applet(id_b, hash_b, &rng, &presence);
    assert_eq!(
        verify_pw1(&mut app_b, &mut fs, consts::PW1_DEFAULT),
        Sw::new(0x63, 0xC2),
        "a changed serial rejects the correct PIN (the verifier is serial-bound)"
    );

    // The stored PIN is fine: back on boot A the same PIN verifies (this success
    // resets the counter the app_b miss decremented), so only the derived
    // identity moved — not the PIN in flash.
    let mut app_a2 = applet(id_a, hash_a, &rng, &presence);
    assert_eq!(
        verify_pw1(&mut app_a2, &mut fs, consts::PW1_DEFAULT),
        Sw::OK,
        "the PIN is unchanged in flash — only the serial-derived key differs"
    );
}

#[test]
fn serial_change_moves_the_card_aid() {
    let (id_a, hash_a) = boot(CHIPID_A);
    let (id_b, hash_b) = boot(CHIPID_B);
    let mut fs = provision(&id_a, &hash_a);
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);

    let mut app_a = applet(id_a, hash_a, &rng, &presence);
    let aid_a = get_aid(&mut app_a, &mut fs);

    let mut app_b = applet(id_b, hash_b, &rng, &presence);
    let aid_b = get_aid(&mut app_b, &mut fs);

    // Same 6-byte OpenPGP AID prefix + version/manufacturer, but the 4-byte
    // serial at offset 10..14 differs → scdaemon reads a different card serial.
    assert_eq!(aid_a.len(), 16);
    assert_eq!(
        &aid_a[..10],
        &aid_b[..10],
        "only the serial region may differ"
    );
    assert_ne!(
        &aid_a[10..14],
        &aid_b[10..14],
        "a changed serial moves the card AID/serial scdaemon keys on"
    );
}

#[test]
fn serial_change_burns_retries_and_blocks_the_good_boot() {
    // Unrecoverable on a no-OTP board: check_pin has no serial fallback (only the
    // OTP-generation one), so correct PINs under the wrong serial drain the
    // counter to a hard block — the "card unusable" end state, not just one bad
    // attempt.
    let (id_a, hash_a) = boot(CHIPID_A);
    let (id_b, hash_b) = boot(CHIPID_B);
    let mut fs = provision(&id_a, &hash_a);
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);

    let mut app_b = applet(id_b, hash_b, &rng, &presence);
    assert_eq!(
        verify_pw1(&mut app_b, &mut fs, consts::PW1_DEFAULT),
        Sw::new(0x63, 0xC2)
    );
    assert_eq!(
        verify_pw1(&mut app_b, &mut fs, consts::PW1_DEFAULT),
        Sw::new(0x63, 0xC1)
    );
    assert_eq!(
        verify_pw1(&mut app_b, &mut fs, consts::PW1_DEFAULT),
        Sw::PIN_BLOCKED
    );

    // The counter lives in shared flash, so once drained even the correct-serial
    // boot with the correct PIN is locked out: a single serial change would brick
    // OpenPGP, not just fail one attempt.
    let mut app_a = applet(id_a, hash_a, &rng, &presence);
    assert_eq!(
        verify_pw1(&mut app_a, &mut fs, consts::PW1_DEFAULT),
        Sw::PIN_BLOCKED,
        "a serial glitch drains the retry counter and blocks the good boot too"
    );
}
