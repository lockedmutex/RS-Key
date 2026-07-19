// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::consts::{EF_CRED, EF_LARGEBLOB, EF_PIN};
use crate::seed::{bump_sign_counter, get_sign_counter, load_keydev};
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

#[test]
fn reset_wipes_state_and_regenerates() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    // Provisioned state: a PIN, a resident credential, an advanced counter,
    // and a non-default large blob.
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    fs.put(EF_CRED, &[0u8; 100]).unwrap();
    fs.put(EF_LARGEBLOB, &[0xAB; 50]).unwrap();
    // The trusted-display device PIN: a host reset must clear it too (recovery path).
    fs.put(EF_DEVICE_PIN, &[8, 4, 1, 0, 0]).unwrap();
    // An OpenPGP file (EF_PW3 = 0x1083) shares the Fs and must survive a FIDO
    // reset — it sits in the 0x10xx range right next to FIDO's own files.
    fs.put(0x1083, &[0xAB; 34]).unwrap();
    bump_sign_counter(&mut fs).unwrap();
    bump_sign_counter(&mut fs).unwrap();
    assert_eq!(get_sign_counter(&mut fs), 2);
    // A per-credential signature-counter entry must also be wiped by reset.
    crate::seed::set_cred_sign_counter(&mut fs, 0, 7).unwrap();
    assert_eq!(crate::seed::cred_sign_counter(&mut fs, 0), Some(7));

    let mut state = FidoState::new();
    state.paut.permissions = 0x07;

    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx).unwrap()
    };
    assert_eq!(n, 0);
    // Files wiped, counter reset, seed regenerated and PIN-free again.
    assert!(!fs.has_data(EF_PIN));
    assert!(!fs.has_data(EF_CRED));
    // The device PIN is cleared by the reset (so a forgotten one is recoverable).
    assert!(!fs.has_data(EF_DEVICE_PIN));
    // The OpenPGP file is untouched by the FIDO reset.
    assert!(
        fs.has_data(0x1083),
        "OpenPGP files must survive a FIDO reset"
    );
    assert_eq!(get_sign_counter(&mut fs), 0);
    assert_eq!(crate::seed::cred_sign_counter(&mut fs, 0), None);
    assert!(load_keydev(&dev(), &mut fs).is_some());
    // Large blob wiped and re-initialised to the CTAP2.1 default.
    let mut lb = [0u8; 64];
    let ln = fs.read(EF_LARGEBLOB, &mut lb).unwrap();
    assert_eq!(&lb[..ln], &crate::consts::LARGEBLOB_INITIAL);
    // Session state cleared.
    assert_eq!(state.paut.permissions, 0);
}

#[test]
fn factory_reset_keeps_only_attestation() {
    use crate::consts::{EF_ATT_CHAIN, EF_ATT_KEY, EF_KEY_DEV};
    // The org attestation (device identity) survives an on-device factory reset.
    assert!(survives_factory_reset(EF_ATT_KEY.get()));
    assert!(survives_factory_reset(EF_ATT_CHAIN));
    // User secrets and the device seed do not.
    assert!(!survives_factory_reset(EF_PIN));
    assert!(!survives_factory_reset(EF_CRED));
    assert!(!survives_factory_reset(EF_KEY_DEV.get()));
}

struct Fixed(crate::Presence);
impl crate::UserPresence for Fixed {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        self.0
    }
}

#[test]
fn reset_aborts_without_touch() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    let mut state = FidoState::new();
    let r = {
        let mut presence = Fixed(crate::Presence::Timeout);
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx)
    };
    assert_eq!(r, Err(CtapError::UserActionTimeout));
    // A declined touch wipes nothing.
    assert!(fs.has_data(EF_PIN));
}

#[test]
fn reset_wipes_false_absent_credential_without_looping() {
    // A torn-migration false-absent resident credential: live in the backend but
    // with a clear present bit (build the store, then wrap it WITHOUT a scan). The
    // pre-fix reset removed FIDO files with the present-cache-gated `delete`, which
    // skipped such a key while `for_each_key` (reading the backend directly) kept
    // re-yielding it — an infinite wipe loop that hung the device. `force_delete`
    // removes unconditionally, so the wipe terminates. Reaching the asserts below
    // (rather than hanging) IS the regression check.
    let cred = EF_CRED + 3;
    let ram = {
        let mut seed_fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut seed_fs, &mut rng).unwrap();
        seed_fs.put(cred, &[0u8; 100]).unwrap();
        seed_fs.into_storage()
    };
    let mut fs = Fs::new(ram); // no scan → every file, incl. the cred, is false-absent
    let mut rng = SeqRng(2);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx).unwrap();
    }
    assert!(
        !fs.has_data(cred),
        "reset must wipe even a false-absent credential"
    );
    // And it still fully re-provisions afterwards.
    assert!(load_keydev(&dev(), &mut fs).is_some());
}
