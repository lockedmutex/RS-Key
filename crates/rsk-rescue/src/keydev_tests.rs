// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::aes_encrypt;
use rsk_fs::storage::ram::RamStorage;

use super::*;

struct LcgRng(u64);
impl Rng for LcgRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
    }
}

const OTP: [u8; 32] = [0x55; 32];

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn otp_dev() -> Device<'static> {
    Device {
        otp_key: Some(&OTP),
        ..dev()
    }
}

fn fs() -> Fs<RamStorage> {
    Fs::new(RamStorage::new())
}

/// Manually CBC-seal a scalar the pre-#16 way (fixed serial-hash IV, bare 32
/// bytes) so the migration path can be exercised without the old code.
fn write_legacy_cbc(dev: &Device, fs: &mut Fs<RamStorage>, scalar: &[u8; 32]) {
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let mut ct = *scalar;
    let mut kbase = dev.without_otp().derive_kbase();
    aes_encrypt(&kbase, &iv, Mode::Cbc, &mut ct).unwrap();
    kbase.zeroize();
    fs.put_key(EF_DEVCERT_KEY, Sealed::wrap(&ct)).unwrap();
}

#[test]
fn devk_wins_over_flash_and_is_the_scalar_itself() {
    let mut fs = fs();
    let mut rng = LcgRng(3);
    // Provision a flash key first; the DEVK must shadow it.
    let flash_key = load_or_generate(&dev(), None, &mut fs, &mut rng).unwrap();
    let devk = [0x42u8; 32];
    let key = load_or_generate(&dev(), Some(&devk), &mut fs, &mut rng).unwrap();
    assert_eq!(key.to_bytes().as_slice(), &devk);
    assert_ne!(key.to_bytes(), flash_key.to_bytes());
    // An invalid DEVK scalar fails outright (no flash fallback).
    assert!(load_or_generate(&dev(), Some(&[0u8; 32]), &mut fs, &mut rng).is_none());
}

#[test]
fn fresh_key_is_gcm_sealed_and_authenticated() {
    let mut fs = fs();
    let mut rng = LcgRng(7);
    let key = load_or_generate(&otp_dev(), None, &mut fs, &mut rng).unwrap();
    // A GCM record, not a bare/tagged CBC blob.
    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(GCM_LEN));
    let again = load_or_generate(&otp_dev(), None, &mut fs, &mut rng).unwrap();
    assert_eq!(key.to_bytes(), again.to_bytes());

    // A single flipped ciphertext byte fails authentication (no CBC
    // malleability): the GCM tag rejects it, so the key no longer loads.
    let mut blob = [0u8; GCM_LEN];
    assert_eq!(fs.read_key(EF_DEVCERT_KEY, &mut blob), Some(GCM_LEN));
    blob[1 + NONCE_LEN] ^= 0x01;
    fs.put_key(EF_DEVCERT_KEY, Sealed::wrap(&blob)).unwrap();
    assert!(load_or_generate(&otp_dev(), None, &mut fs, &mut rng).is_none());
}

#[test]
fn gcm_keydev_migrates_from_preotp_to_otp_arm() {
    let mut fs = fs();
    let mut rng = LcgRng(5);
    let key = load_or_generate(&dev(), None, &mut fs, &mut rng).unwrap();
    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(GCM_LEN));

    // Boot pass re-seals under the OTP arm; idempotent, same size.
    migrate_kbase(&otp_dev(), &mut fs, &mut rng);
    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(GCM_LEN));
    migrate_kbase(&otp_dev(), &mut fs, &mut rng);
    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(GCM_LEN));

    // The OTP device loads the SAME key; a pre-OTP device can no longer.
    let migrated = load_or_generate(&otp_dev(), None, &mut fs, &mut rng).unwrap();
    assert_eq!(migrated.to_bytes(), key.to_bytes());
    assert!(load_or_generate(&dev(), None, &mut fs, &mut rng).is_none());
}

#[test]
fn legacy_cbc_record_loads_and_upgrades_to_gcm() {
    // A device provisioned before #16 has a bare 32-byte CBC blob. It must
    // still load, and migrate_kbase upgrades it to authenticated GCM.
    let mut fs = fs();
    let mut rng = LcgRng(9);
    let scalar = [0x33u8; 32]; // a valid secp256k1 scalar
    let expect = SigningKey::from_bytes(&scalar.into()).unwrap();
    write_legacy_cbc(&dev(), &mut fs, &scalar);
    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(32));

    // Loads via the CBC path…
    let loaded = load_or_generate(&dev(), None, &mut fs, &mut rng).unwrap();
    assert_eq!(loaded.to_bytes(), expect.to_bytes());

    // …and the boot migration upgrades it to GCM, still the same key.
    migrate_kbase(&dev(), &mut fs, &mut rng);
    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(GCM_LEN));
    let after = load_or_generate(&dev(), None, &mut fs, &mut rng).unwrap();
    assert_eq!(after.to_bytes(), expect.to_bytes());
}
