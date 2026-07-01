// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Device master-seed lifecycle: at-rest sealing, format migrations, the
//! soft-lock wrap and first-boot init (seed / counter / large-blob / cert).
//!
//! The seed (and the org attestation scalar `EF_ATT_KEY`) is stored
//! ChaCha20-Poly1305-sealed under a key HKDF-derived from the device root key
//! (`derive_kbase`), behind a 1-byte format tag: 0x02 is the device-key-only
//! (pre-OTP) arm, 0x12 the OTP-MKEK arm; `migrate_keydev_boot` re-seals across
//! the arm boundary at boot. The record is `[tag] ‖ nonce(12) ‖ ct(32) ‖
//! tag(16)`, AAD = the serial hash. The 12-byte nonce is SYNTHETIC —
//! `HMAC(HMAC(nonce_key, fid), value)` truncated — so the seed and the
//! attestation key (one shared arm key) never share a nonce, and re-sealing the
//! same value is byte-identical: the property that makes the boot migration
//! deterministic and crash-safe without an RNG (the seal it replaces reused a
//! fixed serial-hash IV across both slots and carried no MAC).
//!
//! Older records still load and are re-sealed forward: the pre-AEAD AES-256-CBC
//! wrap (tags 0x01 pre-OTP / 0x11 OTP, fixed IV, no MAC) is read by `cbc_open`
//! and upgraded at boot. The legacy 0x03/0x13 variants add an outer PIN-keyed
//! AEAD over that CBC inner; they are migrated at the first successful PIN
//! verify (`migrate_keydev_pin`), the only moment their outer layer is open — a
//! PIN-wrapped seed makes every UP-only operation (an SSH `ed25519-sk` login,
//! any no-PIN assertion) fail after a power cycle until some clientPIN command
//! runs, and the at-rest protection is the kbase itself (silicon-rooted once the
//! OTP key is burnt).

use zeroize::Zeroize;

#[cfg(test)]
use rsk_crypto::aes_encrypt;
use rsk_crypto::chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_crypto::{Device, Mode, PinKdf, aes_decrypt, hkdf_sha256, hmac_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::error::{Error, Result};

use crate::Rng;
use crate::cert::build_attestation_cert;
use crate::consts::{
    EF_ATT_KEY, EF_COUNTER, EF_EE_DEV, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_LARGEBLOB, LARGEBLOB_INITIAL,
};
use crate::ec::P256Key;

/// Legacy fixed-IV AES-CBC tags (load + migrate only; never written).
const FORMAT_F1: u8 = 0x01; // pre-OTP CBC
const FORMAT_F3: u8 = 0x03; // pre-OTP CBC under an outer PIN AEAD
const FORMAT_F1_OTP: u8 = 0x11; // OTP-arm CBC
const FORMAT_F3_OTP: u8 = 0x13; // OTP-arm CBC under an outer PIN AEAD
/// Current ChaCha20-Poly1305 tags (`[tag] ‖ nonce ‖ ct ‖ tag`).
const FORMAT_G1: u8 = 0x02; // pre-OTP AEAD
const FORMAT_G1_OTP: u8 = 0x12; // OTP-arm AEAD

const KEYDEV_F1_LEN: usize = 33; // legacy: format(1) + CBC ct(32)
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `[tag] ‖ nonce(12) ‖ ct(32) ‖ tag(16)`. Numerically equal to the legacy
/// PIN-wrapped length below; the tag byte (0x02/0x12 vs 0x03/0x13) disambiguates.
const KEYDEV_G1_LEN: usize = 1 + NONCE_LEN + 32 + TAG_LEN;
const KEYDEV_F3_LEN: usize = 61; // legacy PIN-wrapped: format(1) + AEAD(nonce 12 + ct 32 + tag 16)

/// HKDF `info` labels (off the arm's kbase, salt = serial_hash).
const INFO_SEED_ENC: &[u8] = b"KEYDEV/CHACHA";
const INFO_SEED_NONCE: &[u8] = b"KEYDEV/NONCE";

/// `EF_KEY_DEV_ENC` layout: nonce(12) ‖ ChaCha20-Poly1305(seed value, 32) ‖ tag(16).
///
/// The lock wraps the decrypted seed *value*, not the stored file content, so
/// lock/unlock is independent of the at-rest format tag and of the kbase the
/// plain file is sealed under.
pub const LOCK_BLOB_LEN: usize = 12 + 32 + 16;

/// Whether the soft lock is engaged (the wrapped blob is what's on flash).
pub fn lock_engaged<S: Storage>(fs: &mut Fs<S>) -> bool {
    fs.has_key(EF_KEY_DEV_ENC)
}

/// Wrap the seed value under a host-supplied 32-byte lock key (AUT_ENABLE).
pub fn seal_seed_locked(
    rng: &mut impl Rng,
    lock_key: &[u8; 32],
    seed: &[u8; 32],
) -> [u8; LOCK_BLOB_LEN] {
    let mut blob = [0u8; LOCK_BLOB_LEN];
    let (nonce, rest) = blob.split_at_mut(12);
    rng.fill(nonce);
    let (ct, tag) = rest.split_at_mut(32);
    ct.copy_from_slice(seed);
    let nonce12: [u8; 12] = nonce.try_into().unwrap();
    tag.copy_from_slice(&chacha20poly1305_encrypt(lock_key, &nonce12, &[], ct));
    blob
}

/// Unwrap `EF_KEY_DEV_ENC` content with the lock key (vendor UNLOCK). `None` on
/// a wrong key, a tampered blob, or a malformed length.
pub fn open_seed_locked(lock_key: &[u8; 32], blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() != LOCK_BLOB_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&blob[12..44]);
    match chacha20poly1305_decrypt(lock_key, &nonce, &[], &mut seed, &tag) {
        Ok(()) => Some(seed),
        Err(_) => {
            seed.zeroize();
            None
        }
    }
}

/// The ChaCha tag this device generation writes: 0x12 once the OTP key is
/// provisioned, 0x02 before (the only formats ever written).
fn plain_tag(dev: &Device) -> u8 {
    if dev.otp_key.is_some() {
        FORMAT_G1_OTP
    } else {
        FORMAT_G1
    }
}

/// The arm a ChaCha tag was sealed under: 0x02 uses the pre-OTP arm; 0x12 needs
/// the OTP key (None when absent — an OTP-era blob read without the OTP key is
/// orphaned and must fail cleanly, never yield a wrong-key result).
fn gcm_arm<'a>(dev: &Device<'a>, tag: u8) -> Option<Device<'a>> {
    match tag {
        FORMAT_G1 => Some(dev.without_otp()),
        FORMAT_G1_OTP => dev.otp_key.map(|_| *dev),
        _ => None,
    }
}

/// The ChaCha20-Poly1305 sealing key for `arm`: HKDF-SHA256(serial_hash, kbase).
fn seed_enc_key(arm: &Device) -> [u8; 32] {
    let mut kbase = arm.derive_kbase();
    let mut enc = [0u8; 32];
    hkdf_sha256(arm.serial_hash, &kbase, INFO_SEED_ENC, &mut enc).expect("32-byte HKDF output");
    kbase.zeroize();
    enc
}

/// The synthetic-nonce PRF key for `arm`: a second HKDF label off the same kbase.
fn seed_nonce_key(arm: &Device) -> [u8; 32] {
    let mut kbase = arm.derive_kbase();
    let mut nk = [0u8; 32];
    hkdf_sha256(arm.serial_hash, &kbase, INFO_SEED_NONCE, &mut nk).expect("32-byte HKDF output");
    kbase.zeroize();
    nk
}

/// Synthetic 12-byte nonce for `fid`'s `value`: `HMAC(nonce_key, fid)` re-keys a
/// second HMAC over the value. Distinct fids (the seed vs the attestation key)
/// and distinct values both yield distinct nonces, so two records under the one
/// shared arm key never share a (key, nonce) pair; identical material re-seals
/// identically (deterministic → idempotent migration, no RNG).
fn synth_nonce(nonce_key: &[u8; 32], fid: KeyFid, value: &[u8; 32]) -> [u8; NONCE_LEN] {
    let sub = hmac_sha256(nonce_key, &fid.get().to_be_bytes());
    let full = hmac_sha256(&sub, value);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&full[..NONCE_LEN]);
    nonce
}

/// Seal `value` as `[tag] ‖ nonce ‖ ct ‖ tag16` under the current arm's ChaCha
/// key, AAD = serial_hash; `fid` domain-separates the synthetic nonce.
fn seal_gcm(dev: &Device, fid: KeyFid, value: &[u8; 32]) -> [u8; KEYDEV_G1_LEN] {
    let mut nk = seed_nonce_key(dev);
    let nonce = synth_nonce(&nk, fid, value);
    nk.zeroize();
    let mut rec = [0u8; KEYDEV_G1_LEN];
    rec[0] = plain_tag(dev);
    rec[1..1 + NONCE_LEN].copy_from_slice(&nonce);
    let ctpos = 1 + NONCE_LEN;
    rec[ctpos..ctpos + 32].copy_from_slice(value);
    let mut enc = seed_enc_key(dev);
    let tag = chacha20poly1305_encrypt(&enc, &nonce, dev.serial_hash, &mut rec[ctpos..ctpos + 32]);
    enc.zeroize();
    rec[ctpos + 32..].copy_from_slice(&tag);
    rec
}

/// Open a ChaCha record (`0x02`/`0x12`), deriving the key from the tag's arm and
/// authenticating with the serial hash. `None` on a malformed blob, an orphaned
/// OTP-era tag (no OTP key), or an auth failure — a flipped tag byte picks the
/// wrong arm and the MAC rejects it.
fn open_gcm(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != KEYDEV_G1_LEN {
        return None;
    }
    let arm = gcm_arm(dev, buf[0])?;
    let ctpos = 1 + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[1..ctpos]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[ctpos + 32..]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&buf[ctpos..ctpos + 32]);
    let mut enc = seed_enc_key(&arm);
    let r = chacha20poly1305_decrypt(&enc, &nonce, dev.serial_hash, &mut value, &tag);
    enc.zeroize();
    match r {
        Ok(()) => Some(value),
        Err(_) => {
            value.zeroize();
            None
        }
    }
}

/// Decrypt a legacy fixed-IV AES-CBC record (`0x01` pre-OTP / `0x11` OTP, no
/// MAC), kept for load + migration of devices provisioned before the AEAD
/// format. An orphaned `0x11` read without the OTP key returns `None`.
fn cbc_open(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != KEYDEV_F1_LEN {
        return None;
    }
    let arm = match buf[0] {
        FORMAT_F1 => dev.without_otp(),
        FORMAT_F1_OTP => {
            dev.otp_key?;
            *dev
        }
        _ => return None,
    };
    let mut value = [0u8; 32];
    value.copy_from_slice(&buf[1..KEYDEV_F1_LEN]);
    let mut kbase = arm.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let r = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut value);
    kbase.zeroize();
    match r {
        Ok(()) => Some(value),
        Err(_) => {
            value.zeroize();
            None
        }
    }
}

/// Recover a 32-byte value from any supported on-flash form: the current ChaCha
/// AEAD (either arm) or a legacy CBC record. A PIN-wrapped (0x03/0x13) blob
/// returns `None` — it is not loadable until `migrate_keydev_pin` opens its
/// outer layer.
fn open_any(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    open_gcm(dev, buf).or_else(|| cbc_open(dev, buf))
}

/// Read and decrypt the 32-byte device seed. Returns `None` if absent,
/// undecryptable, or still in a legacy PIN-wrapped format (0x03/0x13) — those
/// become loadable again once a successful PIN verify migrates them
/// ([`migrate_keydev_pin`]).
pub fn load_keydev<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_KEY_DEV)
}

/// The org-provisioned FIDO attestation scalar (`EF_ATT_KEY`), sealed exactly
/// like the seed — the tag records which kbase arm wrapped it, so import before
/// or after OTP provisioning both stay loadable.
pub fn load_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Option<[u8; 32]> {
    get_sealed32(dev, fs, EF_ATT_KEY)
}

pub fn store_att_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, key: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_ATT_KEY, key)
}

/// Read and unseal a 32-byte value from any supported at-rest form (read-both).
fn get_sealed32<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Option<[u8; 32]> {
    let mut buf = [0u8; 64];
    let n = fs.read_key(fid, &mut buf)?;
    let out = open_any(dev, &buf[..n.min(buf.len())]);
    buf.zeroize();
    out
}

/// Store `seed` ChaCha20-Poly1305-sealed under the device root key (tag 0x02, or
/// 0x12 once the OTP key is provisioned).
pub fn encrypt_keydev_f1<S: Storage>(dev: &Device, fs: &mut Fs<S>, seed: &[u8; 32]) -> Result<()> {
    put_sealed32(dev, fs, EF_KEY_DEV, seed)
}

/// Seal a 32-byte value under the current arm's ChaCha key and write it to `fid`.
fn put_sealed32<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    value: &[u8; 32],
) -> Result<()> {
    let mut rec = seal_gcm(dev, fid, value);
    let r = fs.put_key(fid, Sealed::wrap(&rec));
    rec.zeroize();
    r
}

/// Boot-pass migration for the seed and the attestation key: bring each to the
/// current ChaCha form under the current kbase arm — upgrading a legacy CBC
/// record (removing the fixed-IV / no-MAC weakness) and re-sealing a pre-OTP
/// blob under the OTP arm once the fuse key is present. A PIN-wrapped (0x03/0x13)
/// seed is left untouched — that migrates at the first PIN verify
/// ([`migrate_keydev_pin`]). Idempotent and crash-safe: each re-seal is one
/// atomic record write, and a torn write leaves the prior record intact.
pub fn migrate_keydev_boot<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Result<()> {
    migrate_slot(dev, fs, EF_KEY_DEV)?;
    migrate_slot(dev, fs, EF_ATT_KEY)
}

/// Re-seal one slot forward if it is not already current-arm ChaCha. Absent
/// slots and unrecoverable (PIN-wrapped) records are no-ops.
fn migrate_slot<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<()> {
    let mut buf = [0u8; 64];
    let Some(n) = fs.read_key(fid, &mut buf) else {
        return Ok(());
    };
    let n = n.min(buf.len());
    // Already current-arm ChaCha? Skip the redundant flash erase (the
    // deterministic re-seal would be byte-identical anyway).
    if buf[0] == plain_tag(dev)
        && let Some(mut v) = open_gcm(dev, &buf[..n])
    {
        v.zeroize();
        buf.zeroize();
        return Ok(());
    }
    let recovered = open_any(dev, &buf[..n]);
    buf.zeroize();
    match recovered {
        Some(mut v) => {
            let r = put_sealed32(dev, fs, fid, &v);
            v.zeroize();
            r
        }
        None => Ok(()),
    }
}

/// Lazy migration of a legacy PIN-wrapped seed (0x03/0x13) forward to the
/// current ChaCha form, callable only when a PIN just verified (the outer AEAD
/// key derives from the PIN hash — the only moment that layer is open). Strips
/// the PIN AEAD, recovers the seed through the inner CBC layer, and re-seals it
/// under the current arm in one atomic write (a pre-OTP blob on an OTP device
/// lands straight at 0x12). No-op for current or unmatchable tags. `pin_hash` is
/// the verified 16-byte PIN hash.
pub fn migrate_keydev_pin<S: Storage>(dev: &Device, fs: &mut Fs<S>, pin_hash: &[u8]) -> Result<()> {
    let mut buf = [0u8; 64];
    let Some(KEYDEV_F3_LEN) = fs.read_key(EF_KEY_DEV, &mut buf) else {
        return Ok(());
    };
    let (seal_dev, cbc_tag) = match buf[0] {
        FORMAT_F3 => (dev.without_otp(), FORMAT_F1),
        FORMAT_F3_OTP if dev.otp_key.is_some() => (*dev, FORMAT_F1_OTP),
        _ => return Ok(()),
    };
    // Strip the outer PIN AEAD, leaving the inner CBC record the seed was sealed
    // in before the PIN was set.
    let mut session = seal_dev.pin_derive_session(pin_hash);
    let mut cbc = [0u8; KEYDEV_F1_LEN];
    cbc[0] = cbc_tag;
    let r = seal_dev.decrypt_with_aad(&session, &buf[1..KEYDEV_F3_LEN], PinKdf::V2, &mut cbc[1..]);
    session.zeroize();
    buf.zeroize();
    if r.is_err() {
        cbc.zeroize();
        return Err(Error::ExecError);
    }
    // Recover the seed through the shared CBC reader and re-seal it forward under
    // the current arm as authenticated ChaCha.
    let recovered = cbc_open(dev, &cbc);
    cbc.zeroize();
    match recovered {
        Some(mut seed) => {
            let r = put_sealed32(dev, fs, EF_KEY_DEV, &seed);
            seed.zeroize();
            r
        }
        None => Err(Error::ExecError),
    }
}

/// First-boot init: generate the seed if absent, initialise the signature
/// counter and the default large-blob array, and create the U2F attestation
/// certificate.
///
/// On a soft-locked device (`EF_KEY_DEV` gone, `EF_KEY_DEV_ENC` present) the
/// seed is NOT regenerated — the wrapped blob *is* the seed — and the
/// attestation step is skipped (the cert already exists from before the lock;
/// the seed is unreadable here anyway).
pub fn ensure_seed<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut impl Rng) -> Result<()> {
    let locked = lock_engaged(fs);
    if !fs.has_key(EF_KEY_DEV) && !locked {
        let mut seed = [0u8; 32];
        loop {
            rng.fill(&mut seed);
            if P256Key::from_scalar(&seed).is_some() {
                break;
            }
        }
        let r = encrypt_keydev_f1(dev, fs, &seed);
        seed.zeroize();
        r?;
    }
    if !fs.has_data(EF_COUNTER) {
        fs.put(EF_COUNTER, &[0u8; 4])?;
    }
    if !fs.has_data(EF_LARGEBLOB) {
        fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL)?;
    }
    if !fs.has_data(EF_EE_DEV) && !locked {
        // Self-signed attestation cert over the device key (the seed scalar).
        let mut seed = load_keydev(dev, fs).ok_or(Error::ExecError)?;
        let key = P256Key::from_scalar(&seed).ok_or(Error::ExecError)?;
        seed.zeroize();
        let mut serial = [0u8; 16];
        rng.fill(&mut serial);
        serial[0] &= 0x7F; // keep the INTEGER positive (no leading 0x00 needed)
        let mut buf = [0u8; 512];
        let n = build_attestation_cert(&key, &serial, &mut buf).ok_or(Error::ExecError)?;
        fs.put(EF_EE_DEV, &buf[..n])?;
    }
    Ok(())
}

/// The global signature counter, stored little-endian.
pub fn get_sign_counter<S: Storage>(fs: &mut Fs<S>) -> u32 {
    let mut buf = [0u8; 4];
    match fs.read(EF_COUNTER, &mut buf) {
        Some(4) => u32::from_le_bytes(buf),
        _ => 0,
    }
}

/// Persist `counter+1`; returns the value *before* the bump — the value to
/// report in the current operation.
pub fn bump_sign_counter<S: Storage>(fs: &mut Fs<S>) -> Result<u32> {
    let ctr = get_sign_counter(fs);
    fs.put(EF_COUNTER, &ctr.wrapping_add(1).to_le_bytes())?;
    Ok(ctr)
}

/// Test-only: `seed` AES-CBC-encrypted under `dev`'s arm (fixed serial-hash IV)
/// as the pre-AEAD legacy record (tag 0x01 pre-OTP / 0x11 OTP), to exercise the
/// boot upgrade path without the old write code.
#[cfg(test)]
pub(crate) fn write_legacy_cbc<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    seed: &[u8; 32],
) {
    let mut ct = *seed;
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    aes_encrypt(&kbase, &iv, Mode::Cbc, &mut ct).unwrap();
    kbase.zeroize();
    let mut out = [0u8; KEYDEV_F1_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F1_OTP
    } else {
        FORMAT_F1
    };
    out[1..].copy_from_slice(&ct);
    ct.zeroize();
    fs.put_key(fid, Sealed::wrap(&out)).unwrap();
}

/// Test-only: build a legacy PIN-wrapped seed record (tag 0x03 pre-OTP / 0x13
/// OTP) — the outer PIN-keyed AEAD over the seed's inner CBC ciphertext — to
/// exercise [`migrate_keydev_pin`]. The tag arm must match the device generation.
#[cfg(test)]
pub(crate) fn wrap_keydev_legacy<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    seed: &[u8; 32],
    pin_hash: &[u8],
) {
    let mut inner = *seed;
    let mut kbase = dev.derive_kbase();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    aes_encrypt(&kbase, &iv, Mode::Cbc, &mut inner).unwrap();
    kbase.zeroize();
    let mut out = [0u8; KEYDEV_F3_LEN];
    out[0] = if dev.otp_key.is_some() {
        FORMAT_F3_OTP
    } else {
        FORMAT_F3
    };
    let session = dev.pin_derive_session(pin_hash);
    dev.encrypt_with_aad(&session, &inner, PinKdf::V2, &[0x24; 12], &mut out[1..])
        .unwrap();
    inner.zeroize();
    fs.put(EF_KEY_DEV.get(), &out).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
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

    const OTP_KEY: [u8; 32] = [0x77; 32];

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    fn fs() -> Fs<RamStorage> {
        Fs::new(RamStorage::new(), &[])
    }

    #[test]
    fn seed_roundtrips_through_flash() {
        let d = dev();
        let mut fs = fs();
        let seed = [0x5A; 32];
        encrypt_keydev_f1(&d, &mut fs, &seed).unwrap();
        // Stored as [tag] ‖ nonce ‖ ct ‖ tag, ChaCha-sealed — not the plaintext.
        assert_eq!(fs.size(EF_KEY_DEV.get()), Some(KEYDEV_G1_LEN));
        let mut raw = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_G1);
        assert_ne!(&raw[13..45], &seed); // the ciphertext, not the seed
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));
    }

    #[test]
    fn wrong_device_cannot_decrypt_seed() {
        let mut fs = fs();
        encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
        let other = Device {
            serial_hash: &[0xCD; 32],
            ..dev()
        };
        // A different root key derives a different AEAD key → the tag rejects it.
        assert_eq!(load_keydev(&other, &mut fs), None);
    }

    #[test]
    fn seal_is_authenticated_against_tamper() {
        // The property the fixed-IV CBC seal lacked: a single flipped ciphertext
        // byte no longer decrypts to a silently-corrupted seed — the MAC refuses.
        let d = dev();
        let mut fs = fs();
        encrypt_keydev_f1(&d, &mut fs, &[0x5A; 32]).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        raw[13] ^= 0x01; // flip a ciphertext byte
        fs.put_key(EF_KEY_DEV, Sealed::wrap(&raw)).unwrap();
        assert_eq!(load_keydev(&d, &mut fs), None);
    }

    #[test]
    fn seed_and_att_key_never_share_a_nonce() {
        // The finding: two same-format scalars under one fixed-IV CBC key leaked
        // via block-0 keystream reuse. The fid-separated synthetic nonce means
        // even an identical value stores differently across the two slots.
        let d = dev();
        let mut fs = fs();
        let value = [0x5A; 32];
        encrypt_keydev_f1(&d, &mut fs, &value).unwrap();
        store_att_key(&d, &mut fs, &value).unwrap();
        let mut a = [0u8; KEYDEV_G1_LEN];
        let mut b = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut a).unwrap();
        fs.read(EF_ATT_KEY.get(), &mut b).unwrap();
        assert_ne!(&a[1..13], &b[1..13]); // distinct nonces
        assert_ne!(&a[13..45], &b[13..45]); // distinct ciphertext
        assert_eq!(load_keydev(&d, &mut fs), Some(value));
        assert_eq!(load_att_key(&d, &mut fs), Some(value));
    }

    #[test]
    fn legacy_cbc_record_loads_and_upgrades_at_boot() {
        // A device provisioned before the AEAD format holds a fixed-IV CBC
        // record; it must still load, and the boot pass upgrades it to ChaCha.
        let d = dev();
        let mut fs = fs();
        let seed = [0x5A; 32];
        write_legacy_cbc(&d, &mut fs, EF_KEY_DEV, &seed);
        assert_eq!(fs.size(EF_KEY_DEV.get()), Some(KEYDEV_F1_LEN));
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));

        migrate_keydev_boot(&d, &mut fs).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_G1_LEN));
        assert_eq!(raw[0], FORMAT_G1);
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));

        // Idempotent AND byte-deterministic (synthetic nonce): a second pass
        // leaves the record identical.
        migrate_keydev_boot(&d, &mut fs).unwrap();
        let mut again = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut again).unwrap();
        assert_eq!(raw, again);
    }

    #[test]
    fn att_key_legacy_cbc_migrates_at_boot() {
        // The attestation scalar shares the seal path and the boot migration.
        let d = dev();
        let mut fs = fs();
        let att = [0x21; 32];
        write_legacy_cbc(&d, &mut fs, EF_ATT_KEY, &att);
        assert_eq!(load_att_key(&d, &mut fs), Some(att));
        migrate_keydev_boot(&d, &mut fs).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        assert_eq!(fs.read(EF_ATT_KEY.get(), &mut raw), Some(KEYDEV_G1_LEN));
        assert_eq!(raw[0], FORMAT_G1);
        assert_eq!(load_att_key(&d, &mut fs), Some(att));
    }

    #[test]
    fn legacy_pin_wrapped_seed_unreadable_until_pin_migrates_it() {
        let d = dev();
        let mut fs = fs();
        let seed = [0x5A; 32];
        let pin_hash = [0x99u8; 16];
        wrap_keydev_legacy(&d, &mut fs, &seed, &pin_hash);
        assert_eq!(fs.size(EF_KEY_DEV.get()), Some(KEYDEV_F3_LEN));
        // The wrapped blob is unreadable (the UP-only failure window)…
        assert_eq!(load_keydev(&d, &mut fs), None);
        // …until a PIN verify unwraps it forward to plain ChaCha, permanently.
        migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_G1_LEN));
        assert_eq!(raw[0], FORMAT_G1);
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));
        // Idempotent.
        migrate_keydev_pin(&d, &mut fs, &pin_hash).unwrap();
        assert_eq!(load_keydev(&d, &mut fs), Some(seed));
    }

    #[test]
    fn migration_with_wrong_pin_fails_and_leaves_blob_intact() {
        let d = dev();
        let mut fs = fs();
        wrap_keydev_legacy(&d, &mut fs, &[0x5A; 32], &[0x99u8; 16]);
        assert!(migrate_keydev_pin(&d, &mut fs, &[0x11u8; 16]).is_err());
        let mut raw = [0u8; KEYDEV_F3_LEN];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(KEYDEV_F3_LEN));
        assert_eq!(raw[0], FORMAT_F3);
    }

    #[test]
    fn ensure_seed_is_idempotent() {
        let d = dev();
        let mut fs = fs();
        let mut rng = SeqRng(7);
        ensure_seed(&d, &mut fs, &mut rng).unwrap();
        let seed1 = load_keydev(&d, &mut fs).unwrap();
        assert!(fs.has_data(EF_COUNTER));
        assert_eq!(get_sign_counter(&mut fs), 0);
        // A second scan must not regenerate the seed.
        ensure_seed(&d, &mut fs, &mut rng).unwrap();
        assert_eq!(load_keydev(&d, &mut fs).unwrap(), seed1);
        assert!(P256Key::from_scalar(&seed1).is_some());
    }

    #[test]
    fn counter_bumps_and_persists() {
        let mut fs = fs();
        fs.put(EF_COUNTER, &[0u8; 4]).unwrap();
        assert_eq!(bump_sign_counter(&mut fs).unwrap(), 0);
        assert_eq!(bump_sign_counter(&mut fs).unwrap(), 1);
        assert_eq!(get_sign_counter(&mut fs), 2);
    }

    #[test]
    fn lock_blob_roundtrips_and_authenticates() {
        let mut rng = SeqRng(3);
        let key = [0x4D; 32];
        let seed = [0x5A; 32];
        let blob = seal_seed_locked(&mut rng, &key, &seed);
        assert_eq!(open_seed_locked(&key, &blob), Some(seed));
        // Wrong key, tampered ciphertext, truncated blob: all refused.
        assert_eq!(open_seed_locked(&[0x4E; 32], &blob), None);
        let mut bad = blob;
        bad[20] ^= 1;
        assert_eq!(open_seed_locked(&key, &bad), None);
        assert_eq!(open_seed_locked(&key, &blob[..LOCK_BLOB_LEN - 1]), None);
    }

    #[test]
    fn ensure_seed_skips_generation_when_locked() {
        // A locked device has only the wrapped blob on flash; a boot pass must
        // not invent a fresh seed next to it (that would fork the identity).
        let d = dev();
        let mut fs = fs();
        let mut rng = SeqRng(9);
        let blob = seal_seed_locked(&mut rng, &[0x4D; 32], &[0x5A; 32]);
        fs.put(EF_KEY_DEV_ENC.get(), &blob).unwrap();
        ensure_seed(&d, &mut fs, &mut rng).unwrap();
        assert!(!fs.has_data(EF_KEY_DEV.get()));
        assert!(fs.has_data(EF_COUNTER)); // the rest of the scan still runs
        assert!(!fs.has_data(EF_EE_DEV)); // cert step skipped (seed unreadable)
    }

    #[test]
    fn boot_migration_reseals_plain_seed_to_otp_kbase() {
        let mut fs = fs();
        let seed = [0x5A; 32];
        encrypt_keydev_f1(&dev(), &mut fs, &seed).unwrap(); // 0x02 pre-OTP arm

        migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_G1_OTP);
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));

        // Idempotent: a second pass is a no-op (tag already 0x12).
        migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
    }

    #[test]
    fn boot_migration_without_otp_is_noop() {
        let mut fs = fs();
        encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
        migrate_keydev_boot(&dev(), &mut fs).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_G1);
    }

    #[test]
    fn otp_era_seed_fails_cleanly_without_otp_key() {
        // Downgrade scenario: a 0x12 blob read by a no-OTP device must yield a
        // clean None, never a wrong-key result masquerading as a seed.
        let mut fs = fs();
        let seed = [0x5A; 32];
        encrypt_keydev_f1(&otp_dev(), &mut fs, &seed).unwrap();
        let mut raw = [0u8; KEYDEV_G1_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_G1_OTP);
        assert_eq!(load_keydev(&dev(), &mut fs), None);
    }

    #[test]
    fn pre_otp_wrapped_seed_migrates_to_otp_plain_at_verify() {
        let mut fs = fs();
        let seed = [0x5A; 32];
        let pin_hash = [0x99u8; 16];

        // Legacy pre-OTP layout: plain seed, then a PIN set wrapped it (0x03).
        wrap_keydev_legacy(&dev(), &mut fs, &seed, &pin_hash);
        let mut raw = [0u8; KEYDEV_F3_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_F3);

        // The boot pass cannot touch a PIN-wrapped blob.
        migrate_keydev_boot(&otp_dev(), &mut fs).unwrap();
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_F3);

        // First PIN verify on the OTP build unwraps the outer layer AND re-seals
        // forward — straight to a plain 0x12, loadable with no session.
        migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
        let mut g = [0u8; KEYDEV_G1_LEN];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut g), Some(KEYDEV_G1_LEN));
        assert_eq!(g[0], FORMAT_G1_OTP);
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));

        // Idempotent.
        migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
    }

    #[test]
    fn otp_wrapped_seed_migrates_to_plain_at_verify() {
        // A legacy 0x13 blob unwraps to 0x12 at verify; without the OTP key it
        // is left untouched.
        let mut fs = fs();
        let seed = [0x5A; 32];
        let pin_hash = [0x99u8; 16];
        wrap_keydev_legacy(&otp_dev(), &mut fs, &seed, &pin_hash);
        let mut raw = [0u8; KEYDEV_F3_LEN];
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_F3_OTP);

        // Orphan on a no-OTP build: no-op, no error, still closed.
        migrate_keydev_pin(&dev(), &mut fs, &pin_hash).unwrap();
        fs.read(EF_KEY_DEV.get(), &mut raw).unwrap();
        assert_eq!(raw[0], FORMAT_F3_OTP);
        assert_eq!(load_keydev(&dev(), &mut fs), None);

        migrate_keydev_pin(&otp_dev(), &mut fs, &pin_hash).unwrap();
        let mut g = [0u8; KEYDEV_G1_LEN];
        assert_eq!(fs.read(EF_KEY_DEV.get(), &mut g), Some(KEYDEV_G1_LEN));
        assert_eq!(g[0], FORMAT_G1_OTP);
        assert_eq!(load_keydev(&otp_dev(), &mut fs), Some(seed));
    }
}
