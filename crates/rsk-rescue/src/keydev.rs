// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The rescue device key: a secp256k1 keypair for device attestation. A
//! provisioned OTP DEVK is the scalar itself; otherwise the key lives sealed in
//! flash (`EF_DEVCERT_KEY`), minted on first use. The seal is AES-256-GCM
//! (`[fmt] ‖ nonce ‖ ct ‖ tag`) under a key HKDF-derived from `derive_kbase`: an
//! authenticated blob with a random nonce, so a pre-secure-boot flash-writer can
//! neither forge nor silently corrupt it. Older AES-256-CBC records (fixed
//! serial-hash IV, no MAC) still load and are re-sealed as GCM by
//! [`migrate_kbase`] at boot.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use rsk_crypto::{Device, Mode, aes_decrypt, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use zeroize::Zeroize;

use crate::Rng;

/// The sealed device key. Outside every applet reset scope, like `EF_PHY`.
pub const EF_DEVCERT_KEY: KeyFid = KeyFid::new(0xE0C1);
/// The uploaded device attestation certificate.
pub const EF_DEVCERT: u16 = 0x2F02;

/// AEAD generation marker for a GCM-sealed keydev blob (`[0x20] ‖ nonce ‖ ct ‖
/// tag`). Distinguishes the current format from the legacy CBC records — a bare
/// 32-byte blob (pre-OTP CBC) or `[0x11] ‖ ct` (OTP-arm CBC).
const FMT_GCM: u8 = 0x20;
/// Legacy tag: an OTP-arm AES-CBC record (33 bytes). Retained for load +
/// migration only; no new record uses CBC.
const TAG_OTP: u8 = 0x11;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `[FMT_GCM] ‖ nonce(12) ‖ ct(32) ‖ tag(16)`.
const GCM_LEN: usize = 1 + NONCE_LEN + 32 + TAG_LEN;

const INFO_KEYDEV: &[u8] = b"KEYDEV/SEAL";

/// The GCM sealing key for `arm`: HKDF-SHA256(serial_hash, kbase(arm), info).
fn kenc(arm: &Device) -> [u8; 32] {
    let mut kbase = arm.derive_kbase();
    let mut out = [0u8; 32];
    hkdf_sha256(arm.serial_hash, &kbase, INFO_KEYDEV, &mut out).expect("32-byte HKDF output");
    kbase.zeroize();
    out
}

/// Seal `scalar` as `[FMT_GCM] ‖ nonce ‖ ct ‖ tag` under the current arm's key,
/// AAD = serial_hash.
fn seal_gcm(dev: &Device, rng: &mut dyn Rng, scalar: &[u8; 32]) -> [u8; GCM_LEN] {
    let mut rec = [0u8; GCM_LEN];
    rec[0] = FMT_GCM;
    rng.fill(&mut rec[1..1 + NONCE_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&rec[1..1 + NONCE_LEN]);
    let ctpos = 1 + NONCE_LEN;
    rec[ctpos..ctpos + 32].copy_from_slice(scalar);
    let mut key = kenc(dev);
    let tag = aes256gcm_encrypt(&key, &nonce, dev.serial_hash, &mut rec[ctpos..ctpos + 32]);
    key.zeroize();
    rec[ctpos + 32..].copy_from_slice(&tag);
    rec
}

/// GCM-open a keydev blob, deriving the key from `arm` and authenticating with
/// `dev.serial_hash` as AAD. `None` on a malformed blob or auth failure.
fn gcm_open(dev: &Device, arm: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() != GCM_LEN || buf[0] != FMT_GCM {
        return None;
    }
    let ctpos = 1 + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[1..ctpos]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[ctpos + 32..]);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&buf[ctpos..ctpos + 32]);
    let mut key = kenc(arm);
    let r = aes256gcm_decrypt(&key, &nonce, dev.serial_hash, &mut scalar, &tag);
    key.zeroize();
    if r.is_ok() {
        Some(scalar)
    } else {
        scalar.zeroize();
        None
    }
}

/// Decrypt a legacy AES-CBC keydev record (fixed serial-hash IV, no MAC): a bare
/// 32-byte pre-OTP blob or the tagged 33-byte OTP-arm blob. Kept for load +
/// migration of devices provisioned before the GCM format.
fn cbc_open(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&dev.serial_hash[..16]);
    let mut scalar = [0u8; 32];
    let mut kbase = match buf.len() {
        32 => {
            scalar.copy_from_slice(&buf[..32]);
            dev.without_otp().derive_kbase()
        }
        33 if buf[0] == TAG_OTP => {
            dev.otp_key?;
            scalar.copy_from_slice(&buf[1..33]);
            dev.derive_kbase()
        }
        _ => return None,
    };
    let r = aes_decrypt(&kbase, &iv, Mode::Cbc, &mut scalar);
    kbase.zeroize();
    if r.is_ok() {
        Some(scalar)
    } else {
        scalar.zeroize();
        None
    }
}

/// Recover the keydev scalar from any supported on-flash form: GCM under the
/// current arm, GCM under the pre-OTP arm (a key sealed before provisioning),
/// or a legacy CBC record.
fn unseal_scalar(dev: &Device, buf: &[u8]) -> Option<[u8; 32]> {
    if let Some(s) = gcm_open(dev, dev, buf) {
        return Some(s);
    }
    if dev.otp_key.is_some()
        && let Some(s) = gcm_open(dev, &dev.without_otp(), buf)
    {
        return Some(s);
    }
    cbc_open(dev, buf)
}

/// A provisioned DEVK is the scalar itself (no flash, no derivation); an
/// invalid DEVK scalar fails outright, with no flash fallback. Without a DEVK,
/// unseal the stored key or mint + GCM-seal one first.
pub fn load_or_generate<S: Storage>(
    dev: &Device,
    devk: Option<&[u8; 32]>,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
) -> Option<SigningKey> {
    if let Some(devk) = devk {
        return SigningKey::from_bytes(devk.into()).ok();
    }
    let mut buf = [0u8; GCM_LEN];
    let key = match fs.read_key(EF_DEVCERT_KEY, &mut buf) {
        Some(n) => {
            let mut scalar = unseal_scalar(dev, &buf[..n.min(GCM_LEN)])?;
            let k = SigningKey::from_bytes(&scalar.into()).ok();
            scalar.zeroize();
            k
        }
        None => {
            // Draw until the scalar is a valid non-zero field element
            // (overwhelmingly the first draw), then persist it GCM-sealed.
            let mut scalar = [0u8; 32];
            let key = loop {
                rng.fill(&mut scalar);
                if let Ok(k) = SigningKey::from_bytes(&scalar.into()) {
                    break k;
                }
            };
            let rec = seal_gcm(dev, rng, &scalar);
            scalar.zeroize();
            if fs.put_key(EF_DEVCERT_KEY, Sealed::wrap(&rec)).is_err() {
                return None;
            }
            Some(key)
        }
    };
    buf.zeroize();
    key
}

/// Boot-pass migration: bring the stored keydev to the current GCM form under
/// the current kbase arm. Upgrades a legacy CBC record (removing the fixed-IV /
/// no-MAC weakness) and re-seals a pre-OTP GCM blob under the OTP arm once the
/// fuse key is present. No-op when the key is absent or already current;
/// idempotent (the re-seal is one atomic record write).
pub fn migrate_kbase<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    let mut buf = [0u8; GCM_LEN];
    let Some(n) = fs.read_key(EF_DEVCERT_KEY, &mut buf) else {
        buf.zeroize();
        return;
    };
    let n = n.min(GCM_LEN);
    // Already GCM under the current arm? Nothing to do.
    if let Some(mut s) = gcm_open(dev, dev, &buf[..n]) {
        s.zeroize();
        buf.zeroize();
        return;
    }
    // Otherwise recover via the pre-OTP GCM arm or a legacy CBC record and
    // re-seal as GCM under the current arm.
    if let Some(mut scalar) = unseal_scalar(dev, &buf[..n]) {
        let rec = seal_gcm(dev, rng, &scalar);
        scalar.zeroize();
        let _ = fs.put_key(EF_DEVCERT_KEY, Sealed::wrap(&rec));
    }
    buf.zeroize();
}

/// ECDSA over a host-supplied 32-byte digest; returns r || s (64 bytes), with
/// RFC 6979 deterministic nonces.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Option<[u8; 64]> {
    let sig: Signature = key.sign_prehash(digest).ok()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Some(out)
}

/// The uncompressed SEC1 public point (65 bytes), as KEYDEV_SIGN P1=0x02
/// returns it.
pub fn public_uncompressed(key: &SigningKey) -> [u8; 65] {
    let mut out = [0u8; 65];
    let pt = key.verifying_key().to_encoded_point(false);
    out.copy_from_slice(pt.as_bytes());
    out
}

#[cfg(test)]
mod tests {
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
        Fs::new(RamStorage::new(), &[])
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
}
