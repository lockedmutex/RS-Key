// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Read-only slot metadata for the trusted display. PIV slot introspection is
//! entirely `rsk-fs` metadata — key presence, algorithm and PIN/touch policy
//! from the meta side-store, certificate presence — none of which needs a PIN
//! or the management key, so an on-device screen can show it freely. The private
//! key bytes are sealed and never surfaced; the public point is *not* read (that
//! is the management-key-gated GET METADATA path, deliberately out of scope).

use rsk_fs::{Fs, Storage};

use crate::files::*;

/// The four primary asymmetric slots, in display order: Authentication (9A),
/// Signing (9C), Key Management (9D), Card Authentication (9E). The card-mgmt
/// (9B), attestation (F9) and retired (82–95) slots are plumbing / advanced and
/// are left off the at-a-glance screen.
pub const PRIMARY_SLOTS: [u8; 4] = [
    SLOT_AUTHENTICATION,
    SLOT_SIGNATURE,
    SLOT_KEYMGM,
    SLOT_CARDAUTH,
];

/// What one PIV slot holds, all read without a PIN or the management key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PivSlot {
    /// Wire key reference (`0x9A` …).
    pub slot: u8,
    /// Whether a private key is present in the slot.
    pub present: bool,
    /// Key algorithm (`ALGO_*`), or `0` when no key.
    pub algo: u8,
    /// PIN policy (`PINPOLICY_*`).
    pub pin_policy: u8,
    /// Touch policy (`TOUCHPOLICY_*`).
    pub touch_policy: u8,
    /// Key origin (`ORIGIN_*`), or `0` when unknown.
    pub origin: u8,
    /// Whether an X.509 certificate is stored for the slot.
    pub cert: bool,
}

/// A read-only snapshot of the PIV applet's public state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PivInfo {
    /// The four primary slots, in [`PRIMARY_SLOTS`] order.
    pub slots: [PivSlot; 4],
    /// Remaining PIN attempts.
    pub pin_retries: u8,
    /// Remaining PUK attempts.
    pub puk_retries: u8,
}

impl PivInfo {
    /// How many primary slots hold a key or a certificate.
    pub fn populated(&self) -> u8 {
        self.slots.iter().filter(|s| s.present || s.cert).count() as u8
    }
}

/// A short ASCII label for a PIV key reference.
pub fn slot_name(slot: u8) -> &'static str {
    match slot {
        SLOT_AUTHENTICATION => "Authentication",
        SLOT_SIGNATURE => "Signature",
        SLOT_KEYMGM => "Key Management",
        SLOT_CARDAUTH => "Card Auth",
        SLOT_CARDMGM => "Management",
        SLOT_ATTESTATION => "Attestation",
        _ => "Retired",
    }
}

/// A short ASCII label for a PIV algorithm id (`ALGO_*`).
pub fn algo_name(algo: u8) -> &'static str {
    match algo {
        ALGO_RSA1024 => "RSA 1024",
        ALGO_RSA2048 => "RSA 2048",
        ALGO_RSA3072 => "RSA 3072",
        ALGO_RSA4096 => "RSA 4096",
        ALGO_ECCP256 => "NIST P-256",
        ALGO_ECCP384 => "NIST P-384",
        ALGO_X25519 => "X25519",
        ALGO_3DES => "3DES",
        ALGO_AES128 => "AES-128",
        ALGO_AES192 => "AES-192",
        ALGO_AES256 => "AES-256",
        _ => "—",
    }
}

/// A short ASCII label for a PIN policy (`PINPOLICY_*`).
pub fn pin_policy_name(p: u8) -> &'static str {
    match p {
        PINPOLICY_NEVER => "Never",
        PINPOLICY_ONCE => "Once",
        PINPOLICY_ALWAYS => "Always",
        _ => "Default",
    }
}

/// A short ASCII label for a touch policy (`TOUCHPOLICY_*`).
pub fn touch_policy_name(p: u8) -> &'static str {
    match p {
        TOUCHPOLICY_NEVER => "Never",
        TOUCHPOLICY_ALWAYS => "Always",
        TOUCHPOLICY_CACHED => "Cached",
        _ => "Default",
    }
}

/// A short ASCII label for a key origin (`ORIGIN_*`).
pub fn origin_name(o: u8) -> &'static str {
    match o {
        ORIGIN_GENERATED => "Generated",
        ORIGIN_IMPORTED => "Imported",
        _ => "—",
    }
}

/// Read the public state of the PIV applet for the trusted display.
pub fn read_info<S: Storage>(fs: &mut Fs<S>) -> PivInfo {
    let mut slots = [PivSlot {
        slot: 0,
        present: false,
        algo: 0,
        pin_policy: 0,
        touch_policy: 0,
        origin: 0,
        cert: false,
    }; 4];
    for (i, &slot) in PRIMARY_SLOTS.iter().enumerate() {
        let present = fs.has_key(key_fid(slot));
        let mut meta = [0u8; 4];
        let (algo, pin_policy, touch_policy, origin) = if present {
            match fs.meta_find(key_fid(slot).get(), &mut meta) {
                Some(n) if n >= 3 => (meta[0], meta[1], meta[2], if n >= 4 { meta[3] } else { 0 }),
                _ => (0, 0, 0, 0),
            }
        } else {
            (0, 0, 0, 0)
        };
        let cert = cert_fid_for_slot(slot).is_some_and(|f| fs.has_data(f));
        slots[i] = PivSlot {
            slot,
            present,
            algo,
            pin_policy,
            touch_policy,
            origin,
            cert,
        };
    }

    let mut r = [0u8; 4];
    let (pin_retries, puk_retries) = match fs.read(EF_RETRIES, &mut r) {
        Some(n) if n >= 4 => (r[1], r[3]),
        _ => (DEFAULT_RETRIES, DEFAULT_RETRIES),
    };

    PivInfo {
        slots,
        pin_retries,
        puk_retries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    fn fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    #[test]
    fn empty_card_has_no_slots_and_default_retries() {
        let mut fs = fs();
        let info = read_info(&mut fs);
        assert_eq!(info.populated(), 0);
        for s in &info.slots {
            assert!(!s.present && !s.cert);
            assert_eq!(s.algo, 0);
        }
        assert_eq!((info.pin_retries, info.puk_retries), (3, 3));
    }

    #[test]
    fn auth_slot_reads_algo_and_policy_from_meta() {
        let mut fs = fs();
        fs.put(key_fid(SLOT_AUTHENTICATION).get(), &[0xAB; 64])
            .unwrap();
        fs.meta_add(
            key_fid(SLOT_AUTHENTICATION).get(),
            &[
                ALGO_ECCP256,
                PINPOLICY_ALWAYS,
                TOUCHPOLICY_CACHED,
                ORIGIN_GENERATED,
            ],
        )
        .unwrap();
        let s = read_info(&mut fs).slots[0];
        assert_eq!(s.slot, SLOT_AUTHENTICATION);
        assert!(s.present);
        assert_eq!(algo_name(s.algo), "NIST P-256");
        assert_eq!(pin_policy_name(s.pin_policy), "Always");
        assert_eq!(touch_policy_name(s.touch_policy), "Cached");
        assert_eq!(origin_name(s.origin), "Generated");
    }

    #[test]
    fn cert_without_key_counts_as_populated() {
        let mut fs = fs();
        let cert_fid = cert_fid_for_slot(SLOT_SIGNATURE).unwrap();
        fs.put(cert_fid, &[0x30, 0x03, 0x01, 0x02, 0x03]).unwrap();
        let info = read_info(&mut fs);
        assert!(!info.slots[1].present);
        assert!(info.slots[1].cert);
        assert_eq!(info.populated(), 1);
    }

    #[test]
    fn retries_come_from_ef_retries() {
        let mut fs = fs();
        fs.put(EF_RETRIES, &[3, 2, 3, 0]).unwrap();
        let info = read_info(&mut fs);
        assert_eq!((info.pin_retries, info.puk_retries), (2, 0));
    }
}
