// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Read-only key metadata for the trusted display. Every fact here is plaintext
//! or computed from plaintext — no DEK unseal, no PIN, no host session — so an
//! on-device screen can show the OpenPGP card's slots without ever touching a
//! secret. It mirrors what the GET DATA builder ([`crate::dobj`]) reads, but
//! returns typed values instead of TLV. The private key scalars and public
//! points are deliberately *not* exposed: the public point is reconstructed only
//! on GENERATE / INTERNAL AUTH after a PIN, so a passive read cannot show it.

use rsk_fs::{Fs, KeyFid, Storage};

use crate::consts::*;
use crate::keys::{Curve, curve_from_attr};

/// The three OpenPGP key slots (SIG, DEC, AUT), in card order.
pub const SLOTS: usize = 3;

/// Per-slot EF bases; slot `s` in `0..SLOTS` reads `base + s` (the SIG/DEC/AUT
/// FIDs are consecutive — see [`crate::consts`]).
const PK_FIDS: [KeyFid; SLOTS] = [EF_PK_SIG, EF_PK_DEC, EF_PK_AUT];

/// A slot's algorithm, decoded from its stored attribute (`[algo_id ‖ oid]`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotAlgo {
    /// No key in the slot.
    None,
    /// RSA with the given modulus size in bits.
    Rsa(u16),
    /// A supported EC curve.
    Ec(Curve),
    /// A key is present but its attribute is unrecognised.
    Unknown,
}

impl SlotAlgo {
    /// A short ASCII label for the slot row / detail (≤10 chars).
    pub fn label(self) -> &'static str {
        match self {
            SlotAlgo::None => "—",
            SlotAlgo::Rsa(1024) => "RSA 1024",
            SlotAlgo::Rsa(2048) => "RSA 2048",
            SlotAlgo::Rsa(3072) => "RSA 3072",
            SlotAlgo::Rsa(4096) => "RSA 4096",
            SlotAlgo::Rsa(_) => "RSA",
            SlotAlgo::Ec(Curve::P256) => "NIST P-256",
            SlotAlgo::Ec(Curve::P384) => "NIST P-384",
            SlotAlgo::Ec(Curve::P521) => "NIST P-521",
            SlotAlgo::Ec(Curve::K256) => "secp256k1",
            SlotAlgo::Ec(Curve::Ed25519) => "Ed25519",
            SlotAlgo::Ec(Curve::X25519) => "Cv25519",
            SlotAlgo::Unknown => "Key set",
        }
    }
}

/// What one OpenPGP slot holds, all read without a PIN.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotInfo {
    pub present: bool,
    pub algo: SlotAlgo,
    /// 20-byte SHA-1 key fingerprint, or `None` when unset (absent / all-zero).
    pub fingerprint: Option<[u8; 20]>,
    /// Whether a generation timestamp is recorded. The device has no real-time
    /// clock, so the value itself is meaningless to show — only presence is.
    pub created: bool,
    /// Whether the UIF touch policy gates use of the slot.
    pub touch: bool,
}

/// A read-only snapshot of the OpenPGP card's public state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenpgpInfo {
    /// SIG, DEC, AUT in card order.
    pub slots: [SlotInfo; SLOTS],
    /// PSO:CDS signature counter.
    pub sig_count: u32,
    /// Remaining PW1 (user) PIN attempts.
    pub pw1_retries: u8,
    /// Remaining PW3 (admin) PIN attempts.
    pub pw3_retries: u8,
}

impl OpenpgpInfo {
    /// How many of the three slots hold a key.
    pub fn key_count(&self) -> u8 {
        self.slots.iter().filter(|s| s.present).count() as u8
    }
}

fn slot_algo<S: Storage>(fs: &mut Fs<S>, slot: usize, present: bool) -> SlotAlgo {
    if !present {
        return SlotAlgo::None;
    }
    let mut buf = [0u8; 16];
    let attr = match fs.read(EF_ALGO_PRIV1 + slot as u16, &mut buf) {
        // A key with no stored attribute is the applet's rsa2k default.
        Some(n) if n >= 1 => &buf[..n],
        _ => return SlotAlgo::Rsa(2048),
    };
    match attr[0] {
        ALGO_RSA => {
            let bits = if attr.len() >= 3 {
                u16::from_be_bytes([attr[1], attr[2]])
            } else {
                0
            };
            SlotAlgo::Rsa(bits)
        }
        _ => match curve_from_attr(attr) {
            Some(c) => SlotAlgo::Ec(c),
            None => SlotAlgo::Unknown,
        },
    }
}

/// Read the public state of the OpenPGP applet for the trusted display.
pub fn read_info<S: Storage>(fs: &mut Fs<S>) -> OpenpgpInfo {
    let mut slots = [SlotInfo {
        present: false,
        algo: SlotAlgo::None,
        fingerprint: None,
        created: false,
        touch: false,
    }; SLOTS];
    for (s, slot) in slots.iter_mut().enumerate() {
        let present = fs.has_key(PK_FIDS[s]);
        let mut fp = [0u8; 20];
        let fingerprint = match fs.read(EF_FP_SIG + s as u16, &mut fp) {
            Some(n) if n > 0 && fp[..n].iter().any(|&b| b != 0) => Some(fp),
            _ => None,
        };
        let mut ts = [0u8; 4];
        let created = matches!(fs.read(EF_TS_SIG + s as u16, &mut ts), Some(n) if ts[..n].iter().any(|&b| b != 0));
        let mut uif = [0u8; 2];
        let touch =
            matches!(fs.read(EF_UIF_SIG + s as u16, &mut uif), Some(n) if n >= 1 && uif[0] != 0);
        *slot = SlotInfo {
            present,
            algo: slot_algo(fs, s, present),
            fingerprint,
            created,
            touch,
        };
    }

    let mut c = [0u8; 3];
    let sig_count = match fs.read(EF_SIG_COUNT, &mut c) {
        Some(3) => u32::from_be_bytes([0, c[0], c[1], c[2]]),
        _ => 0,
    };

    let mut pw = [0u8; 7];
    let (pw1_retries, pw3_retries) = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) if n >= 7 => (pw[4], pw[6]),
        _ => (PW_RETRIES_DEFAULT, PW_RETRIES_DEFAULT),
    };

    OpenpgpInfo {
        slots,
        sig_count,
        pw1_retries,
        pw3_retries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_fs::storage::ram::RamStorage;

    // Stored algorithm-attribute values (the form `[algo_id ‖ oid]`, no length
    // prefix — that is what PUT DATA C1/C2/C3 lands in EF_ALGO_PRIV*).
    const ATTR_ED25519: &[u8] = &[0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
    const ATTR_P256: &[u8] = &[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    fn fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.scan();
        fs
    }

    #[test]
    fn empty_card_has_no_keys_and_default_retries() {
        let mut fs = fs();
        let info = read_info(&mut fs);
        assert_eq!(info.key_count(), 0);
        for s in &info.slots {
            assert!(!s.present);
            assert_eq!(s.algo, SlotAlgo::None);
            assert!(s.fingerprint.is_none());
            assert!(!s.created && !s.touch);
        }
        assert_eq!(info.sig_count, 0);
        // No EF_PW_PRIV seeded → the reader falls back to the default 3/3.
        assert_eq!((info.pw1_retries, info.pw3_retries), (3, 3));
    }

    #[test]
    fn sig_slot_decodes_ed25519_with_fingerprint_and_touch() {
        let mut fs = fs();
        fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
        fs.put(EF_ALGO_PRIV1, ATTR_ED25519).unwrap();
        fs.put(EF_FP_SIG, &[0x11; 20]).unwrap();
        fs.put(EF_UIF_SIG, &[0x01, 0x20]).unwrap();
        fs.put(EF_TS_SIG, &0x6500_0000u32.to_be_bytes()).unwrap();
        let s = read_info(&mut fs).slots[0];
        assert!(s.present);
        assert_eq!(s.algo, SlotAlgo::Ec(Curve::Ed25519));
        assert_eq!(s.algo.label(), "Ed25519");
        assert_eq!(s.fingerprint, Some([0x11; 20]));
        assert!(s.created);
        assert!(s.touch);
    }

    #[test]
    fn dec_slot_p256_aut_slot_defaults_to_rsa2k() {
        let mut fs = fs();
        fs.put(EF_PK_DEC.get(), &[0xCD; 32]).unwrap();
        fs.put(EF_ALGO_PRIV2, ATTR_P256).unwrap();
        // AUT key present but no stored attribute → the applet default rsa2k.
        fs.put(EF_PK_AUT.get(), &[0xEF; 256]).unwrap();
        let info = read_info(&mut fs);
        assert_eq!(info.slots[1].algo, SlotAlgo::Ec(Curve::P256));
        assert_eq!(info.slots[1].algo.label(), "NIST P-256");
        assert_eq!(info.slots[2].algo, SlotAlgo::Rsa(2048));
        assert_eq!(info.slots[2].algo.label(), "RSA 2048");
        assert!(info.slots[1].fingerprint.is_none());
        assert_eq!(info.key_count(), 2);
    }

    #[test]
    fn pw_status_and_sig_counter_are_read() {
        let mut fs = fs();
        fs.put(EF_PW_PRIV, &[0x01, 127, 127, 127, 2, 3, 1]).unwrap();
        fs.put(EF_SIG_COUNT, &[0x00, 0x00, 0x2A]).unwrap();
        let info = read_info(&mut fs);
        assert_eq!((info.pw1_retries, info.pw3_retries), (2, 1));
        assert_eq!(info.sig_count, 42);
    }
}
