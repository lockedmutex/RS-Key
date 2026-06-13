// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Typed-ticket generation — what a button press "types" as keystrokes: a
//! 44-char modhex Yubico OTP (6-byte public id ‖ AES-128-ECB private block), an
//! OATH-HOTP 6/8-digit code, or a static password of raw scancodes. [`build`] is pure.

use rsk_crypto::{aes128_encrypt_block, hmac_sha1};

use crate::{
    CFG_OATH_HOTP8, CFG_SHORT_TICKET, CFG_STATIC_TICKET, CONFIG_SIZE, FIXED_SIZE, KEY_SIZE,
    OFF_AES_KEY, OFF_CFG_FLAGS, OFF_TKT_FLAGS, OFF_UID, SLOT_SIZE, TKT_APPEND_CR, TKT_OATH_HOTP,
    UID_SIZE, crc16,
};

/// The YubiKey modhex alphabet (keyboard-layout-independent).
const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

/// Largest typed ticket: a 44-char Yubico-OTP modhex string plus a trailing CR.
pub const MAX_TICKET: usize = 64;

/// The outcome of [`build`]: the bytes to type and how, plus any slot state to
/// persist (the bumped use counter / HOTP moving factor) and the new RAM session
/// counter for this slot.
pub struct Typed {
    /// Number of valid bytes in the caller's `out` buffer.
    pub len: usize,
    /// `true` → `out` is ASCII to be mapped through the keycode table; `false` →
    /// `out` holds raw HID scancodes (a static password).
    pub encode: bool,
    /// New 8-byte slot tail to persist, or `None` if the counter is unchanged.
    pub new_tail: Option<[u8; SLOT_TAIL]>,
    /// The session counter to keep in RAM for this slot after this press.
    pub new_session: u8,
}

/// The dynamic counter tail appended to a slot file.
pub const SLOT_TAIL: usize = SLOT_SIZE - CONFIG_SIZE; // 8

fn encode_modhex(input: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    for &b in input {
        out[n] = MODHEX[(b >> 4) as usize];
        out[n + 1] = MODHEX[(b & 0xF) as usize];
        n += 2;
    }
    n
}

/// RFC 4226 HOTP over an HMAC-SHA1 key and a 64-bit counter; writes the decimal
/// code (zero-padded to `digits`) into `out`, returning its length.
fn hotp(key: &[u8], counter: u64, digits: u32, out: &mut [u8]) -> usize {
    let mac = hmac_sha1(key, &counter.to_be_bytes());
    let off = (mac[19] & 0x0F) as usize;
    let bin = ((mac[off] & 0x7F) as u32) << 24
        | (mac[off + 1] as u32) << 16
        | (mac[off + 2] as u32) << 8
        | (mac[off + 3] as u32);
    let modulo = 10u32.pow(digits);
    let mut code = bin % modulo;
    let n = digits as usize;
    for i in (0..n).rev() {
        out[i] = b'0' + (code % 10) as u8;
        code /= 10;
    }
    n
}

/// Build the ticket for slot `cfg`+`tail`. Returns `None` for slots that type
/// nothing (challenge-response slots — the button only gates the CCID/HID
/// calculate for those). `ts_secs` is the device uptime in seconds, `rnd` two
/// fresh random bytes (Yubico-OTP only), `session` the current RAM session
/// counter for this slot.
pub fn build(
    slot: &[u8; SLOT_SIZE],
    session: u8,
    ts_secs: u32,
    rnd: [u8; 2],
    out: &mut [u8; MAX_TICKET],
) -> Option<Typed> {
    let cfg = &slot[..CONFIG_SIZE];
    let tail = &slot[CONFIG_SIZE..];
    let tkt = cfg[OFF_TKT_FLAGS];
    let cfgf = cfg[OFF_CFG_FLAGS];
    let append_cr = tkt & TKT_APPEND_CR != 0;

    if tkt & TKT_OATH_HOTP != 0 {
        // OATH-HOTP: the 20-byte key ykman packs = AES field ‖ first 4 UID
        // bytes. HMAC zero-padding makes shorter keys equivalent.
        let mut key = [0u8; KEY_SIZE + 4];
        key[..KEY_SIZE].copy_from_slice(&cfg[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
        key[KEY_SIZE..].copy_from_slice(&cfg[OFF_UID..OFF_UID + 4]);
        // Moving factor: the 64-bit tail, or the programmed initial IMF in the
        // last two UID bytes when the tail is still zero.
        let mut imf = u64::from_be_bytes(tail.try_into().ok()?);
        if imf == 0 {
            imf = u16::from_be_bytes([cfg[OFF_UID + 4], cfg[OFF_UID + 5]]) as u64;
        }
        let digits = if cfgf & CFG_OATH_HOTP8 != 0 { 8 } else { 6 };
        let mut len = hotp(&key, imf, digits, out);
        if append_cr {
            out[len] = b'\r';
            len += 1;
        }
        // Roll the HOTP counter; `wrapping_add` matches the sibling config_seq
        // bumps and removes a debug-panic/release-wrap asymmetry at the
        // (unreachable) u64::MAX counter.
        let new_tail = imf.wrapping_add(1).to_be_bytes();
        return Some(Typed {
            len,
            encode: true,
            new_tail: Some(new_tail),
            new_session: session,
        });
    }

    if cfgf & (CFG_SHORT_TICKET | CFG_STATIC_TICKET) != 0 {
        // Static password: the fixed ‖ uid ‖ key bytes are HID scancodes, typed
        // verbatim (SHORT_TICKET applies no truncation).
        let n = FIXED_SIZE + UID_SIZE + KEY_SIZE; // 38
        out[..n].copy_from_slice(&cfg[..n]);
        let mut len = n;
        if append_cr {
            out[len] = 0x28; // HID Enter scancode
            len += 1;
        }
        return Some(Typed {
            len,
            encode: false,
            new_tail: None,
            new_session: session,
        });
    }

    // Yubico OTP. otpk = public id (6, clear) ‖ AES-ECB( private block 16 ).
    let mut counter = u16::from_be_bytes([tail[0], tail[1]]);
    let mut update = false;
    if counter == 0 {
        counter = 1;
        update = true;
    }
    let mut otpk = [0u8; 22];
    otpk[..6].copy_from_slice(&cfg[..6]); // public id prefix
    otpk[6..12].copy_from_slice(&cfg[OFF_UID..OFF_UID + UID_SIZE]);
    otpk[12..14].copy_from_slice(&counter.to_le_bytes());
    let ts = ts_secs >> 1;
    otpk[14] = ts as u8;
    otpk[15] = (ts >> 8) as u8;
    otpk[16] = (ts >> 16) as u8;
    otpk[17] = session;
    otpk[18..20].copy_from_slice(&rnd);
    let crc = !crc16(&otpk[6..20]);
    otpk[20..22].copy_from_slice(&crc.to_le_bytes());
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&cfg[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
    let mut block = [0u8; 16];
    block.copy_from_slice(&otpk[6..22]);
    aes128_encrypt_block(&key, &mut block);
    otpk[6..22].copy_from_slice(&block);
    let mut len = encode_modhex(&otpk, out);
    if append_cr {
        out[len] = b'\r';
        len += 1;
    }

    let new_session = session.wrapping_add(1);
    if new_session == 0 && counter <= 0x7FFF {
        counter += 1;
        update = true;
    }
    let new_tail = if update {
        let mut t = [0u8; SLOT_TAIL];
        t.copy_from_slice(tail);
        t[..2].copy_from_slice(&counter.to_be_bytes());
        Some(t)
    } else {
        None
    };
    Some(Typed {
        len,
        encode: true,
        new_tail,
        new_session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::*;

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        // RFC 4226 Appendix D: key = "12345678901234567890" (20 bytes ASCII).
        let key = b"12345678901234567890";
        let expect = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        let mut out = [0u8; MAX_TICKET];
        for (c, want) in expect.iter().enumerate() {
            let n = hotp(key, c as u64, 6, &mut out);
            assert_eq!(&out[..n], want.as_bytes(), "counter {c}");
        }
    }

    #[test]
    fn hotp_slot_uses_20_byte_key_and_bumps_imf() {
        // Program a HOTP slot the ykman way: key[..16] in the AES field,
        // key[16..20] in the UID head. The typed code must equal RFC 4226 over
        // the full 20-byte key.
        let key20 = b"12345678901234567890";
        let mut cfg = [0u8; CONFIG_SIZE];
        cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&key20[..16]);
        cfg[OFF_UID..OFF_UID + 4].copy_from_slice(&key20[16..]);
        cfg[OFF_TKT_FLAGS] = TKT_OATH_HOTP | TKT_APPEND_CR;
        let mut slot = [0u8; SLOT_SIZE];
        slot[..CONFIG_SIZE].copy_from_slice(&cfg);

        let mut out = [0u8; MAX_TICKET];
        let t = build(&slot, 0, 0, [0, 0], &mut out).unwrap();
        assert!(t.encode);
        assert_eq!(&out[..t.len], b"755224\r"); // RFC 4226 counter 0 + CR
        // IMF advanced 0 → 1.
        assert_eq!(t.new_tail.unwrap(), 1u64.to_be_bytes());

        // Replay at IMF 1 → the next RFC 4226 code.
        slot[CONFIG_SIZE..].copy_from_slice(&1u64.to_be_bytes());
        let t = build(&slot, 0, 0, [0, 0], &mut out).unwrap();
        assert_eq!(&out[..6], b"287082");
        assert_eq!(t.new_tail.unwrap(), 2u64.to_be_bytes());
    }

    #[test]
    fn hotp8_digits() {
        let key20 = b"12345678901234567890";
        let mut cfg = [0u8; CONFIG_SIZE];
        cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&key20[..16]);
        cfg[OFF_UID..OFF_UID + 4].copy_from_slice(&key20[16..]);
        cfg[OFF_TKT_FLAGS] = TKT_OATH_HOTP;
        cfg[OFF_CFG_FLAGS] = CFG_OATH_HOTP8;
        let mut slot = [0u8; SLOT_SIZE];
        slot[..CONFIG_SIZE].copy_from_slice(&cfg);
        let mut out = [0u8; MAX_TICKET];
        let t = build(&slot, 0, 0, [0, 0], &mut out).unwrap();
        // RFC 4226 8-digit truncation of counter 0 = 84755224.
        assert_eq!(&out[..t.len], b"84755224");
    }

    #[test]
    fn yubico_otp_is_decryptable_and_bumps_counter() {
        // A plain Yubico-OTP slot. Decrypt the modhex with the AES key and check
        // the embedded fields + the trailing CRC residual.
        let aes = [0x11u8; 16];
        let uid = [1, 2, 3, 4, 5, 6];
        let mut cfg = [0u8; CONFIG_SIZE];
        cfg[..6].copy_from_slice(b"\x01\x02\x03\x04\x05\x06"); // public id
        cfg[OFF_UID..OFF_UID + 6].copy_from_slice(&uid);
        cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&aes);
        cfg[OFF_TKT_FLAGS] = TKT_APPEND_CR;
        let mut slot = [0u8; SLOT_SIZE];
        slot[..CONFIG_SIZE].copy_from_slice(&cfg);

        let mut out = [0u8; MAX_TICKET];
        let t = build(&slot, 0, 100, [0xAA, 0xBB], &mut out).unwrap();
        assert!(t.encode);
        assert_eq!(t.len, 44 + 1); // 44 modhex + CR
        assert_eq!(out[44], b'\r');
        assert_eq!(t.new_session, 1);
        // Counter was 0 → set to 1 and persisted.
        assert_eq!(t.new_tail.unwrap()[..2], 1u16.to_be_bytes());

        // Decode modhex → 22 bytes; the first 6 are the clear public id.
        let raw = demodhex(&out[..44]);
        assert_eq!(&raw[..6], &cfg[..6]);
        // Decrypt the 16-byte block and verify uid + counter + CRC residual.
        let mut block = [0u8; 16];
        block.copy_from_slice(&raw[6..22]);
        aes128_decrypt_block(&aes, &mut block);
        assert_eq!(&block[..6], &uid); // private uid
        assert_eq!(u16::from_le_bytes([block[6], block[7]]), 1); // counter
        let mut chk = [0u8; 16];
        chk.copy_from_slice(&block);
        // CRC over the first 14 bytes ‖ stored ~CRC ⇒ X.25 residual.
        assert_eq!(crc16(&chk), 0xF0B8);
    }

    #[test]
    fn yubico_session_wrap_bumps_counter() {
        let mut cfg = [0u8; CONFIG_SIZE];
        cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&[0x22; 16]);
        let mut slot = [0u8; SLOT_SIZE];
        slot[..CONFIG_SIZE].copy_from_slice(&cfg);
        slot[CONFIG_SIZE..CONFIG_SIZE + 2].copy_from_slice(&5u16.to_be_bytes());
        let mut out = [0u8; MAX_TICKET];
        // session 255 → wraps to 0 → counter 5 → 6.
        let t = build(&slot, 255, 0, [0, 0], &mut out).unwrap();
        assert_eq!(t.new_session, 0);
        assert_eq!(t.new_tail.unwrap()[..2], 6u16.to_be_bytes());
    }

    #[test]
    fn static_password_types_scancodes_verbatim() {
        let mut cfg = [0u8; CONFIG_SIZE];
        for (i, b) in cfg[..38].iter_mut().enumerate() {
            *b = i as u8;
        }
        cfg[OFF_TKT_FLAGS] = TKT_APPEND_CR;
        cfg[OFF_CFG_FLAGS] = CFG_STATIC_TICKET;
        let mut slot = [0u8; SLOT_SIZE];
        slot[..CONFIG_SIZE].copy_from_slice(&cfg);
        let mut out = [0u8; MAX_TICKET];
        let t = build(&slot, 0, 0, [0, 0], &mut out).unwrap();
        assert!(!t.encode); // raw scancodes
        assert_eq!(t.len, 38 + 1);
        assert_eq!(&out[..38], &cfg[..38]);
        assert_eq!(out[38], 0x28); // Enter scancode
        assert!(t.new_tail.is_none());
    }
}
