// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! AES — in-place CBC and CFB-128 (`aes_encrypt`/`aes_decrypt`, AES-128/192/256
//! picked from the key length) plus the raw AES-256-GCM primitive behind the PIN
//! AEAD. CBC needs a block-multiple length; CFB-128 is a stream and takes any
//! length (CFB decryption uses the forward cipher; `cfb_mode` handles that).

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{AsyncStreamCipher, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::{Error, Result};

/// Block cipher mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cbc,
    Cfb,
}

macro_rules! cbc_encrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        let len = $data.len();
        cbc::Encryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .encrypt_padded_mut::<NoPadding>($data, len)
            .map(|_| ())
            .map_err(|_| Error::BadLength)
    }};
}

macro_rules! cbc_decrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        cbc::Decryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .decrypt_padded_mut::<NoPadding>($data)
            .map(|_| ())
            .map_err(|_| Error::BadLength)
    }};
}

macro_rules! cfb_encrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        cfb_mode::Encryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .encrypt($data);
        Ok(())
    }};
}

macro_rules! cfb_decrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        cfb_mode::Decryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .decrypt($data);
        Ok(())
    }};
}

/// In-place AES encrypt. Key length selects AES-128/192/256.
pub fn aes_encrypt(key: &[u8], iv: &[u8; 16], mode: Mode, data: &mut [u8]) -> Result<()> {
    match (mode, key.len()) {
        (Mode::Cbc, 16) => cbc_encrypt!(Aes128, key, iv, data),
        (Mode::Cbc, 24) => cbc_encrypt!(Aes192, key, iv, data),
        (Mode::Cbc, 32) => cbc_encrypt!(Aes256, key, iv, data),
        (Mode::Cfb, 16) => cfb_encrypt!(Aes128, key, iv, data),
        (Mode::Cfb, 24) => cfb_encrypt!(Aes192, key, iv, data),
        (Mode::Cfb, 32) => cfb_encrypt!(Aes256, key, iv, data),
        _ => Err(Error::BadLength),
    }
}

/// In-place AES decrypt. Key length selects AES-128/192/256.
pub fn aes_decrypt(key: &[u8], iv: &[u8; 16], mode: Mode, data: &mut [u8]) -> Result<()> {
    match (mode, key.len()) {
        (Mode::Cbc, 16) => cbc_decrypt!(Aes128, key, iv, data),
        (Mode::Cbc, 24) => cbc_decrypt!(Aes192, key, iv, data),
        (Mode::Cbc, 32) => cbc_decrypt!(Aes256, key, iv, data),
        (Mode::Cfb, 16) => cfb_decrypt!(Aes128, key, iv, data),
        (Mode::Cfb, 24) => cfb_decrypt!(Aes192, key, iv, data),
        (Mode::Cfb, 32) => cfb_decrypt!(Aes256, key, iv, data),
        _ => Err(Error::BadLength),
    }
}

/// AES-128-ECB single-block encrypt in place — the Yubico OTP primitive (the
/// token body and the Yubico-mode challenge-response are one ECB block each).
/// Not a general ECB mode on purpose.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes::cipher::BlockEncrypt;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

/// AES-ECB single-block encrypt in place, AES-128/192/256 picked from the key
/// length — the PIV GENERAL AUTHENTICATE management-key primitive (witness /
/// challenge / response are one ECB block each). Not a general ECB mode on
/// purpose.
pub fn aes_ecb_encrypt_block(key: &[u8], block: &mut [u8; 16]) -> Result<()> {
    use aes::cipher::BlockEncrypt;
    let b = GenericArray::from_mut_slice(block);
    match key.len() {
        16 => Aes128::new(GenericArray::from_slice(key)).encrypt_block(b),
        24 => Aes192::new(GenericArray::from_slice(key)).encrypt_block(b),
        32 => Aes256::new(GenericArray::from_slice(key)).encrypt_block(b),
        _ => return Err(Error::BadLength),
    }
    Ok(())
}

/// AES-ECB single-block decrypt in place — the inverse of
/// [`aes_ecb_encrypt_block`], for the PIV mutual-auth response check.
pub fn aes_ecb_decrypt_block(key: &[u8], block: &mut [u8; 16]) -> Result<()> {
    use aes::cipher::BlockDecrypt;
    let b = GenericArray::from_mut_slice(block);
    match key.len() {
        16 => Aes128::new(GenericArray::from_slice(key)).decrypt_block(b),
        24 => Aes192::new(GenericArray::from_slice(key)).decrypt_block(b),
        32 => Aes256::new(GenericArray::from_slice(key)).decrypt_block(b),
        _ => return Err(Error::BadLength),
    }
    Ok(())
}

/// AES-256-CFB encrypt in place.
pub fn aes_encrypt_cfb_256(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    aes_encrypt(key, iv, Mode::Cfb, data)
}

/// AES-256-CFB decrypt in place.
pub fn aes_decrypt_cfb_256(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    aes_decrypt(key, iv, Mode::Cfb, data)
}

/// AES-256-GCM encrypt in place; returns the 16-byte tag (detached). The raw
/// primitive behind the PIN KDF's `encrypt_with_aad`.
pub fn aes256gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
        .expect("GCM in-place encryption is infallible for in-range lengths");
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// AES-256-GCM decrypt in place, verifying `tag`; `Err(Decrypt)` on auth failure.
pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            buf,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_block_fips197() {
        // FIPS-197 appendix C.1.
        let key: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let mut block: [u8; 16] = unhex("00112233445566778899aabbccddeeff");
        aes128_encrypt_block(&key, &mut block);
        assert_eq!(block, unhex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[test]
    fn aes_ecb_block_fips197() {
        // FIPS-197 appendix C.1–C.3, encrypt + decrypt round-trips.
        let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff");
        for (key, ct) in [
            (
                &unhex::<16>("000102030405060708090a0b0c0d0e0f")[..],
                unhex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"),
            ),
            (
                &unhex::<24>("000102030405060708090a0b0c0d0e0f1011121314151617")[..],
                unhex::<16>("dda97ca4864cdfe06eaf70a0ec0d7191"),
            ),
            (
                &unhex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[..],
                unhex::<16>("8ea2b7ca516745bfeafc49904b496089"),
            ),
        ] {
            let mut block = pt;
            aes_ecb_encrypt_block(key, &mut block).unwrap();
            assert_eq!(block, ct);
            aes_ecb_decrypt_block(key, &mut block).unwrap();
            assert_eq!(block, pt);
        }
        assert!(aes_ecb_encrypt_block(&[0u8; 8], &mut [0u8; 16]).is_err());
        assert!(aes_ecb_decrypt_block(&[0u8; 8], &mut [0u8; 16]).is_err());
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
            *o = (hi << 4) | lo;
        }
        out
    }

    // NIST SP 800-38A, F.2.5 CBC-AES256.Encrypt (first block).
    #[test]
    fn cbc_aes256_nist() {
        let key: [u8; 32] =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let mut data: [u8; 16] = unhex("6bc1bee22e409f96e93d7e117393172a");
        aes_encrypt(&key, &iv, Mode::Cbc, &mut data).unwrap();
        assert_eq!(data, unhex::<16>("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
        aes_decrypt(&key, &iv, Mode::Cbc, &mut data).unwrap();
        assert_eq!(data, unhex::<16>("6bc1bee22e409f96e93d7e117393172a"));
    }

    // NIST SP 800-38A, F.3.17 CFB128-AES256.Encrypt (first segment).
    #[test]
    fn cfb_aes256_nist() {
        let key: [u8; 32] =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
        let mut data: [u8; 16] = unhex("6bc1bee22e409f96e93d7e117393172a");
        aes_encrypt_cfb_256(&key, &iv, &mut data).unwrap();
        assert_eq!(data, unhex::<16>("dc7e84bfda79164b7ecd8486985d3860"));
        aes_decrypt_cfb_256(&key, &iv, &mut data).unwrap();
        assert_eq!(data, unhex::<16>("6bc1bee22e409f96e93d7e117393172a"));
    }

    // CFB is a stream cipher: a non-block-multiple length must work.
    #[test]
    fn cfb_partial_block_roundtrip() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let orig = *b"hello, cfb!"; // 11 bytes
        let mut data = orig;
        aes_encrypt_cfb_256(&key, &iv, &mut data).unwrap();
        assert_ne!(data, orig);
        aes_decrypt_cfb_256(&key, &iv, &mut data).unwrap();
        assert_eq!(data, orig);
    }

    #[test]
    fn cbc_rejects_unaligned() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut data = [0u8; 17]; // not a block multiple
        assert_eq!(
            aes_encrypt(&key, &iv, Mode::Cbc, &mut data),
            Err(Error::BadLength)
        );
    }

    #[test]
    fn bad_key_len() {
        let iv = [0u8; 16];
        let mut data = [0u8; 16];
        assert_eq!(
            aes_encrypt(&[0u8; 20], &iv, Mode::Cbc, &mut data),
            Err(Error::BadLength)
        );
    }

    // NIST GCM test case 14: K=0^256, IV=0^96, A=empty, P=0^128.
    #[test]
    fn gcm_aes256_nist_case14() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut buf = [0u8; 16];
        let tag = aes256gcm_encrypt(&key, &nonce, &[], &mut buf);
        assert_eq!(buf, unhex::<16>("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(tag, unhex::<16>("d0d1c8a799996bf0265b98b5d48ab919"));
        aes256gcm_decrypt(&key, &nonce, &[], &mut buf, &tag).unwrap();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn gcm_aad_roundtrip_and_tamper() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"serial-hash-as-aad";
        let mut buf = *b"thirty-two-byte device key!! abcd"; // 33 bytes
        let plain = buf;
        let tag = aes256gcm_encrypt(&key, &nonce, aad, &mut buf);
        assert_ne!(buf, plain);
        // Wrong AAD must fail authentication.
        assert_eq!(
            aes256gcm_decrypt(&key, &nonce, b"wrong-aad", &mut buf.clone(), &tag),
            Err(Error::Decrypt)
        );
        // Correct AAD recovers the plaintext.
        aes256gcm_decrypt(&key, &nonce, aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plain);
    }
}
