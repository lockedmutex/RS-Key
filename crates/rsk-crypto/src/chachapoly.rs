// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ChaCha20-Poly1305 (IETF, 96-bit nonce). The FIDO credential ID is a
//! ChaCha20-Poly1305 box: the rpId hash is the AAD and the 16-byte tag is stored
//! detached, matching the detached-tag shape of [`crate::aes::aes256gcm_encrypt`].

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use crate::{Error, Result};

/// ChaCha20-Poly1305 encrypt in place; returns the detached 16-byte tag.
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
        .expect("ChaCha20-Poly1305 in-place encryption is infallible for in-range lengths");
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// ChaCha20-Poly1305 decrypt in place, verifying `tag`; `Err(Decrypt)` on failure.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
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

    fn unhex(s: &str) -> std::vec::Vec<u8> {
        let b = s.as_bytes();
        (0..s.len() / 2)
            .map(|i| {
                let hi = (b[i * 2] as char).to_digit(16).unwrap() as u8;
                let lo = (b[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    // RFC 8439 §2.8.2 — the canonical ChaCha20-Poly1305 AEAD test vector.
    #[test]
    fn rfc8439_vector() {
        let mut key = [0u8; 32];
        for (i, k) in key.iter_mut().enumerate() {
            *k = 0x80 + i as u8;
        }
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                      only one tip for the future, sunscreen would be it.";
        let ct = unhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let want_tag = unhex("1ae10b594f09e26a7e902ecbd0600691");

        let mut buf = std::vec::Vec::from(plain.as_slice());
        let tag = chacha20poly1305_encrypt(&key, &nonce, &aad, &mut buf);
        assert_eq!(buf, ct);
        assert_eq!(tag.as_slice(), want_tag.as_slice());

        let mut tag16 = [0u8; 16];
        tag16.copy_from_slice(&want_tag);
        chacha20poly1305_decrypt(&key, &nonce, &aad, &mut buf, &tag16).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn aad_and_tamper_fail() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"rp-id-hash-as-aad";
        let mut buf = std::vec::Vec::from(b"a credential id plaintext blob".as_slice());
        let plain = buf.clone();
        let tag = chacha20poly1305_encrypt(&key, &nonce, aad, &mut buf);
        assert_ne!(buf, plain);

        // Wrong AAD fails.
        let mut wrong = buf.clone();
        assert_eq!(
            chacha20poly1305_decrypt(&key, &nonce, b"other-aad", &mut wrong, &tag),
            Err(Error::Decrypt)
        );
        // Flipped ciphertext byte fails.
        let mut flipped = buf.clone();
        flipped[0] ^= 0x01;
        assert_eq!(
            chacha20poly1305_decrypt(&key, &nonce, aad, &mut flipped, &tag),
            Err(Error::Decrypt)
        );
        // Correct inputs recover the plaintext.
        chacha20poly1305_decrypt(&key, &nonce, aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plain);
    }
}
