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
#[path = "chachapoly_tests.rs"]
mod tests;
