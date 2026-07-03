// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! 3DES single-block ECB — the legacy PIV management-key algorithm. Three-key
//! EDE over one 8-byte block; not a general mode on purpose. The default PIV
//! management key is AES-192 — 3DES only appears when a host programs a TDES key.

use des::TdesEde3;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// 3DES-EDE3-ECB encrypt one 8-byte block in place.
pub fn des3_encrypt_block(key: &[u8; 24], block: &mut [u8; 8]) {
    let cipher = TdesEde3::new(GenericArray::from_slice(key));
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

/// 3DES-EDE3-ECB decrypt one 8-byte block in place.
pub fn des3_decrypt_block(key: &[u8; 24], block: &mut [u8; 8]) {
    let cipher = TdesEde3::new(GenericArray::from_slice(key));
    cipher.decrypt_block(GenericArray::from_mut_slice(block));
}

#[cfg(test)]
#[path = "des_tests.rs"]
mod tests;
