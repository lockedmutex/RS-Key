// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Host-test helpers shared by the unit tests (modhex decode + an independent
//! AES-128 block decrypt for the typed Yubico-OTP round-trip).

use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};

/// Inverse of [`ticket::encode_modhex`](crate::ticket): map a modhex string back
/// to its bytes.
pub fn demodhex(input: &[u8]) -> Vec<u8> {
    const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";
    let nib = |c: u8| MODHEX.iter().position(|&m| m == c).unwrap() as u8;
    input
        .chunks(2)
        .map(|p| (nib(p[0]) << 4) | nib(p[1]))
        .collect()
}

/// AES-128 single-block ECB decrypt (the inverse of
/// [`rsk_crypto::aes128_encrypt_block`]).
pub fn aes128_decrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut b);
    block.copy_from_slice(&b);
}
