// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn des3_block_three_key_kat() {
    // Three-key EDE (K1≠K2≠K3) known answer, cross-checked against pyca
    // `cryptography`'s TripleDES-ECB.
    let key: [u8; 24] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, //
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, //
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
    ];
    let pt: [u8; 8] = *b"The qufo";
    let mut block = pt;
    des3_encrypt_block(&key, &mut block);
    assert_eq!(
        block,
        [0x40, 0xce, 0xcc, 0x32, 0xea, 0x0a, 0xec, 0xdc],
        "TDES EDE3 KAT"
    );
    des3_decrypt_block(&key, &mut block);
    assert_eq!(block, pt);
}

#[test]
fn des3_single_key_degenerates_to_des() {
    // With K1 = K2 = K3, EDE collapses to single DES — the FIPS 46-3 sanity
    // property; vector from the NBS DES known-answer set.
    let mut key = [0u8; 24];
    for chunk in key.chunks_mut(8) {
        chunk.copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }
    let mut block: [u8; 8] = [0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74];
    des3_encrypt_block(&key, &mut block);
    assert_eq!(block, [0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15]);
}
