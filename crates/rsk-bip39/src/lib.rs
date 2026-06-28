// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! BIP-39 mnemonic encoding for a 256-bit seed, on-device.
//!
//! The trusted display shows the recovery phrase as 24 English words derived **on the
//! device** from its master seed, so the seed never crosses USB. This is the encode
//! direction only (entropy → words): the host keeps the decode/restore path (its
//! `mnemonic` library). The two must agree bit-for-bit, which a host-vector test pins.
//!
//! `no_std`, no alloc, no secret intermediate buffer kept: [`entropy_to_indices`] reads
//! the 264 bits (256 entropy + 8 checksum) straight out of the inputs. The 24 returned
//! indices encode the seed, so the **caller zeroizes them** after rendering.

#![no_std]

mod wordlist;
pub use wordlist::WORDS;

/// Words a 256-bit (32-byte) entropy encodes: `(256 + 8 checksum) / 11 = 24`.
pub const WORD_COUNT: usize = 24;

/// The 24 BIP-39 word indices (`0..2048`) for a 32-byte seed, in order. Each is an
/// 11-bit value, so it always indexes [`WORDS`] in bounds (proven by `indices_in_range`).
///
/// The checksum is the first 8 bits of `SHA-256(entropy)`, appended to the 256 entropy
/// bits; the 264-bit string is then read big-endian in 11-bit groups. The returned array
/// is secret (it reconstructs the seed) — zeroize it once the phrase is shown.
pub fn entropy_to_indices(entropy: &[u8; 32]) -> [u16; WORD_COUNT] {
    let checksum = rsk_crypto::sha256(entropy)[0];
    // Bit `b` of the 264-bit string: the first 256 come from `entropy` (MSB-first per
    // byte), the last 8 from `checksum`. No copy of the seed is made.
    let bit = |b: usize| -> u16 {
        let byte = if b < 256 { entropy[b / 8] } else { checksum };
        ((byte >> (7 - (b % 8))) & 1) as u16
    };
    let mut idx = [0u16; WORD_COUNT];
    let mut i = 0;
    while i < WORD_COUNT {
        let mut v = 0u16;
        let mut j = 0;
        while j < 11 {
            v = (v << 1) | bit(i * 11 + j);
            j += 1;
        }
        idx[i] = v;
        i += 1;
    }
    idx
}

/// The BIP-39 word for `index` (`0..2048`). Indices from [`entropy_to_indices`] are
/// always in range; an out-of-range index panics (a programming error).
pub fn word(index: u16) -> &'static str {
    WORDS[index as usize]
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Every index [`entropy_to_indices`] returns is `< 2048`, so [`word`]/[`WORDS`]
    /// indexing can never go out of bounds for any seed.
    #[kani::proof]
    fn indices_in_range() {
        let entropy: [u8; 32] = kani::any();
        // Model the checksum as an arbitrary byte: the proof is about the bit-packing,
        // not SHA-256 (whose output is some byte, already covered by `any`).
        let checksum: u8 = kani::any();
        let bit = |b: usize| -> u16 {
            let byte = if b < 256 { entropy[b / 8] } else { checksum };
            ((byte >> (7 - (b % 8))) & 1) as u16
        };
        let mut i = 0;
        while i < WORD_COUNT {
            let mut v = 0u16;
            let mut j = 0;
            while j < 11 {
                v = (v << 1) | bit(i * 11 + j);
                j += 1;
            }
            assert!((v as usize) < WORDS.len());
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;
    use std::vec::Vec;

    #[test]
    fn wordlist_is_exactly_2048_and_endpoints_match() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(WORDS[0], "abandon");
        assert_eq!(WORDS[2047], "zoo");
        assert!(WORDS.iter().all(|w| w.len() <= 8 && w.is_ascii()));
    }

    /// Pin the embedded list to the canonical BIP-39 english.txt by re-hashing it: the
    /// newline-joined words (trailing newline) must match the published checksum, so a
    /// single transposed/edited word can never slip in unnoticed.
    #[test]
    fn wordlist_matches_the_canonical_checksum() {
        let mut joined = String::new();
        for w in WORDS {
            joined.push_str(w);
            joined.push('\n');
        }
        let digest = rsk_crypto::sha256(joined.as_bytes());
        let mut hex = String::new();
        for b in digest {
            hex.push_str(&std::format!("{b:02x}"));
        }
        assert_eq!(
            hex,
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    fn phrase(entropy: &[u8; 32]) -> String {
        entropy_to_indices(entropy)
            .iter()
            .map(|&i| word(i))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Authoritative 256-bit vectors generated from the same `mnemonic` library the host
    /// `rsk backup` uses, so on-device encode == host decode (interop).
    #[test]
    fn matches_host_bip39_vectors() {
        assert_eq!(
            phrase(&[0x00; 32]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon art"
        );
        assert_eq!(
            phrase(&[0xff; 32]),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
             zoo zoo zoo zoo vote"
        );
        assert_eq!(
            phrase(&[0x80; 32]),
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage \
             absurd amount doctor acoustic avoid letter advice cage absurd amount doctor \
             acoustic bless"
        );
        let mut seq = [0u8; 32];
        for (i, b) in seq.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        assert_eq!(
            phrase(&seq),
            "absurd avoid scissors anxiety gather lottery category door army half long \
             cage bachelor another expect people blade school educate curtain scrub \
             monitor lady beyond"
        );
    }

    #[test]
    fn always_24_words_and_in_range() {
        let idx = entropy_to_indices(&[0x5a; 32]);
        assert_eq!(idx.len(), WORD_COUNT);
        assert!(idx.iter().all(|&i| (i as usize) < WORDS.len()));
    }
}
