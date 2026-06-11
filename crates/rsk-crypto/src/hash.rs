// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! One-shot SHA-1 / SHA-256 / SHA-384 / SHA-512 helpers.

use sha2::{Digest, Sha256, Sha384, Sha512};

/// One-shot SHA-1 — only for X.509 key identifiers (SKI/AKI, RFC 5280 method 1),
/// never for new signatures.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let digest = sha1::Sha1::digest(input);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// One-shot SHA-256.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// One-shot SHA-384.
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let digest = Sha384::digest(input);
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

/// One-shot SHA-512.
pub fn sha512(input: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write;
        let mut s = std::string::String::new();
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn sha256_vectors() {
        // NIST / FIPS 180-4 examples.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha1_vectors() {
        // FIPS 180-1 examples.
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha384_vectors() {
        // FIPS 180-4 examples.
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }
}
