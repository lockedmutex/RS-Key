// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! base64url: encode emits the URL alphabet (`-`/`_`) with the trailing `=`
//! stripped; decode accepts input with or without padding. A length of
//! `n % 4 == 1` is rejected as malformed.

use crate::{Error, Result};

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encoded length (no padding) for `n` input bytes.
pub fn encoded_len(n: usize) -> usize {
    let rem = n % 3;
    (n / 3) * 4
        + match rem {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

/// Decoded length for a base64url string of `n` chars.
pub fn decoded_len(n: usize) -> Result<usize> {
    if n % 4 == 1 {
        return Err(Error::Base64);
    }
    let pad = (4 - (n % 4)) % 4;
    let out = ((n + pad) / 4) * 3;
    Ok(out - pad)
}

/// base64url-encode `src` into `dst` (no padding); returns the encoded length.
pub fn encode(dst: &mut [u8], src: &[u8]) -> Result<usize> {
    let out_len = encoded_len(src.len());
    if dst.len() < out_len {
        return Err(Error::BadLength);
    }
    let mut di = 0;
    for chunk in src.chunks(3) {
        let b0 = chunk[0];
        dst[di] = ENC[(b0 >> 2) as usize];
        di += 1;
        match chunk.len() {
            1 => {
                dst[di] = ENC[((b0 & 0x03) << 4) as usize];
                di += 1;
            }
            2 => {
                let b1 = chunk[1];
                dst[di] = ENC[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
                dst[di + 1] = ENC[((b1 & 0x0f) << 2) as usize];
                di += 2;
            }
            _ => {
                let (b1, b2) = (chunk[1], chunk[2]);
                dst[di] = ENC[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
                dst[di + 1] = ENC[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize];
                dst[di + 2] = ENC[(b2 & 0x3f) as usize];
                di += 3;
            }
        }
    }
    Ok(di)
}

/// base64url-decode `src` into `dst`; returns the decoded length. Accepts missing
/// or present `=` padding and the URL alphabet.
pub fn decode(dst: &mut [u8], src: &[u8]) -> Result<usize> {
    if src.len() % 4 == 1 {
        return Err(Error::Base64);
    }
    if dst.len() < decoded_len(src.len())? {
        return Err(Error::BadLength);
    }
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut di = 0;
    for &c in src {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break, // padding ends the data
            _ => return Err(Error::Base64),
        };
        acc = (acc << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            dst[di] = (acc >> nbits) as u8;
            di += 1;
        }
    }
    Ok(di)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(src: &[u8]) -> std::string::String {
        let mut buf = [0u8; 256];
        let n = encode(&mut buf, src).unwrap();
        std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    #[test]
    fn rfc4648_vectors_no_pad() {
        assert_eq!(enc(b""), "");
        assert_eq!(enc(b"f"), "Zg");
        assert_eq!(enc(b"fo"), "Zm8");
        assert_eq!(enc(b"foo"), "Zm9v");
        assert_eq!(enc(b"foob"), "Zm9vYg");
        assert_eq!(enc(b"fooba"), "Zm9vYmE");
        assert_eq!(enc(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn url_alphabet() {
        // Bytes chosen to exercise indices 62 ('-') and 63 ('_').
        // 0xFB 0xF0 -> 111110 111111 000000 -> "-_A"
        assert_eq!(enc(&[0xFB, 0xF0]), "-_A");
        // 0xFF 0xFF 0xFF -> all ones -> "____"
        assert_eq!(enc(&[0xFF, 0xFF, 0xFF]), "____");
    }

    #[test]
    fn roundtrip_all_lengths() {
        for len in 0..64usize {
            let src: std::vec::Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut e = [0u8; 128];
            let en = encode(&mut e, &src).unwrap();
            let mut d = [0u8; 64];
            let dn = decode(&mut d, &e[..en]).unwrap();
            assert_eq!(&d[..dn], &src[..], "len={len}");
        }
    }

    #[test]
    fn decode_accepts_padding() {
        let mut d = [0u8; 8];
        // "Zm8=" and "Zm8" both decode to "fo".
        assert_eq!(decode(&mut d, b"Zm8=").unwrap(), 2);
        assert_eq!(&d[..2], b"fo");
        assert_eq!(decode(&mut d, b"Zm8").unwrap(), 2);
        assert_eq!(&d[..2], b"fo");
    }

    #[test]
    fn decode_rejects_bad() {
        let mut d = [0u8; 8];
        assert_eq!(decode(&mut d, b"AAAAA"), Err(Error::Base64)); // len % 4 == 1
        assert_eq!(decode(&mut d, b"Zm.v"), Err(Error::Base64)); // bad char
    }

    #[test]
    fn decoded_len_matches() {
        assert_eq!(decoded_len(0).unwrap(), 0);
        assert_eq!(decoded_len(2).unwrap(), 1);
        assert_eq!(decoded_len(3).unwrap(), 2);
        assert_eq!(decoded_len(4).unwrap(), 3);
        assert_eq!(decoded_len(1), Err(Error::Base64));
    }
}
