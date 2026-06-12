// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ISO-7816 APDU parsing.

use crate::error::{Error, Result};

#[inline]
fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

/// A parsed command APDU. `data` borrows the command buffer (the `Nc` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Apdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Length of the command data field (`Nc`).
    pub nc: usize,
    /// Expected length of the response (`Ne` / Le), already normalised
    /// (0 → 256 short, 0 → 65536 extended).
    pub ne: usize,
    pub data: &'a [u8],
}

impl<'a> Apdu<'a> {
    /// Parse a raw command buffer. Handles ISO-7816 cases 1–4, short and
    /// extended length.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(Error::WrongLength);
        }
        let size = buf.len();
        let (cla, ins, p1, p2) = (buf[0], buf[1], buf[2], buf[3]);
        let mut nc = 0usize;
        let mut ne = 0usize;
        let mut data: &[u8] = &[];

        if size == 4 {
            // Case 1 (Ne still defaults to 256).
            ne = 256;
        } else if size == 5 {
            // Case 2 short.
            ne = match buf[4] {
                0 => 256,
                n => n as usize,
            };
        } else if buf[4] == 0 && size >= 7 {
            // Extended length (leading 0 marker).
            if size == 7 {
                ne = match be16(&buf[5..7]) {
                    0 => 65536,
                    n => n as usize,
                };
            } else {
                nc = be16(&buf[5..7]) as usize;
                let start = 7;
                if start + nc > size {
                    return Err(Error::WrongLength);
                }
                data = &buf[start..start + nc];
                if nc + 7 + 2 == size {
                    ne = match be16(&buf[size - 2..]) {
                        0 => 65536,
                        n => n as usize,
                    };
                }
            }
        } else {
            // Short Lc (cases 3 and 4).
            nc = buf[4] as usize;
            let start = 5;
            if start + nc > size {
                return Err(Error::WrongLength);
            }
            data = &buf[start..start + nc];
            if nc + 5 + 1 == size {
                ne = match buf[size - 1] {
                    0 => 256,
                    n => n as usize,
                };
            }
        }

        Ok(Apdu {
            cla,
            ins,
            p1,
            p2,
            nc,
            ne,
            data,
        })
    }

    /// True when this is a command-chaining segment (CLA bit 0x10 set).
    #[inline]
    pub fn is_chaining(&self) -> bool {
        self.cla & 0x10 != 0
    }
}

/// Kani proof harnesses (`cargo kani -p rsk-sdk`).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Parsing ANY buffer up to 20 bytes (long enough to reach every of the
    /// ISO-7816 case-1..4 branches, short and extended, with a few body bytes
    /// past the extended Lc/Le markers) never panics, and a successful parse
    /// upholds the struct's invariants: `data` is the `nc` bytes it claims to
    /// be, and `ne` never exceeds the extended-length ceiling. Extended bodies
    /// longer than the bound are exercised by the fuzz target instead.
    #[kani::proof]
    fn parse_any_buffer() {
        const N: usize = 20;
        let buf: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        if let Ok(a) = Apdu::parse(&buf[..n]) {
            assert_eq!(a.nc, a.data.len());
            assert!(a.nc <= n);
            assert!(a.ne <= 65536);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case1() {
        let a = Apdu::parse(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!((a.cla, a.ins, a.p1, a.p2), (0x00, 0xA4, 0x04, 0x00));
        assert_eq!(a.nc, 0);
        assert_eq!(a.ne, 256);
        assert!(a.data.is_empty());
    }

    #[test]
    fn case2_short() {
        let a = Apdu::parse(&[0x00, 0xC0, 0x00, 0x00, 0x10]).unwrap();
        assert_eq!(a.nc, 0);
        assert_eq!(a.ne, 0x10);
    }

    #[test]
    fn case3_short() {
        // SELECT by AID: CLA INS P1 P2 Lc=5 data...
        let raw = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x06, 0x47];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.nc, 5);
        assert_eq!(a.data, &[0xA0, 0x00, 0x00, 0x06, 0x47]);
        assert_eq!(a.ne, 0);
    }

    #[test]
    fn case4_short() {
        // Lc=2 data, then Le
        let raw = [0x00, 0x01, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0x40];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.nc, 2);
        assert_eq!(a.data, &[0xDE, 0xAD]);
        assert_eq!(a.ne, 0x40);
    }

    #[test]
    fn case2_extended() {
        // 00 B0 0000 00 <Le16=0x0200>
        let raw = [0x00, 0xB0, 0x00, 0x00, 0x00, 0x02, 0x00];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.nc, 0);
        assert_eq!(a.ne, 0x0200);
    }

    #[test]
    fn case3_extended() {
        // 00 01 0000 00 <Lc16=0x0003> data[3]
        let raw = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.nc, 3);
        assert_eq!(a.data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn case4_extended() {
        // 00 01 0000 00 <Lc16=2> AA BB <Le16=0x0100>
        let raw = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x01, 0x00,
        ];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.nc, 2);
        assert_eq!(a.data, &[0xAA, 0xBB]);
        assert_eq!(a.ne, 0x0100);
    }

    #[test]
    fn case2_extended_le_zero_is_65536() {
        // 00 B0 0000 00 <Le16=0> → Ne normalised to 65536.
        let a = Apdu::parse(&[0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(a.nc, 0);
        assert_eq!(a.ne, 65536);
    }

    #[test]
    fn case2_short_le_zero_is_256() {
        // Le byte 0 → Ne 256.
        let a = Apdu::parse(&[0x00, 0xC0, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(a.ne, 256);
    }

    #[test]
    fn extended_bad_lc() {
        // Extended Lc=16 but only 1 data byte present → WrongLength.
        let raw = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0xAA];
        assert_eq!(Apdu::parse(&raw).err(), Some(Error::WrongLength));
    }

    #[test]
    fn extended_marker_too_short_is_short_lc() {
        // Leading 0 but only 6 bytes: too short for extended, decoded as short Le.
        let a = Apdu::parse(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x10]).unwrap();
        assert_eq!(a.nc, 0);
        assert_eq!(a.ne, 0x10);
        assert!(a.data.is_empty());
    }

    #[test]
    fn chaining_flag() {
        // CLA bit 0x10 marks a chaining segment.
        assert!(
            Apdu::parse(&[0x10, 0x01, 0x00, 0x00])
                .unwrap()
                .is_chaining()
        );
        assert!(
            !Apdu::parse(&[0x00, 0x01, 0x00, 0x00])
                .unwrap()
                .is_chaining()
        );
    }

    #[test]
    fn too_short() {
        assert_eq!(Apdu::parse(&[0x00, 0x01]), Err(Error::WrongLength));
    }

    #[test]
    fn bad_lc() {
        // Lc says 10 but only 1 data byte follows (size 6 → short-Lc branch)
        assert_eq!(
            Apdu::parse(&[0x00, 0x01, 0x00, 0x00, 0x0A, 0xAA]).err(),
            Some(Error::WrongLength)
        );
    }
}
