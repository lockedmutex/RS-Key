// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! BER-TLV walk/find. Tags are 1 or 2 bytes (the 2-byte form when the low 5 bits
//! are `0x1f`); lengths are short (`< 0x80`), `0x81 + 1 byte`, or `0x82 + 2 bytes`.

/// Iterator over the TLV objects in a byte slice. Yields `(tag, value)`.
/// Malformed/overrunning input simply ends iteration.
pub struct Tlv<'a> {
    rest: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Tlv { rest: data }
    }
}

impl<'a> Iterator for Tlv<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.rest;
        if b.is_empty() {
            return None;
        }
        let mut p = 0usize;
        let mut tag = *b.get(p)? as u16;
        p += 1;
        if tag & 0x1f == 0x1f {
            tag = (tag << 8) | *b.get(p)? as u16;
            p += 1;
        }
        let l0 = *b.get(p)?;
        p += 1;
        let len = match l0 {
            0x82 => {
                let v = ((*b.get(p)? as usize) << 8) | *b.get(p + 1)? as usize;
                p += 2;
                v
            }
            0x81 => {
                let v = *b.get(p)? as usize;
                p += 1;
                v
            }
            n => n as usize,
        };
        let end = p.checked_add(len)?;
        if end > b.len() {
            return None;
        }
        let value = &b[p..end];
        self.rest = &b[end..];
        Some((tag, value))
    }
}

/// Return the value of the first object with `tag`.
pub fn find_tag(data: &[u8], tag: u16) -> Option<&[u8]> {
    Tlv::new(data).find(|(t, _)| *t == tag).map(|(_, v)| v)
}

/// Number of bytes the encoded length field needs.
pub const fn format_len_size(len: u16) -> usize {
    if len < 128 {
        1
    } else if len < 256 {
        2
    } else {
        3
    }
}

/// Encode `len` into `out`, returning the number of bytes written.
pub fn format_len(len: u16, out: &mut [u8]) -> usize {
    if len < 128 {
        out[0] = len as u8;
        1
    } else if len < 256 {
        out[0] = 0x81;
        out[1] = len as u8;
        2
    } else {
        out[0] = 0x82;
        out[1] = (len >> 8) as u8;
        out[2] = len as u8;
        3
    }
}

/// Total encoded size of a TLV object with `tag` and `len`.
pub const fn len_tag(tag: u16, len: u16) -> usize {
    let base = 1 + format_len_size(len) + len as usize;
    if tag > 0x00ff { base + 1 } else { base }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_two_objects() {
        // 0x5A len2 [aa bb], 0x9F1F (2-byte tag) len1 [cc]
        let data = [0x5A, 0x02, 0xAA, 0xBB, 0x9F, 0x1F, 0x01, 0xCC];
        let items: Vec<_> = Tlv::new(&data).collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (0x5A, &[0xAA, 0xBB][..]));
        assert_eq!(items[1], (0x9F1F, &[0xCC][..]));
    }

    #[test]
    fn find_and_long_len() {
        // tag 0x70, length 0x81 0x80 (128 bytes)
        let mut data = [0u8; 3 + 128];
        data[0] = 0x70;
        data[1] = 0x81;
        data[2] = 0x80;
        let v = find_tag(&data, 0x70).unwrap();
        assert_eq!(v.len(), 128);
        assert!(find_tag(&data, 0x71).is_none());
    }

    #[test]
    fn truncated_is_none() {
        // claims 5 bytes but only 2 present
        let data = [0x5A, 0x05, 0x01, 0x02];
        assert_eq!(Tlv::new(&data).count(), 0);
    }

    #[test]
    fn format_len_roundtrip() {
        let mut buf = [0u8; 3];
        assert_eq!(format_len(10, &mut buf), 1);
        assert_eq!(buf[0], 10);
        assert_eq!(format_len(200, &mut buf), 2);
        assert_eq!(&buf[..2], &[0x81, 200]);
        assert_eq!(format_len(0x1234, &mut buf), 3);
        assert_eq!(&buf[..3], &[0x82, 0x12, 0x34]);
    }
}
