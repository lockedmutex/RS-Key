// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.10 `authenticatorLargeBlobs` conformance for the ungated read,
//! driven through the wire envelope (`process_cbor`): a full get returns the
//! serialized array as `{1: bytes}`, `get=0` is a valid zero-byte read, and an
//! out-of-range offset is rejected.

use super::{Authr, assert_ok, field_at, int_map_keys};
use crate::consts::{CTAP_LARGE_BLOBS, LARGEBLOB_MIN, MAX_LARGE_BLOB_SIZE};
use crate::error::CtapError;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// A largeBlobs get request `{1: get, 3: offset}`.
fn lb_get(offset: u64, get: u64) -> Vec<u8> {
    let mut buf = [0u8; 32];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(get).unwrap();
        e.u8(3).unwrap().u64(offset).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn largeblobs_get_full_array() {
    // A full read returns the serialized large-blob array as {1: bytes}; a fresh
    // device carries at least the 17-byte initial trailer (empty array + hash).
    let r = Authr::fresh().send(CTAP_LARGE_BLOBS, &lb_get(0, MAX_LARGE_BLOB_SIZE as u64));
    assert_ok(&r);
    assert_eq!(int_map_keys(&r.body), vec![1u32]);
    let mut d = field_at(&r.body, 1).expect("config fragment (0x01) present");
    let frag = d.bytes().unwrap();
    assert!(
        frag.len() >= LARGEBLOB_MIN,
        "initial array carries the minimum trailer"
    );
    assert!(
        frag.len() <= MAX_LARGE_BLOB_SIZE,
        "fragment within the advertised max"
    );
}

#[test]
fn largeblobs_get_zero_length_is_valid() {
    // get=0 is a valid zero-byte read (conformance LargeBlobs-1 P-2).
    let r = Authr::fresh().send(CTAP_LARGE_BLOBS, &lb_get(0, 0));
    assert_ok(&r);
    let mut d = field_at(&r.body, 1).expect("config fragment (0x01) present");
    assert_eq!(d.bytes().unwrap().len(), 0);
}

#[test]
fn largeblobs_offset_past_end_rejected() {
    // offset > size → CTAP2_ERR_INVALID_PARAMETER.
    let r = Authr::fresh().send(CTAP_LARGE_BLOBS, &lb_get(u64::from(u32::MAX), 1));
    assert_eq!(r.status, CtapError::InvalidParameter.as_u8());
}
