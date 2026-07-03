// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::files::full_aid;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

fn fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new(), &[]);
    fs.scan();
    fs
}

#[test]
fn algo_default_is_rsa2k() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4]);
    let mut out = [0u8; 64];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_ALGO_SIG)
    };
    // emit_algo always self-writes the tag + length (C1 06) ahead of the
    // value; GET DATA strips the outer tag for FUNC DOs.
    assert_eq!(
        &out[..n],
        &[0xC1, 6, ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00]
    );
}

#[test]
fn full_aid_is_returned_with_serial() {
    let mut fs = fs();
    let aid = full_aid(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let mut out = [0u8; 64];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_FULL_AID)
    };
    assert_eq!(n, 16);
    assert_eq!(&out[..6], OPENPGP_AID);
    assert_eq!(&out[10..14], &[0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn app_data_is_constructed_6e_with_nested_aid_and_hist() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4]);
    let mut out = [0u8; 512];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_APP_DATA)
    };
    // 6E 82 HH LL ...
    assert_eq!(out[0], 0x6E);
    assert_eq!(out[1], 0x82);
    let nested = ((out[2] as usize) << 8) | out[3] as usize;
    assert_eq!(n, nested + 4);
    // first nested DO is 4F (full AID), len 16.
    assert_eq!(out[4], 0x4F);
    assert_eq!(out[5], 16);
    assert_eq!(&out[6..12], OPENPGP_AID);
    // 5F52 historical bytes follows.
    let hist_tag = 6 + 16;
    assert_eq!(&out[hist_tag..hist_tag + 2], &[0x5F, 0x52]);
}

#[test]
fn over_long_flash_do_does_not_overflow_the_output_buffer() {
    // Regression: an over-long stored DO (cardholder name here) must not push the
    // write cursor past `out` and panic. PUT DATA is uncapped and `fs.read`
    // returns the full stored length, so GET DATA 65 used to slice out of range.
    let mut fs = fs();
    fs.put(EF_CH_NAME, &[0x41u8; 2000]).unwrap();
    let aid = full_aid(&[0; 4]);
    let cap = 1024;
    let mut out = [0u8; 1024];
    let mut w = DoWriter::new(&mut out, &mut fs, &aid);
    w.build(EF_CH_DATA); // 0x65 cardholder template, nests EF_CH_NAME
    // Reaching here means no OOB slice panicked; the cursor stayed in bounds.
    assert!(w.len() <= cap);
    let _ = w.bytes(); // bytes() slices out[..pos] — would panic if pos overran
}

#[test]
fn discrete_do_nests_algo_pw_fp() {
    let mut fs = fs();
    // seed a PW status so emit_pw_status emits its 7 bytes.
    fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
    let aid = full_aid(&[0; 4]);
    let mut out = [0u8; 512];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_DISCRETE_DO)
    };
    assert_eq!(out[0], 0x73);
    assert_eq!(out[1], 0x82);
    assert!(n > 4);
    // C0 (ext caps) is the first nested DO.
    assert_eq!(out[4], 0xC0);
    assert_eq!(out[5], 10);
}
