// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PUT DATA (INS 0xDA): write the working DOs, with the algorithm-attribute
//! redirect (C1/C2/C3 → EF_ALGO_PRIV1/2/3). The reset code (0xD3) and PW-status
//! (0xC4) are routed by the dispatch to their own handlers (they touch the DEK
//! / status file, not the generic DO store).

use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use crate::consts::*;
use crate::files::{DoSource, source};
use crate::pin::Session;

/// Write `data` to the DO addressed by `fid` (empty `data` deletes it). ACL:
/// private DOs 1/3 need PW2 or PW3; everything else needs PW3.
pub fn put_data<S: Storage>(fs: &mut Fs<S>, sess: &Session, fid: u16, data: &[u8]) -> Sw {
    let target = match fid {
        // Routed away by the dispatch (put_reset_code / put_pw_status); rejected
        // here so a direct call cannot write them as raw DOs.
        EF_RESET_CODE | EF_PW_STATUS => return Sw::CONDITIONS_NOT_SATISFIED,
        // Algorithm attributes write to the private storage read back by `dobj`.
        EF_ALGO_SIG => EF_ALGO_PRIV1,
        EF_ALGO_DEC => EF_ALGO_PRIV2,
        EF_ALGO_AUT => EF_ALGO_PRIV3,
        f if matches!(source(f), DoSource::Flash) => f,
        _ => return Sw::REFERENCE_NOT_FOUND,
    };

    let priv13 = fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3;
    let authorized = if priv13 {
        sess.has_pw2 || sess.has_pw3
    } else {
        sess.has_pw3
    };
    if !authorized {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }

    if data.is_empty() {
        let _ = fs.delete(target);
    } else if fs.put(target, data).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// PUT DATA PW status (`0xC4` → `EF_PW_PRIV`): update the leading status bytes
/// (the "PW1 valid for multiple signatures" flag + max-length bytes) in place,
/// preserving the retry counters. Requires PW3.
pub fn put_pw_status<S: Storage>(fs: &mut Fs<S>, sess: &Session, data: &[u8]) -> Sw {
    if !sess.has_pw3 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    let mut pw = [0u8; 7];
    let n = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) => n,
        None => return Sw::REFERENCE_NOT_FOUND,
    };
    let m = data.len().min(n);
    pw[..m].copy_from_slice(&data[..m]);
    if fs.put(EF_PW_PRIV, &pw[..n]).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

#[cfg(test)]
#[path = "putdata_tests.rs"]
mod tests;
