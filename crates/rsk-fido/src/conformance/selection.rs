// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.9 `authenticatorSelection` conformance, driven through the wire
//! envelope (`process_cbor`): an empty success on presence, a timeout without it.

use super::{Authr, assert_ok_empty};
use crate::consts::CTAP_SELECTION;
use crate::error::CtapError;

#[test]
fn selection_confirms_on_presence() {
    // A present user yields an empty CTAP2_OK (the "this is me" tap).
    let r = Authr::fresh().send(CTAP_SELECTION, &[]);
    assert_ok_empty(&r);
}

#[test]
fn selection_times_out_without_presence() {
    // No touch → CTAP2_ERR_USER_ACTION_TIMEOUT (§6.9 / conformance HID-1).
    let r = Authr::declining().send(CTAP_SELECTION, &[]);
    assert_eq!(r.status, CtapError::UserActionTimeout.as_u8());
}
