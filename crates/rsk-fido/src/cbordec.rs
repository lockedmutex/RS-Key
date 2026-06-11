// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Small CBOR-decode helpers shared by the command parsers: map minicbor errors
//! to `CtapError` and require definite-length maps/arrays (CTAP2 canonical CBOR).

use minicbor::Decoder;

use crate::error::CtapError;

pub fn cbor<T>(r: core::result::Result<T, minicbor::decode::Error>) -> Result<T, CtapError> {
    // A major-type mismatch (e.g. a text string where an int is expected) maps to
    // CTAP2_ERR_CBOR_UNEXPECTED_TYPE; anything else is CTAP2_ERR_INVALID_CBOR.
    r.map_err(|e| {
        if e.is_type_mismatch() {
            CtapError::CborUnexpectedType
        } else {
            CtapError::InvalidCbor
        }
    })
}

pub fn def_map(d: &mut Decoder) -> Result<u64, CtapError> {
    cbor(d.map())?.ok_or(CtapError::InvalidCbor)
}

pub fn def_arr(d: &mut Decoder) -> Result<u64, CtapError> {
    cbor(d.array())?.ok_or(CtapError::InvalidCbor)
}
