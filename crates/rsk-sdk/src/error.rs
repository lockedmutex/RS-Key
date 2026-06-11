// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Internal error codes.

/// Result alias for SDK-internal operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Internal error codes; success is represented by `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoMemory,
    MemoryFatal,
    NullParam,
    FileNotFound,
    Blocked,
    NoLogin,
    ExecError,
    WrongLength,
    WrongData,
    WrongDkek,
    WrongSignature,
    WrongPadding,
    VerificationFailed,
}
