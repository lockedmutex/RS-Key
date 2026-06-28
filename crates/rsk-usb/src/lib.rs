// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! USB transport layer: CTAPHID (FIDO HID) and the CCID smart-card class.

pub mod ccid;
pub mod ctaphid;
pub mod secure_pin;
