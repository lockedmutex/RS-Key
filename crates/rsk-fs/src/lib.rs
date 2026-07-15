// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(any(test, feature = "test-util")), no_std)]

//! `rsk-fs` — key/value file API over a backend-agnostic `Storage`: file contents
//! are keyed by 16-bit FID. On device the backend is `sequential-storage` over
//! embassy-rp flash (provided by `firmware`); tests use a RAM backend. A dynamic
//! present-cache plus a metadata side-store sit on top; applets own their own FID
//! ranges and access control, so `Fs` is a plain typed KV store.

pub mod fs;
pub mod sealed;
pub mod storage;

pub use fs::Fs;
pub use sealed::{KeyFid, Sealed};
pub use storage::Storage;

/// The metadata side-store EF.
pub const EF_META: u16 = 0xE010;

/// Max number of dynamic (runtime-created) files — the shared budget across ALL
/// applets (each FIDO cred, each PIV key + cert, each OATH cred, each OpenPGP DO, …).
/// Sized to the union of every applet's own logical cap so one applet can't starve
/// another (e.g. filling PIV must not shrink the passkey ceiling). The storage
/// backend's key-pointer cache (firmware `MAIN_CACHE_KEYS`) MUST stay `>=` this, or
/// files past the cache read/migrate off an O(flash) latency cliff.
pub const MAX_DYNAMIC_FILES: usize = 1280;
