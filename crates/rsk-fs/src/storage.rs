// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The FID → bytes persistence backend. On device this is `sequential-storage`
//! over embassy-rp flash (implemented in `firmware`); tests use `RamStorage`.

use rsk_sdk::error::Result;

/// A persistent map from 16-bit file id to a byte value.
pub trait Storage {
    /// Copy the value for `fid` into `buf` (truncated to `buf.len()`), returning
    /// the value's full length, or `None` if `fid` is absent.
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize>;
    /// Store (or replace) the value for `fid`.
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()>;
    /// Remove `fid` if present.
    fn remove(&mut self, fid: u16) -> Result<()>;
    /// Length of the value for `fid`, or `None`.
    fn size(&mut self, fid: u16) -> Option<usize>;
    /// Whether `fid` has a stored value.
    fn exists(&mut self, fid: u16) -> bool {
        self.size(fid).is_some()
    }
    /// Invoke `f` once per stored key (used to rebuild the dynamic-file set and to
    /// probe credential slots without a per-slot `read` of every absent FID).
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16));
}

#[cfg(any(test, feature = "test-util"))]
pub mod ram {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `Storage` for host tests. `Clone` lets fuzz targets snapshot
    /// an initialized image instead of re-deriving it per exec.
    #[derive(Default, Clone)]
    pub struct RamStorage {
        map: HashMap<u16, Vec<u8>>,
    }

    impl RamStorage {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Storage for RamStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            let v = self.map.get(&fid)?;
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            Some(v.len())
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.map.insert(fid, data.to_vec());
            Ok(())
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.map.remove(&fid);
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.map.get(&fid).map(|v| v.len())
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) {
            for &k in self.map.keys() {
                f(k);
            }
        }
    }
}
