// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Resolve the reported device firmware version (management DeviceInfo, FIDO
//! getInfo 0x0E, OATH/OTP/PIV version fields). `FW_VERSION=X.Y.Z` overrides the
//! default 5.7.4; emitted as `PK_FW_VERSION_{MAJOR,MINOR,PATCH}` for `env!`.
use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=FW_VERSION");
    println!("cargo:rerun-if-changed=build.rs");

    let raw = env::var("FW_VERSION").unwrap_or_else(|_| "5.7.4".into());
    let parts: Vec<&str> = raw.trim().split('.').collect();
    assert!(
        (1..=3).contains(&parts.len()),
        "FW_VERSION={raw:?} must be X, X.Y, or X.Y.Z"
    );
    let component = |i: usize| -> u8 {
        match parts.get(i) {
            None => 0,
            Some(s) => s.trim().parse::<u8>().unwrap_or_else(|_| {
                panic!("FW_VERSION={raw:?}: component {s:?} is not an integer 0..=255")
            }),
        }
    };
    let (major, minor, patch) = (component(0), component(1), component(2));

    println!("cargo:rustc-env=PK_FW_VERSION_MAJOR={major}");
    println!("cargo:rustc-env=PK_FW_VERSION_MINOR={minor}");
    println!("cargo:rustc-env=PK_FW_VERSION_PATCH={patch}");
}
