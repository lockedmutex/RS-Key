// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Build script: places `memory.x` on the linker search path, resolves the
//! compile-time USB VID/PID (see [`resolve_vidpid`]) and the XOSC startup-delay
//! multiplier, and bakes them in as `PK_*` env vars that `main.rs` reads with `env!`.
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");

    let (vid, pid) = resolve_vidpid();
    println!("cargo:rustc-env=PK_USB_VID={vid}");
    println!("cargo:rustc-env=PK_USB_PID={pid}");
    println!("cargo:rerun-if-env-changed=VIDPID");
    println!("cargo:rerun-if-env-changed=USB_VID");
    println!("cargo:rerun-if-env-changed=USB_PID");

    println!(
        "cargo:rustc-env=PK_XOSC_DELAY_MULT={}",
        resolve_xosc_delay_mult()
    );
    println!("cargo:rerun-if-env-changed=XOSC_DELAY_MULT");

    // Bake fake OTP keys into the image instead of reading the fuses — exercises
    // the kbase migration + boot path without an irreversible OTP write.
    // TEST BUILDS ONLY; never set for a shipped image.
    for (env_var, baked) in [("FAKE_MKEK", "PK_FAKE_MKEK"), ("FAKE_DEVK", "PK_FAKE_DEVK")] {
        if let Some(hex) = resolve_fake_key(env_var) {
            println!("cargo:rustc-env={baked}={hex}");
            println!("cargo:warning={env_var} baked into this image — TEST BUILD ONLY, never ship");
        }
        println!("cargo:rerun-if-env-changed={env_var}");
    }
}

/// Validate a fake-OTP-key env var: exactly 64 hex chars (32 bytes), returned
/// lowercased. Anything else fails the build — a silently truncated key would
/// "work" while sealing data under the wrong root.
fn resolve_fake_key(var: &str) -> Option<String> {
    let v = env::var(var).ok()?;
    if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!("{var} must be exactly 64 hex chars (32 bytes), got {v:?}");
    }
    Some(v.to_ascii_lowercase())
}

/// Resolve the XOSC startup-delay multiplier (`XOSC_DELAY_MULT`, default 128 =
/// the embassy default). A larger multiplier lengthens the crystal-oscillator
/// settle wait before the chip runs from it, hardening the early-boot /
/// clock-switch window against glitch / fault injection. Range 1..=1024: embassy
/// stores the derived startup count as a `u16`, which a larger multiplier would
/// overflow for the 12 MHz crystal.
fn resolve_xosc_delay_mult() -> u32 {
    let raw = env::var("XOSC_DELAY_MULT").unwrap_or_else(|_| "128".into());
    let v = raw
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("XOSC_DELAY_MULT={raw:?} is not a positive integer"));
    assert!(
        (1..=1024).contains(&v),
        "XOSC_DELAY_MULT={v} out of range 1..=1024"
    );
    v
}

/// Resolve the (VID, PID) pair: `VIDPID=<preset>` picks a named pair (default
/// `Yubikey5`, 0x1050:0x0407), then `USB_VID` / `USB_PID` (`0xHHHH` or decimal)
/// override either half. 0x1050 is Yubico's VID — a local-interop masquerade for
/// host software that allowlists Yubico, not for distribution; `VIDPID=Dev`
/// selects this project's own non-colliding ids.
fn resolve_vidpid() -> (u16, u16) {
    let preset = env::var("VIDPID").unwrap_or_else(|_| "Yubikey5".into());
    let (mut vid, mut pid) = match preset.as_str() {
        // Named vendor presets.
        "NitroHSM" => (0x20A0, 0x4230),
        "NitroFIDO2" => (0x20A0, 0x42B1),
        "NitroStart" => (0x20A0, 0x4211),
        "NitroPro" => (0x20A0, 0x4108),
        "Nitro3" => (0x20A0, 0x42B2),
        "Yubikey5" => (0x1050, 0x0407),
        "YubikeyNeo" => (0x1050, 0x0116),
        "YubiHSM" => (0x1050, 0x0030),
        "Gnuk" => (0x234B, 0x0000),
        "GnuPG" => (0x1209, 0x2440),
        // Raspberry Pi VID fallback and this project's own dev ids.
        "Pico" => (0x2E8A, 0x10FD),
        "Dev" => (0xFEFF, 0xFCFD),
        other => panic!(
            "unknown VIDPID preset {other:?}; known: NitroHSM, NitroFIDO2, NitroStart, \
             NitroPro, Nitro3, Yubikey5, YubikeyNeo, YubiHSM, Gnuk, GnuPG, Pico, Dev \
             (or set USB_VID / USB_PID directly)"
        ),
    };
    if let Ok(v) = env::var("USB_VID") {
        vid = parse_u16(&v, "USB_VID");
    }
    if let Ok(p) = env::var("USB_PID") {
        pid = parse_u16(&p, "USB_PID");
    }
    (vid, pid)
}

/// Parse a `0xHHHH` (or decimal) 16-bit value from an env override.
fn parse_u16(s: &str, var: &str) -> u16 {
    let s = s.trim();
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    let v = parsed.unwrap_or_else(|_| panic!("{var}={s:?} is not a 0xHHHH or decimal number"));
    assert!(v <= 0xFFFF, "{var}={s:?} exceeds 16 bits");
    v as u16
}
