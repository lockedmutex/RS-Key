// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn json_escapes_and_nulls() {
    let mut s = DeviceSnapshot::default();
    s.identity.serial = Some("ab\"cd".into());
    let j = s.to_json();
    assert!(j.contains("\"serial\":\"ab\\\"cd\""));
    assert!(j.contains("\"backup\":null"));
    assert!(j.contains("\"demo\":false"));
    // Valid-ish: balanced braces, starts/ends as object.
    assert!(j.starts_with('{') && j.ends_with('}'));
}

#[test]
fn summary_without_device() {
    let s = DeviceSnapshot::default();
    assert_eq!(s.summary(), "no device detected");
    assert_eq!(s.overall_health(), Health::Unknown);
}

#[test]
fn security_status_classifies_health() {
    let mut s = DeviceSnapshot::default();
    s.fido.present = true;
    s.backup = Some(BackupState {
        sealed: false,
        has_seed: false,
    });
    s.lock = Some(LockState {
        locked: true,
        unlocked: false,
    });
    s.secure_boot = Some(SecureBootState {
        enabled: true,
        locked: false,
        bootkey: 1,
    });
    let rows = s.security_status();
    let by = |k: &str| rows.iter().find(|r| r.key == k).unwrap().health;
    assert_eq!(by("backup"), Health::Warn); // has_seed = false
    assert_eq!(by("seed lock"), Health::Warn); // locked, not unlocked
    assert_eq!(by("secure boot"), Health::Warn); // enabled, not locked
}

#[test]
fn log_redacts_known_secret_substrings() {
    let mut log = EventLog::default();
    log.push(LogLevel::Info, "pin was 1234 oops", &["1234"]);
    assert_eq!(log.iter().last().unwrap().text, "pin was [redacted] oops");
}

#[test]
fn log_is_bounded() {
    let mut log = EventLog::default();
    for i in 0..(EventLog::CAP + 50) {
        log.push(LogLevel::Info, format!("e{i}"), &[]);
    }
    assert_eq!(log.len(), EventLog::CAP);
    assert_eq!(
        log.iter().last().unwrap().text,
        format!("e{}", EventLog::CAP + 49)
    );
}
