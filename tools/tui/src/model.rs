// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Typed state model for rsk-tui — the vocabulary every other module speaks.
//!
//! Pure data: no device I/O, no ratatui, no terminal. That keeps the UI and the
//! navigation logic testable against a snapshot without any hardware (see the
//! `MockProvider` in `device.rs` and the `--demo` flag). Status is *typed* —
//! the renderer never parses strings back out of a status field.

use std::collections::VecDeque;

use zeroize::Zeroizing;

/// Health of a single status field — drives the OK / WARN / ERROR / UNKNOWN
/// indicator. Color is never the only signal: the renderer always prints the
/// word too, so the dashboard reads on a monochrome or color-blind terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    Ok,
    Warn,
    Error,
    Unknown,
    /// Supported by the device but intentionally not driven from the TUI
    /// (CLI-only). Shown plainly, never faked.
    NotApplicable,
}

impl Health {
    pub fn word(self) -> &'static str {
        match self {
            Health::Ok => "OK",
            Health::Warn => "WARN",
            Health::Error => "ERR",
            Health::Unknown => "UNK",
            Health::NotApplicable => "N/A",
        }
    }
}

/// One typed status row: a health classification plus a human label/value. The
/// renderer consumes these instead of re-deriving state from formatted strings.
#[derive(Clone, Debug)]
pub struct FeatureStatus {
    pub health: Health,
    pub key: String,
    pub value: String,
}

impl FeatureStatus {
    pub fn new(health: Health, key: impl Into<String>, value: impl Into<String>) -> Self {
        FeatureStatus {
            health,
            key: key.into(),
            value: value.into(),
        }
    }
}

/// A presence/answered indicator for a transport channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Link {
    #[default]
    Unknown,
    Present,
    Absent,
    /// Channel exists but the device would not talk (reader busy, etc.).
    Busy,
    Error,
}

impl Link {
    pub fn word(self) -> &'static str {
        match self {
            Link::Unknown => "unknown",
            Link::Present => "present",
            Link::Absent => "absent",
            Link::Busy => "busy",
            Link::Error => "error",
        }
    }
    pub fn health(self) -> Health {
        match self {
            Link::Present => Health::Ok,
            Link::Absent => Health::Unknown,
            Link::Busy => Health::Warn,
            Link::Error => Health::Error,
            Link::Unknown => Health::Unknown,
        }
    }
}

/// Which transports answered this gather.
#[derive(Clone, Debug, Default)]
pub struct TransportStatus {
    /// CTAPHID over hidapi (FIDO).
    pub hid: Link,
    /// The PC/SC subsystem / reader list.
    pub pcsc: Link,
    /// An RS-Key CCID applet that actually answered SELECT.
    pub ccid: Link,
    pub note: Option<String>,
}

/// Stable device identity, gathered from the rescue applet + FIDO getInfo.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub serial: Option<String>,
    pub sdk: Option<String>,
    pub firmware: Option<String>,
    pub bcd_device: Option<u16>,
    pub aaguid: Option<String>,
    pub product: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct FidoState {
    pub present: bool,
    pub versions: Vec<String>,
    pub client_pin: Option<bool>,
    pub options: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct BackupState {
    pub sealed: bool,
    pub has_seed: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct LockState {
    pub locked: bool,
    pub unlocked: bool,
}

impl LockState {
    pub fn describe(self) -> &'static str {
        match (self.locked, self.unlocked) {
            (false, _) => "off",
            (true, true) => "LOCKED (unlocked this session)",
            (true, false) => "LOCKED — FIDO ops disabled until unlock",
        }
    }
    pub fn health(self) -> Health {
        if self.locked && !self.unlocked {
            Health::Warn
        } else {
            Health::Ok
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SecureBootState {
    pub enabled: bool,
    pub locked: bool,
    pub bootkey: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct RollbackState {
    pub required: bool,
    pub version: u8,
    pub capacity: u8,
}

#[derive(Clone, Debug)]
pub struct AttestationState {
    pub installed: bool,
    pub chain_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct FlashState {
    pub free: u32,
    pub used: u32,
    pub kv_total: u32,
    pub files: u32,
    pub chip: u32,
}

/// CCID applet presence. `None` = not probed; `Some(false)` = probed, absent.
#[derive(Clone, Copy, Debug, Default)]
pub struct Applets {
    pub openpgp: Option<bool>,
    pub piv: Option<bool>,
    pub oath: Option<bool>,
    pub otp: Option<bool>,
}

/// Everything the dashboard knows about the device, all typed. Every field is
/// an honest read: `None`/absent means "not observed", never a faked default.
#[derive(Clone, Debug, Default)]
pub struct DeviceSnapshot {
    pub transport: TransportStatus,
    pub identity: Identity,
    pub fido: FidoState,
    pub backup: Option<BackupState>,
    pub lock: Option<LockState>,
    pub secure_boot: Option<SecureBootState>,
    pub rollback: Option<RollbackState>,
    pub attestation: Option<AttestationState>,
    pub flash: Option<FlashState>,
    pub applets: Applets,
    pub errors: Vec<String>,
    /// True when the snapshot came from the mock provider (`--demo`).
    pub demo: bool,
}

impl DeviceSnapshot {
    /// Is *any* RS-Key channel answering?
    pub fn any_device(&self) -> bool {
        self.fido.present || self.transport.ccid == Link::Present
    }

    pub fn pin_set(&self) -> bool {
        self.fido.client_pin == Some(true)
    }

    pub fn sealed(&self) -> bool {
        self.backup.map(|b| b.sealed).unwrap_or(false)
    }

    /// One-line device summary for the header.
    pub fn summary(&self) -> String {
        if !self.any_device() {
            return "no device detected".into();
        }
        let mut parts = Vec::new();
        if let Some(s) = &self.identity.serial {
            parts.push(format!("serial {}", &s[..s.len().min(12)]));
        }
        if let Some(fw) = &self.identity.firmware {
            parts.push(format!("fw {fw}"));
        }
        if let Some(bcd) = self.identity.bcd_device {
            parts.push(format!("bcd {bcd:#06x}"));
        }
        if parts.is_empty() {
            "device present".into()
        } else {
            parts.join(" · ")
        }
    }

    /// The headline security fields as typed status rows (backup, lock, secure
    /// boot, anti-rollback, attestation, flash). The renderer just paints these.
    pub fn security_status(&self) -> Vec<FeatureStatus> {
        let mut out = Vec::new();
        match self.backup {
            Some(b) => out.push(FeatureStatus::new(
                if b.has_seed { Health::Ok } else { Health::Warn },
                "backup",
                format!("sealed={}  has_seed={}", b.sealed, b.has_seed),
            )),
            None => out.push(FeatureStatus::new(Health::Unknown, "backup", "—")),
        }
        if let Some(l) = self.lock {
            out.push(FeatureStatus::new(l.health(), "seed lock", l.describe()));
        }
        match self.secure_boot {
            Some(sb) => {
                let (h, t) = if sb.locked {
                    (Health::Ok, "LOCKED")
                } else if sb.enabled {
                    (Health::Warn, "ENABLED (not locked)")
                } else {
                    (Health::Unknown, "not enabled")
                };
                out.push(FeatureStatus::new(
                    h,
                    "secure boot",
                    format!("{t}  bootkey {:#x}", sb.bootkey),
                ));
            }
            None => out.push(FeatureStatus::new(
                Health::Unknown,
                "secure boot",
                "CCID unavailable",
            )),
        }
        if let Some(r) = self.rollback {
            out.push(FeatureStatus::new(
                if r.required {
                    Health::Ok
                } else {
                    Health::Unknown
                },
                "anti-rollback",
                format!(
                    "{}  v{}/{}",
                    if r.required {
                        "required"
                    } else {
                        "not required"
                    },
                    r.version,
                    r.capacity
                ),
            ));
        }
        if let Some(a) = &self.attestation {
            out.push(FeatureStatus::new(
                if a.installed {
                    Health::Ok
                } else {
                    Health::Unknown
                },
                "org attest",
                if a.installed {
                    "installed"
                } else {
                    "not installed"
                },
            ));
        }
        if let Some(fl) = self.flash {
            out.push(FeatureStatus::new(
                Health::Ok,
                "flash",
                format!("{}/{} B used, {} files", fl.used, fl.kv_total, fl.files),
            ));
        }
        out
    }

    /// Worst health across the headline fields — the header's overall dot.
    pub fn overall_health(&self) -> Health {
        if !self.any_device() {
            return Health::Unknown;
        }
        if !self.errors.is_empty() {
            return Health::Warn;
        }
        if let Some(l) = self.lock
            && l.locked
            && !l.unlocked
        {
            return Health::Warn;
        }
        Health::Ok
    }

    /// Hand-rolled JSON for `--json` (no extra deps; stable, explicit schema).
    pub fn to_json(&self) -> String {
        let id = &self.identity;
        let mut out = String::from("{");
        json_field(&mut out, "demo", &json_bool(self.demo), true);
        json_field(
            &mut out,
            "transport",
            &format!(
                "{{\"hid\":{},\"pcsc\":{},\"ccid\":{},\"note\":{}}}",
                json_str(self.transport.hid.word()),
                json_str(self.transport.pcsc.word()),
                json_str(self.transport.ccid.word()),
                json_opt_str(self.transport.note.as_deref()),
            ),
            false,
        );
        json_field(
            &mut out,
            "identity",
            &format!(
                "{{\"serial\":{},\"sdk\":{},\"firmware\":{},\"bcd_device\":{},\"aaguid\":{},\"product\":{}}}",
                json_opt_str(id.serial.as_deref()),
                json_opt_str(id.sdk.as_deref()),
                json_opt_str(id.firmware.as_deref()),
                id.bcd_device
                    .map(|b| json_str(&format!("{b:#06x}")))
                    .unwrap_or_else(|| "null".into()),
                json_opt_str(id.aaguid.as_deref()),
                json_opt_str(id.product.as_deref()),
            ),
            false,
        );
        json_field(
            &mut out,
            "fido",
            &format!(
                "{{\"present\":{},\"versions\":[{}],\"client_pin\":{},\"options\":[{}]}}",
                json_bool(self.fido.present),
                self.fido
                    .versions
                    .iter()
                    .map(|v| json_str(v))
                    .collect::<Vec<_>>()
                    .join(","),
                self.fido
                    .client_pin
                    .map(json_bool)
                    .unwrap_or_else(|| "null".into()),
                self.fido
                    .options
                    .iter()
                    .map(|v| json_str(v))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            false,
        );
        json_field(
            &mut out,
            "backup",
            &self
                .backup
                .map(|b| {
                    format!(
                        "{{\"sealed\":{},\"has_seed\":{}}}",
                        json_bool(b.sealed),
                        json_bool(b.has_seed)
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "lock",
            &self
                .lock
                .map(|l| {
                    format!(
                        "{{\"locked\":{},\"unlocked\":{}}}",
                        json_bool(l.locked),
                        json_bool(l.unlocked)
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "secure_boot",
            &self
                .secure_boot
                .map(|s| {
                    format!(
                        "{{\"enabled\":{},\"locked\":{},\"bootkey\":{}}}",
                        json_bool(s.enabled),
                        json_bool(s.locked),
                        s.bootkey
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "rollback",
            &self
                .rollback
                .map(|r| {
                    format!(
                        "{{\"required\":{},\"version\":{},\"capacity\":{}}}",
                        json_bool(r.required),
                        r.version,
                        r.capacity
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "attestation",
            &self
                .attestation
                .as_ref()
                .map(|a| {
                    format!(
                        "{{\"installed\":{},\"chain_sha256\":{}}}",
                        json_bool(a.installed),
                        json_opt_str(a.chain_sha256.as_deref())
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "flash",
            &self
                .flash
                .map(|f| {
                    format!(
                        "{{\"free\":{},\"used\":{},\"kv_total\":{},\"files\":{},\"chip\":{}}}",
                        f.free, f.used, f.kv_total, f.files, f.chip
                    )
                })
                .unwrap_or_else(|| "null".into()),
            false,
        );
        json_field(
            &mut out,
            "applets",
            &format!(
                "{{\"openpgp\":{},\"piv\":{},\"oath\":{},\"otp\":{}}}",
                json_opt_bool(self.applets.openpgp),
                json_opt_bool(self.applets.piv),
                json_opt_bool(self.applets.oath),
                json_opt_bool(self.applets.otp),
            ),
            false,
        );
        json_field(
            &mut out,
            "errors",
            &format!(
                "[{}]",
                self.errors
                    .iter()
                    .map(|e| json_str(e))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            false,
        );
        out.push('}');
        out
    }
}

// ---- the sections of the cockpit ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Overview,
    Fido,
    OpenPgp,
    Piv,
    OathOtp,
    Backup,
    Led,
    Audit,
    Reboot,
    Help,
}

impl Section {
    pub const ALL: [Section; 10] = [
        Section::Overview,
        Section::Fido,
        Section::OpenPgp,
        Section::Piv,
        Section::OathOtp,
        Section::Backup,
        Section::Led,
        Section::Audit,
        Section::Reboot,
        Section::Help,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Section::Overview => "Overview",
            Section::Fido => "FIDO",
            Section::OpenPgp => "OpenPGP",
            Section::Piv => "PIV",
            Section::OathOtp => "OATH / OTP",
            Section::Backup => "Backup",
            Section::Led => "LED",
            Section::Audit => "Audit",
            Section::Reboot => "Reboot / Maintenance",
            Section::Help => "Help",
        }
    }
}

// ---- actions ----

/// A device operation the TUI can perform itself. Destructive/irreversible
/// firmware rituals are deliberately *not* here — they stay in the `rsk` CLI.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Refresh,
    LedGet,
    LedCycle,
    BackupExport,
    BackupRestore,
    BackupFinalize,
    AuditRead,
    Verify,
    RebootApp,
    RebootBootsel,
}

impl Action {
    /// Short label for the search palette.
    pub fn label(self) -> &'static str {
        match self {
            Action::Refresh => "Refresh status",
            Action::LedGet => "LED · read state",
            Action::LedCycle => "LED · cycle idle color",
            Action::BackupExport => "Backup · export (BIP-39)",
            Action::BackupRestore => "Backup · restore (BIP-39)",
            Action::BackupFinalize => "Backup · finalize (seal window)",
            Action::AuditRead => "Audit · read journal",
            Action::Verify => "Verify device identity",
            Action::RebootApp => "Reboot → app",
            Action::RebootBootsel => "Reboot → BOOTSEL",
        }
    }

    pub fn section(self) -> Section {
        match self {
            Action::Refresh | Action::Verify => Section::Overview,
            Action::LedGet | Action::LedCycle => Section::Led,
            Action::BackupExport | Action::BackupRestore | Action::BackupFinalize => {
                Section::Backup
            }
            Action::AuditRead => Section::Audit,
            Action::RebootApp | Action::RebootBootsel => Section::Reboot,
        }
    }

    /// The whole catalog, for the `/` search palette.
    pub const ALL: [Action; 10] = [
        Action::Refresh,
        Action::Verify,
        Action::LedGet,
        Action::LedCycle,
        Action::BackupExport,
        Action::BackupRestore,
        Action::BackupFinalize,
        Action::AuditRead,
        Action::RebootApp,
        Action::RebootBootsel,
    ];
}

/// Secrets collected across a multi-step modal flow. `Zeroizing` wipes them on
/// drop; they are passed to the device once and never reach the log.
#[derive(Default)]
pub struct ActionInput {
    pub pin: Option<Zeroizing<String>>,
    pub phrase: Option<Zeroizing<String>>,
}

/// Outcome of a device operation.
pub enum ActionResult {
    /// Short, non-secret success message → status line + log.
    Ok(String),
    /// Non-secret failure message → status line + log (as an error).
    Failed(String),
    /// Multi-line, non-secret output → shown in a Message modal (audit, verify).
    Report { title: String, body: String },
    /// A secret to reveal once on-screen, then zeroize. NEVER logged.
    Reveal {
        title: String,
        body: Zeroizing<String>,
    },
}

// ---- the event/log ring ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    Info,
    Good,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub level: LogLevel,
    pub text: String,
}

/// A bounded ring of recent operations. The log is the one place text from
/// actions lands, so redaction lives here: see [`EventLog::push`].
#[derive(Default)]
pub struct EventLog {
    entries: VecDeque<LogEntry>,
}

impl EventLog {
    const CAP: usize = 200;

    /// Append an entry. `secrets` are substrings (live PIN/phrase buffers) that
    /// must never be persisted — a defensive backstop on top of the structural
    /// guarantee that secrets are never handed to the log in the first place.
    pub fn push(&mut self, level: LogLevel, text: impl Into<String>, secrets: &[&str]) {
        let mut text = text.into();
        for s in secrets {
            if !s.is_empty() && text.contains(s) {
                text = text.replace(s, "[redacted]");
            }
        }
        self.entries.push_back(LogEntry { level, text });
        while self.entries.len() > Self::CAP {
            self.entries.pop_front();
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---- tiny JSON helpers (hand-rolled; no serde dep) ----

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt_str(s: Option<&str>) -> String {
    s.map(json_str).unwrap_or_else(|| "null".into())
}

fn json_bool(b: bool) -> String {
    if b { "true".into() } else { "false".into() }
}

fn json_opt_bool(b: Option<bool>) -> String {
    b.map(json_bool).unwrap_or_else(|| "null".into())
}

fn json_field(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push_str(&json_str(key));
    out.push(':');
    out.push_str(value);
}

#[cfg(test)]
mod tests {
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
}
