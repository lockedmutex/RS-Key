// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Host-side CTAP2 conformance layer. Unlike the per-command `*_tests.rs` (which
//! call the command functions directly), these tests drive the full
//! `process_cbor` dispatcher and assert the *wire envelope* a host observes —
//! the normative CTAP 2.1 §6.4+ structural rules a conformance tool checks
//! (canonical CBOR key order, field types, cross-field dependencies, no unknown
//! or trailing bytes). Re-derived from the public spec: host-only, no hardware,
//! so a protocol regression fails at commit time, not on a flashed board.

use super::*;
use crate::u2f::process_u2f;
use minicbor::Decoder;
use rsk_crypto::pinproto::PinProto;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::apdu::Apdu;
use rsk_sdk::sw::Sw;

mod clientpin;
mod config;
mod credmgmt;
mod credprotect;
mod extensions;
mod getassertion;
mod getinfo;
mod largeblobs;
mod makecredential;
mod reset;
mod selection;
mod u2f;

/// Deterministic RNG (copied per test file, matching the repo convention).
struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

/// A user-presence backend that never confirms — a button left untouched.
struct Decline;
impl UserPresence for Decline {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Timeout
    }
}

/// One CTAP2 reply as seen on the wire: the leading status byte and, on success,
/// the CBOR payload that follows it.
struct Resp {
    status: u8,
    body: Vec<u8>,
}

/// A host-side authenticator under test — a fresh flash + FIDO state that CTAP2
/// commands run against, driven through the real `process_cbor` dispatcher.
struct Authr {
    fs: Fs<RamStorage>,
    state: FidoState,
    rng: SeqRng,
    /// Whether presence requests confirm (`AlwaysConfirm`) or time out (`Decline`).
    confirm: bool,
}

impl Authr {
    /// A freshly-provisioned authenticator: seed ensured, no PIN, no credentials.
    fn fresh() -> Self {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        crate::seed::ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        Authr {
            fs,
            state: FidoState::new(),
            rng,
            confirm: true,
        }
    }

    /// Like [`fresh`](Self::fresh) but every presence request times out.
    fn declining() -> Self {
        let mut a = Self::fresh();
        a.confirm = false;
        a
    }

    /// Send `command_byte ‖ params` through the dispatcher and capture the reply.
    fn send(&mut self, cmd: u8, params: &[u8]) -> Resp {
        let mut data = vec![cmd];
        data.extend_from_slice(params);
        let mut out = [0u8; 2048];
        let mut yes = AlwaysConfirm;
        let mut no = Decline;
        let presence: &mut dyn UserPresence = if self.confirm { &mut yes } else { &mut no };
        let n = {
            let mut ctx = Ctx {
                dev: dev(),
                fs: &mut self.fs,
                rng: &mut self.rng,
                state: &mut self.state,
                now_ms: 0,
                presence,
            };
            process_cbor(&mut ctx, &data, &mut out)
        };
        assert!(n >= 1, "process_cbor must write at least a status byte");
        Resp {
            status: out[0],
            body: out[1..n].to_vec(),
        }
    }

    fn get_info(&mut self) -> Resp {
        self.send(consts::CTAP_GET_INFO, &[])
    }

    /// Arm a live pinUvAuthToken with `permissions` and mark a PIN configured;
    /// returns the token so a caller can MAC a message with [`pin_auth`]. Call
    /// AFTER any up-only registration — a configured PIN gates a bare
    /// makeCredential. Mirrors `getassertion_tests::arm_pin`.
    fn arm_token(&mut self, permissions: u8) -> [u8; 32] {
        let mut pin_file = [0u8; 35];
        pin_file[0] = 8; // retries
        pin_file[1] = 4; // min length
        pin_file[2] = 1;
        self.fs.put(consts::EF_PIN, &pin_file).unwrap();
        let token = [0x99u8; 32];
        self.state.paut.token = token;
        self.state.paut.permissions = permissions;
        self.state.begin_using_token(false);
        token
    }

    /// Send a raw U2F (CTAP1) APDU and return its status word and response body.
    /// U2F answers with `(Sw, body)` rather than the CTAP2 status-byte envelope.
    fn send_u2f(&mut self, raw: &[u8]) -> (Sw, Vec<u8>) {
        let apdu = Apdu::parse(raw).unwrap();
        let mut out = [0u8; 1024];
        let mut yes = AlwaysConfirm;
        let mut no = Decline;
        let presence: &mut dyn UserPresence = if self.confirm { &mut yes } else { &mut no };
        let (sw, n) = {
            let mut ctx = Ctx {
                dev: dev(),
                fs: &mut self.fs,
                rng: &mut self.rng,
                state: &mut self.state,
                now_ms: 0,
                presence,
            };
            process_u2f(&mut ctx, &apdu, &mut out)
        };
        (sw, out[..n].to_vec())
    }
}

/// A protocol-2 `pinUvAuthParam`: the HMAC of `msg` under the armed `token`.
fn pin_auth(token: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 48];
    let n = rsk_crypto::pinproto::authenticate(PinProto::Two, token, msg, &mut out).unwrap();
    out[..n].to_vec()
}

/// A successful response carries `CTAP2_OK` and a non-empty CBOR body.
fn assert_ok(r: &Resp) {
    assert_eq!(
        r.status, CTAP2_OK,
        "expected CTAP2_OK, got status 0x{:02x}",
        r.status
    );
    assert!(
        !r.body.is_empty(),
        "a CTAP2_OK response must carry a payload"
    );
}

/// A successful response with no CBOR payload (selection, reset, authenticatorConfig).
fn assert_ok_empty(r: &Resp) {
    assert_eq!(
        r.status, CTAP2_OK,
        "expected CTAP2_OK, got status 0x{:02x}",
        r.status
    );
    assert!(r.body.is_empty(), "this command returns no CBOR payload");
}

/// Decode a definite-length map with unsigned-integer keys; assert the keys are
/// strictly ascending (CTAP canonical order) with no trailing bytes, and return
/// them in order.
fn int_map_keys(body: &[u8]) -> Vec<u32> {
    let mut d = Decoder::new(body);
    let n = d.map().unwrap().expect("definite-length map");
    let mut keys = Vec::new();
    let mut prev: Option<u32> = None;
    for _ in 0..n {
        let k = d.u32().unwrap();
        if let Some(p) = prev {
            assert!(
                k > p,
                "map keys not strictly ascending: 0x{p:02x} then 0x{k:02x}"
            );
        }
        prev = Some(k);
        keys.push(k);
        d.skip().unwrap();
    }
    assert_eq!(
        d.position(),
        body.len(),
        "unexpected trailing bytes after map"
    );
    keys
}

/// Return a decoder positioned at the value of integer `key` in a top-level map,
/// or `None` if the key is absent.
fn field_at(body: &[u8], key: u32) -> Option<Decoder<'_>> {
    let mut d = Decoder::new(body);
    let n = d.map().ok()??;
    for _ in 0..n {
        let k = d.u32().ok()?;
        let vpos = d.position();
        if k == key {
            return Some(Decoder::new(&body[vpos..]));
        }
        d.skip().ok()?;
    }
    None
}

/// Walk a map whose keys are text and whose values are all booleans; assert
/// canonical key order (length, then bytewise) and return the keys in order.
fn bool_map_canonical(d: &mut Decoder) -> Vec<String> {
    let n = d.map().unwrap().expect("definite-length map");
    let mut keys = Vec::new();
    let mut prev: Option<String> = None;
    for _ in 0..n {
        let k = d.str().unwrap().to_string();
        d.bool().unwrap(); // every option value must decode as a boolean
        if let Some(p) = &prev {
            assert!(
                canonical_lt(p, &k),
                "text keys not in canonical order: {p:?} then {k:?}"
            );
        }
        prev = Some(k.clone());
        keys.push(k);
    }
    keys
}

/// CTAP canonical CBOR key order for text keys: shorter encodings first, then
/// bytewise.
fn canonical_lt(a: &str, b: &str) -> bool {
    (a.len(), a.as_bytes()) < (b.len(), b.as_bytes())
}
