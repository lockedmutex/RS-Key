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
use minicbor::Decoder;
use rsk_fs::storage::ram::RamStorage;

mod getinfo;

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
    presence: AlwaysConfirm,
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
            presence: AlwaysConfirm,
        }
    }

    /// Send `command_byte ‖ params` through the dispatcher and capture the reply.
    fn send(&mut self, cmd: u8, params: &[u8]) -> Resp {
        let mut data = vec![cmd];
        data.extend_from_slice(params);
        let mut out = [0u8; 2048];
        let n = {
            let mut ctx = Ctx {
                dev: dev(),
                fs: &mut self.fs,
                rng: &mut self.rng,
                state: &mut self.state,
                now_ms: 0,
                presence: &mut self.presence,
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
