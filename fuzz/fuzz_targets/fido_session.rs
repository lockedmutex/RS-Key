// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Stateful CTAP2 session fuzzing. The single-command FIDO targets (fido_cbor,
//! fido_largeblobs, fido_credmgmt, …) each drive ONE command from a fresh
//! state; this one replays an attacker-chosen *sequence* of CTAPHID_CBOR
//! messages against a single `FidoState` + flash `Fs`, the way a real host
//! session does. PIN/token state, the credential store, the large-blob array
//! and the journal persist across commands — the bugs of this class
//! (largeBlobs offset accumulation, the mgmt write→read length mismatch) are
//! multi-step by nature, invisible to a fresh-state target. The token is
//! pre-armed with every permission so auth-gated paths are reachable without
//! forging a MAC, a resident credential is provisioned so assert / enumerate /
//! delete have something to chew on, and `now_ms` advances per command to
//! cross the token-timeout edges. A reset mid-sequence wipes the store and the
//! session keeps going against the post-reset state. Nothing may panic, every
//! response carries at least a status byte and fits its buffer, and getInfo
//! must succeed no matter what state the sequence left behind.
//!
//! The provisioned flash image is built once and cloned per exec (the
//! `RamStorage` doc invites exactly this snapshot).

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::{Device, sha256};
use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_store};
use rsk_fido::seed::{ensure_seed, load_keydev};
use rsk_fido::state::{PERM_ACFG, PERM_CM, PERM_GA, PERM_LBW, PERM_MC, PERM_PCMR};
use rsk_fido::{Ctx, FidoState, Rng, consts, process_cbor};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

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

/// Flash image with the seed ensured and one resident credential stored.
fn provisioned() -> &'static RamStorage {
    static IMG: OnceLock<RamStorage> = OnceLock::new();
    IMG.get_or_init(|| {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let rp_hash = sha256(b"a.co");
        if let Some(seed) = load_keydev(&d, &mut fs) {
            let input = CredInput {
                rp_id: "a.co",
                user_id: &[1, 2],
                user_name: "u",
                user_display_name: "",
                use_sign_count: true,
                rk: true,
                created_ms: 1,
                alg: -7,  // ES256
                curve: 1, // P-256
                ext: CredExt {
                    cred_protect: 0,
                    cred_blob: &[],
                    hmac_secret: false,
                    large_blob_key: false,
                    third_party_payment: false,
                },
            };
            let mut cred_box = [0u8; 512];
            if let Ok(len) =
                credential_create(&seed, &d, &input, &rp_hash, &[0x11; 12], &mut cred_box)
            {
                let _ = credential_store(
                    &seed,
                    &d,
                    &mut fs,
                    &cred_box[..len],
                    &rp_hash,
                    "a.co",
                    &[1, 2],
                );
            }
        }
        fs.into_storage()
    })
}

fuzz_target!(|data: &[u8]| {
    let d = dev();
    let mut fs = Fs::new(provisioned().clone(), &[]);
    fs.scan();
    let mut rng = SeqRng(2);

    // Arm a token with every permission once; the sequence itself may rotate
    // or kill it (clientPIN, reset) — those transitions are the point.
    let mut state = FidoState::new();
    state.paut.token = [0x99; 32];
    state.paut.permissions = PERM_MC | PERM_GA | PERM_CM | PERM_LBW | PERM_ACFG | PERM_PCMR;
    state.begin_using_token(false);

    let mut presence = rsk_fido::AlwaysConfirm;
    let mut out = [0u8; 2048];
    let mut now_ms: u64 = 2;

    // Split the input into BE16-length-prefixed CBOR messages and replay them
    // against the shared state; large-blob fragments need more than one byte
    // of length.
    let mut i = 0;
    while i + 2 <= data.len() {
        let n = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        let end = (i + n).min(data.len());
        let msg = &data[i..end];
        i = end;

        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms,
        };
        let w = process_cbor(&mut ctx, msg, &mut out);
        assert!(w >= 1 && w <= out.len());
        // getInfo is stateless by spec: it must succeed whatever the sequence
        // did before it.
        if msg.first() == Some(&consts::CTAP_GET_INFO) {
            assert_eq!(out[0], rsk_fido::CTAP2_OK);
        }
        now_ms += 997;
    }
});
