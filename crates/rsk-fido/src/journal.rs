// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Tamper-evident audit journal: a fixed flash ring of 20-byte entries
//! hash-chained from a sealed "epoch" accumulator, exported and attested over
//! `authenticatorVendor` (AUDIT_READ / AUDIT_CHECKPOINT).
//!
//! Layout. `EF_AUDIT_META` = `ver(1) ‖ seq_next(4 LE) ‖ start(4 LE) ‖ epoch(32)`;
//! entry `seq` lives in slot `EF_AUDIT_RING + (seq % AUDIT_RING_SLOTS)` and the
//! live window is `[start, seq_next)`. When the ring is full the oldest entry
//! is folded into the epoch — `epoch' = SHA-256(epoch ‖ entry)` — and that meta
//! is committed *before* the slot is reused, so a power cut anywhere loses at
//! most the newest event and never produces a false tamper verdict.
//!
//! The chain head is `fold(epoch, window entries)`. A checkpoint signs
//! `"RSK-AUDIT-CKPT-v1" ‖ head ‖ seq_next ‖ challenge` with an ECDSA P-256 key
//! derived (HKDF) from the OTP DEVK — the reset-stable device attestation
//! root — so history evicted from the ring (or scrubbed by a reset, which
//! folds the whole window for privacy) stays attested in aggregate.
//!
//! There is no wall clock: entries carry the boot-relative uptime, and the
//! first entry of every power cycle is an [`EV_BOOT`], so ordering is total
//! (`seq`) and boot boundaries are explicit. Appends never fail their caller —
//! an authentication must not break because the log could not be written.

use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use zeroize::Zeroize;

use rsk_crypto::mac::hkdf_sha256;
use rsk_crypto::{Device, sha256};
use rsk_fs::{Fs, Storage};

use crate::consts::{AUDIT_RING_SLOTS, EF_AUDIT_META, EF_AUDIT_RING};
use crate::ec::{MAX_DER_SIG, P256Key};
use crate::error::{CtapError, CtapResult};
use crate::{Ctx, Rng};

// ---- events ----
pub const EV_BOOT: u8 = 0x01;
pub const EV_MAKE_CRED: u8 = 0x02;
pub const EV_GET_ASSERT: u8 = 0x03;
pub const EV_RESET: u8 = 0x04;
pub const EV_PIN_SET: u8 = 0x05;
pub const EV_PIN_CHANGE: u8 = 0x06;
/// aux: 0 = retry counter exhausted, 1 = per-boot mismatch block.
pub const EV_PIN_LOCKOUT: u8 = 0x07;
/// aux = new minimum; detail[0] = forceChangePin flag.
pub const EV_CFG_MIN_PIN: u8 = 0x08;
pub const EV_CFG_EA: u8 = 0x09;
pub const EV_LOCK_ENGAGE: u8 = 0x0A;
pub const EV_LOCK_RELEASE: u8 = 0x0B;
pub const EV_BACKUP_EXPORT: u8 = 0x0C;
pub const EV_BACKUP_LOAD: u8 = 0x0D;
pub const EV_BACKUP_FINALIZE: u8 = 0x0E;
pub const EV_U2F_REGISTER: u8 = 0x0F;
pub const EV_U2F_AUTH: u8 = 0x10;
pub const EV_CHECKPOINT: u8 = 0x11;
pub const EV_ATT_IMPORT: u8 = 0x12;
pub const EV_ATT_CLEAR: u8 = 0x13;

/// Entry: `seq(4 LE) ‖ uptime_ms(4 LE) ‖ event(1) ‖ aux(1) ‖ detail(8) ‖ rsvd(2)`.
pub const ENTRY_LEN: usize = 20;
const META_LEN: usize = 1 + 4 + 4 + 32;
const META_VER: u8 = 1;
const GENESIS_TAG: &[u8] = b"RSK-AUDIT-GENESIS-v1";
const CKPT_TAG: &[u8] = b"RSK-AUDIT-CKPT-v1";

/// The persistent ring state (`EF_AUDIT_META`).
pub struct Meta {
    pub seq_next: u32,
    pub start: u32,
    pub epoch: [u8; 32],
}

/// `SHA-256(tag ‖ serial_hash)` — the chain anchor of an empty journal, bound
/// to the device so two devices' empty journals do not share a head.
fn genesis(dev: &Device) -> [u8; 32] {
    let mut buf = [0u8; 52];
    buf[..GENESIS_TAG.len()].copy_from_slice(GENESIS_TAG);
    buf[GENESIS_TAG.len()..].copy_from_slice(dev.serial_hash);
    sha256(&buf)
}

/// One chain step: `SHA-256(h ‖ entry)`.
fn chain(h: &[u8; 32], entry: &[u8; ENTRY_LEN]) -> [u8; 32] {
    let mut buf = [0u8; 32 + ENTRY_LEN];
    buf[..32].copy_from_slice(h);
    buf[32..].copy_from_slice(entry);
    sha256(&buf)
}

fn load_meta<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Meta {
    let mut buf = [0u8; META_LEN];
    match fs.read(EF_AUDIT_META, &mut buf) {
        Some(META_LEN) if buf[0] == META_VER => Meta {
            seq_next: u32::from_le_bytes(buf[1..5].try_into().unwrap()),
            start: u32::from_le_bytes(buf[5..9].try_into().unwrap()),
            epoch: buf[9..].try_into().unwrap(),
        },
        _ => Meta {
            seq_next: 0,
            start: 0,
            epoch: genesis(dev),
        },
    }
}

fn put_meta<S: Storage>(fs: &mut Fs<S>, m: &Meta) -> Result<(), ()> {
    let mut buf = [0u8; META_LEN];
    buf[0] = META_VER;
    buf[1..5].copy_from_slice(&m.seq_next.to_le_bytes());
    buf[5..9].copy_from_slice(&m.start.to_le_bytes());
    buf[9..].copy_from_slice(&m.epoch);
    fs.put(EF_AUDIT_META, &buf).map_err(|_| ())
}

fn slot_fid(seq: u32) -> u16 {
    EF_AUDIT_RING + (seq % AUDIT_RING_SLOTS) as u16
}

fn read_slot<S: Storage>(fs: &mut Fs<S>, seq: u32, out: &mut [u8; ENTRY_LEN]) -> Option<()> {
    match fs.read(slot_fid(seq), out) {
        Some(ENTRY_LEN) => Some(()),
        _ => None,
    }
}

fn build_entry(seq: u32, now_ms: u64, ev: u8, aux: u8, detail: &[u8]) -> [u8; ENTRY_LEN] {
    let mut e = [0u8; ENTRY_LEN];
    e[..4].copy_from_slice(&seq.to_le_bytes());
    e[4..8].copy_from_slice(&(now_ms.min(u32::MAX as u64) as u32).to_le_bytes());
    e[8] = ev;
    e[9] = aux;
    let n = detail.len().min(8);
    e[10..10 + n].copy_from_slice(&detail[..n]);
    e
}

/// Append one event, opening the power cycle with an [`EV_BOOT`] entry first.
/// Errors are swallowed — the journal never fails the operation it records.
pub fn append<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, ev: u8, aux: u8, detail: &[u8]) {
    if !ctx.state.audit_boot_logged {
        ctx.state.audit_boot_logged = true;
        let _ = raw_append(ctx, EV_BOOT, 0, &[]);
    }
    let _ = raw_append(ctx, ev, aux, detail);
}

fn raw_append<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    ev: u8,
    aux: u8,
    detail: &[u8],
) -> Result<(), ()> {
    let mut m = load_meta(&ctx.dev, ctx.fs);
    if m.seq_next.wrapping_sub(m.start) >= AUDIT_RING_SLOTS {
        // Full: fold the oldest entry into the epoch and commit that *before*
        // its slot is reused — see the module docs for the power-cut argument.
        let mut e = [0u8; ENTRY_LEN];
        if read_slot(ctx.fs, m.start, &mut e).is_some() {
            m.epoch = chain(&m.epoch, &e);
        }
        m.start = m.start.wrapping_add(1);
        put_meta(ctx.fs, &m)?;
    }
    let entry = build_entry(m.seq_next, ctx.now_ms, ev, aux, detail);
    ctx.fs.put(slot_fid(m.seq_next), &entry).map_err(|_| ())?;
    m.seq_next = m.seq_next.wrapping_add(1);
    put_meta(ctx.fs, &m)
}

/// Fold the whole window into the epoch and delete the entry slots: aggregate
/// history stays attested, per-event details are scrubbed. Run by
/// `authenticatorReset` so a handed-over device keeps chain continuity without
/// leaking where it has been.
pub fn fold_and_scrub<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) {
    let mut m = load_meta(&ctx.dev, ctx.fs);
    let mut e = [0u8; ENTRY_LEN];
    while m.start != m.seq_next {
        if read_slot(ctx.fs, m.start, &mut e).is_some() {
            m.epoch = chain(&m.epoch, &e);
        }
        m.start = m.start.wrapping_add(1);
    }
    if put_meta(ctx.fs, &m).is_err() {
        return; // keep the slots — a half-scrub must not orphan the chain
    }
    for i in 0..AUDIT_RING_SLOTS {
        let _ = ctx.fs.delete(EF_AUDIT_RING + i as u16);
    }
}

/// The current chain head: the epoch folded through the live window.
pub fn chain_head<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> ([u8; 32], Meta) {
    let m = load_meta(dev, fs);
    let mut h = m.epoch;
    let mut e = [0u8; ENTRY_LEN];
    let mut seq = m.start;
    while seq != m.seq_next {
        if read_slot(fs, seq, &mut e).is_some() {
            h = chain(&h, &e);
        }
        seq = seq.wrapping_add(1);
    }
    (h, m)
}

/// The checkpoint signing key: HKDF(salt = serial_hash, ikm = DEVK) → P-256
/// scalar. Deterministic and reset-stable; the counter byte retries the
/// (cosmically unlikely) out-of-range scalar.
pub fn attestation_key(devk: &[u8; 32], serial_hash: &[u8]) -> Option<P256Key> {
    const INFO_TAG: &[u8] = b"RSK audit attestation v1";
    let mut info = [0u8; 25];
    info[..INFO_TAG.len()].copy_from_slice(INFO_TAG);
    let mut scalar = [0u8; 32];
    for i in 0u8..8 {
        info[INFO_TAG.len()] = i;
        if hkdf_sha256(serial_hash, devk, &info, &mut scalar).is_err() {
            return None;
        }
        if let Some(k) = P256Key::from_scalar(&scalar) {
            scalar.zeroize();
            return Some(k);
        }
    }
    scalar.zeroize();
    None
}

/// `AUDIT_READ` (vendor 0x07): export the journal —
/// `{1: start, 2: seq_next, 3: epoch, 4: entries}`. The host recomputes
/// `fold(epoch, entries)` and matches it against a checkpoint head.
pub fn vendor_read<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let m = load_meta(&ctx.dev, ctx.fs);
    let mut entries = [0u8; AUDIT_RING_SLOTS as usize * ENTRY_LEN];
    let mut len = 0usize;
    let mut e = [0u8; ENTRY_LEN];
    let mut seq = m.start;
    while seq != m.seq_next {
        if read_slot(ctx.fs, seq, &mut e).is_some() {
            entries[len..len + ENTRY_LEN].copy_from_slice(&e);
            len += ENTRY_LEN;
        }
        seq = seq.wrapping_add(1);
    }
    encode(out, |enc| {
        enc.map(4)?
            .u8(1)?
            .u32(m.start)?
            .u8(2)?
            .u32(m.seq_next)?
            .u8(3)?
            .bytes(&m.epoch)?
            .u8(4)?
            .bytes(&entries[..len])?;
        Ok(())
    })
}

/// `AUDIT_CHECKPOINT` (vendor 0x08): sign the chain head with the DEVK-derived
/// attestation key — `{1: head, 2: seq_next, 3: sig(DER), 4: pubkey(0x04‖x‖y)}`.
/// `challenge` (≤ 32 bytes, host-chosen) gives the verdict freshness. Refused
/// without a provisioned DEVK: a meaningful attestation needs the OTP root.
pub fn vendor_checkpoint<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    challenge: &[u8],
    out: &mut [u8],
) -> CtapResult {
    if challenge.len() > 32 {
        return Err(CtapError::InvalidParameter);
    }
    let devk = ctx.state.devk.ok_or(CtapError::NotAllowed)?;
    let key = attestation_key(&devk, ctx.dev.serial_hash).ok_or(CtapError::Other)?;
    let (head, m) = chain_head(&ctx.dev, ctx.fs);

    let mut msg = [0u8; CKPT_TAG.len() + 32 + 4 + 32];
    let mut p = 0;
    msg[p..p + CKPT_TAG.len()].copy_from_slice(CKPT_TAG);
    p += CKPT_TAG.len();
    msg[p..p + 32].copy_from_slice(&head);
    p += 32;
    msg[p..p + 4].copy_from_slice(&m.seq_next.to_le_bytes());
    p += 4;
    msg[p..p + challenge.len()].copy_from_slice(challenge);
    p += challenge.len();

    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&msg[..p], &mut sig);
    let (px, py) = key.public_xy();
    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04;
    pubkey[1..33].copy_from_slice(&px);
    pubkey[33..].copy_from_slice(&py);

    let r = encode(out, |enc| {
        enc.map(4)?
            .u8(1)?
            .bytes(&head)?
            .u8(2)?
            .u32(m.seq_next)?
            .u8(3)?
            .bytes(&sig[..sl])?
            .u8(4)?
            .bytes(&pubkey)?;
        Ok(())
    });
    if r.is_ok() {
        append(ctx, EV_CHECKPOINT, 0, &[]);
    }
    r
}

fn encode<F>(out: &mut [u8], f: F) -> CtapResult
where
    F: FnOnce(
        &mut Encoder<Cursor<&mut [u8]>>,
    ) -> Result<(), minicbor::encode::Error<minicbor::encode::write::EndOfSlice>>,
{
    let mut enc = Encoder::new(Cursor::new(out));
    f(&mut enc).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlwaysConfirm, FidoState};
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

    fn run_ctx<T>(
        fs: &mut Fs<RamStorage>,
        state: &mut FidoState,
        f: impl FnOnce(&mut Ctx<RamStorage, SeqRng>) -> T,
    ) -> T {
        let mut rng = SeqRng(1);
        let mut presence = AlwaysConfirm;
        let mut ctx = Ctx {
            dev: dev(),
            fs,
            rng: &mut rng,
            state,
            now_ms: 12345,
            presence: &mut presence,
        };
        f(&mut ctx)
    }

    /// Host-side reference fold: genesis/epoch + every entry ever appended.
    fn reference_head(entries: &[[u8; ENTRY_LEN]]) -> [u8; 32] {
        let mut h = genesis(&dev());
        for e in entries {
            h = chain(&h, e);
        }
        h
    }

    #[test]
    fn append_wrap_folds_and_head_matches_reference() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = FidoState::new();
        state.audit_boot_logged = true; // keep the reference list exact

        // 200 appends on a 128-slot ring: 72 evictions fold into the epoch.
        let mut reference = std::vec::Vec::new();
        run_ctx(&mut fs, &mut state, |ctx| {
            for i in 0..200u32 {
                let detail = i.to_le_bytes();
                raw_append(ctx, EV_GET_ASSERT, 0, &detail).unwrap();
                reference.push(build_entry(i, ctx.now_ms, EV_GET_ASSERT, 0, &detail));
            }
        });

        let (head, m) = chain_head(&dev(), &mut fs);
        assert_eq!(m.seq_next, 200);
        assert_eq!(m.start, 200 - AUDIT_RING_SLOTS);
        assert_eq!(head, reference_head(&reference));
    }

    #[test]
    fn boot_entry_logged_once_per_cycle() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = FidoState::new();
        run_ctx(&mut fs, &mut state, |ctx| {
            append(ctx, EV_MAKE_CRED, 0, &[0xAA; 8]);
            append(ctx, EV_GET_ASSERT, 0, &[0xBB; 8]);
        });
        let (_, m) = chain_head(&dev(), &mut fs);
        assert_eq!(m.seq_next, 3); // BOOT + the two events
        let mut e = [0u8; ENTRY_LEN];
        read_slot(&mut fs, 0, &mut e).unwrap();
        assert_eq!(e[8], EV_BOOT);
    }

    #[test]
    fn fold_and_scrub_keeps_chain_and_deletes_details() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = FidoState::new();
        state.audit_boot_logged = true;

        let mut reference = std::vec::Vec::new();
        run_ctx(&mut fs, &mut state, |ctx| {
            for i in 0..5u32 {
                raw_append(ctx, EV_GET_ASSERT, 0, &i.to_le_bytes()).unwrap();
                reference.push(build_entry(
                    i,
                    ctx.now_ms,
                    EV_GET_ASSERT,
                    0,
                    &i.to_le_bytes(),
                ));
            }
            fold_and_scrub(ctx);
        });

        // Window empty, slots gone, epoch carries the whole history.
        let (head, m) = chain_head(&dev(), &mut fs);
        assert_eq!(m.start, m.seq_next);
        assert!(!fs.has_data(EF_AUDIT_RING));
        assert_eq!(head, reference_head(&reference));

        // The chain continues seamlessly after the scrub.
        run_ctx(&mut fs, &mut state, |ctx| {
            raw_append(ctx, EV_RESET, 0, &[]).unwrap();
            reference.push(build_entry(5, ctx.now_ms, EV_RESET, 0, &[]));
        });
        let (head, _) = chain_head(&dev(), &mut fs);
        assert_eq!(head, reference_head(&reference));
    }

    #[test]
    fn attestation_key_is_deterministic_and_devk_bound() {
        let k1 = attestation_key(&[7; 32], &[0xAB; 32]).unwrap();
        let k2 = attestation_key(&[7; 32], &[0xAB; 32]).unwrap();
        let k3 = attestation_key(&[8; 32], &[0xAB; 32]).unwrap();
        assert_eq!(k1.public_xy(), k2.public_xy());
        assert_ne!(k1.public_xy(), k3.public_xy());
    }

    #[test]
    fn checkpoint_requires_devk_and_signature_verifies() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};

        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = FidoState::new();
        let mut out = [0u8; 512];

        // Without a DEVK the checkpoint is refused.
        let err = run_ctx(&mut fs, &mut state, |ctx| {
            vendor_checkpoint(ctx, &[0x55; 16], &mut out)
        });
        assert_eq!(err, Err(CtapError::NotAllowed));

        state.devk = Some([7; 32]);
        run_ctx(&mut fs, &mut state, |ctx| {
            append(ctx, EV_MAKE_CRED, 0, &[1; 8]);
        });
        let n = run_ctx(&mut fs, &mut state, |ctx| {
            vendor_checkpoint(ctx, &[0x55; 16], &mut out)
        })
        .unwrap();

        // {1: head, 2: seq_next, 3: sig, 4: pubkey}
        let mut d = minicbor::Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 4);
        assert_eq!(d.u8().unwrap(), 1);
        let head: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
        assert_eq!(d.u8().unwrap(), 2);
        let seq_next = d.u32().unwrap();
        assert_eq!(d.u8().unwrap(), 3);
        let sig = d.bytes().unwrap().to_vec();
        assert_eq!(d.u8().unwrap(), 4);
        let pubkey = d.bytes().unwrap().to_vec();

        // The signed head matches the device state *before* the EV_CHECKPOINT
        // entry the call itself appends.
        let (now_head, m) = chain_head(&dev(), &mut fs);
        assert_eq!(m.seq_next, seq_next + 1);
        assert_ne!(head, now_head);

        let mut msg = std::vec::Vec::new();
        msg.extend_from_slice(CKPT_TAG);
        msg.extend_from_slice(&head);
        msg.extend_from_slice(&seq_next.to_le_bytes());
        msg.extend_from_slice(&[0x55; 16]);
        let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let sig = Signature::from_der(&sig).unwrap();
        vk.verify(&msg, &sig).unwrap();
    }

    #[test]
    fn read_exports_window_that_folds_to_head() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut state = FidoState::new();
        let mut out = [0u8; 4096];
        let n = run_ctx(&mut fs, &mut state, |ctx| {
            append(ctx, EV_MAKE_CRED, 1, &[2; 8]);
            append(ctx, EV_PIN_SET, 0, &[]);
            vendor_read(ctx, &mut out)
        })
        .unwrap();

        let mut d = minicbor::Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 4);
        assert_eq!(d.u8().unwrap(), 1);
        let start = d.u32().unwrap();
        assert_eq!(d.u8().unwrap(), 2);
        let seq_next = d.u32().unwrap();
        assert_eq!(d.u8().unwrap(), 3);
        let mut epoch: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
        assert_eq!(d.u8().unwrap(), 4);
        let entries = d.bytes().unwrap();

        assert_eq!(start, 0);
        assert_eq!(seq_next, 3); // BOOT + two events
        assert_eq!(entries.len(), 3 * ENTRY_LEN);
        for e in entries.chunks_exact(ENTRY_LEN) {
            epoch = chain(&epoch, e.try_into().unwrap());
        }
        let (head, _) = chain_head(&dev(), &mut fs);
        assert_eq!(epoch, head);
    }
}
