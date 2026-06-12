// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorLargeBlobs`: an opaque, platform-managed serialized array in
//! EF_LARGEBLOB. `get` reads a fragment at an offset; `set` accumulates
//! fragments across commands and commits only once the whole array (length
//! fixed by the first fragment, trailing 16 bytes = left half of
//! SHA-256(body)) has arrived and verified.

use minicbor::encode::write::Cursor;
use minicbor::encode::{Error, Write};
use minicbor::{Decoder, Encoder};
use rsk_fs::Storage;

use rsk_crypto::pinproto::PinProto;
use rsk_crypto::sha256;

use crate::cbordec::{cbor, def_map};
use crate::consts::{CTAP_LARGE_BLOBS, EF_LARGEBLOB, MAX_FRAGMENT_LENGTH, MAX_LARGE_BLOB_SIZE};
use crate::error::{CtapError, CtapResult};
use crate::state::PERM_LBW;
use crate::{Ctx, Rng};

struct Req<'a> {
    get: u64,                            // 0x01 — bytes to read (0 = absent)
    set: Option<&'a [u8]>,               // 0x02 — fragment to write
    offset: u64,                         // 0x03 — UINT64_MAX sentinel = absent
    length: u64,                         // 0x04 — total array length (first fragment)
    pin_uv_auth_param: Option<&'a [u8]>, // 0x05
    proto: u64,                          // 0x06
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req {
        get: 0,
        set: None,
        offset: u64::MAX,
        length: 0,
        pin_uv_auth_param: None,
        proto: 0,
    };
    let n = def_map(&mut d)?;
    // Keys must be strictly ascending; unlike authenticatorConfig, key 1 is not
    // mandatory (a write has no key 1).
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u64())?;
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        // `key + 1` would overflow on a `u64::MAX` key (no real CTAP key is
        // anywhere near it); reject rather than wrap the ascending watermark.
        expected = key.checked_add(1).ok_or(CtapError::InvalidCbor)?;
        match key {
            0x01 => req.get = cbor(d.u64())?,
            0x02 => req.set = Some(cbor(d.bytes())?),
            0x03 => req.offset = cbor(d.u64())?,
            0x04 => req.length = cbor(d.u64())?,
            0x05 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            0x06 => req.proto = cbor(d.u64())?,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// `authenticatorLargeBlobs`: read or write a fragment of the large-blob array.
pub fn large_blobs<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;

    // offset (0x03) is mandatory; exactly one of get / set must be present.
    if req.offset == u64::MAX {
        return Err(CtapError::InvalidParameter);
    }
    if (req.get == 0) == req.set.is_none() {
        return Err(CtapError::InvalidParameter);
    }

    if req.get > 0 {
        read_fragment(ctx, &req, out)
    } else {
        write_fragment(ctx, &req, out)
    }
}

fn read_fragment<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    if req.length != 0 {
        return Err(CtapError::InvalidParameter);
    }
    let mut blob = [0u8; MAX_LARGE_BLOB_SIZE];
    let size = ctx.fs.read(EF_LARGEBLOB, &mut blob).unwrap_or(0);
    let offset = req.offset as usize;
    if offset > size {
        return Err(CtapError::InvalidParameter);
    }
    let take = core::cmp::min(req.get as usize, size - offset);
    let mut enc = Encoder::new(Cursor::new(out));
    write_get(&mut enc, &blob[offset..offset + take]).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

fn write_get<W: Write>(enc: &mut Encoder<W>, fragment: &[u8]) -> Result<(), Error<W::Error>> {
    enc.map(1)?.u8(0x01)?.bytes(fragment)?;
    Ok(())
}

fn write_fragment<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    out: &mut [u8],
) -> CtapResult {
    let _ = out; // a write replies with only the status byte
    let set = req.set.ok_or(CtapError::InvalidParameter)?;
    if set.len() > MAX_FRAGMENT_LENGTH {
        return Err(CtapError::InvalidLength);
    }
    let offset = req.offset as usize;
    if offset == 0 {
        if req.length == 0 {
            return Err(CtapError::InvalidParameter);
        }
        if req.length as usize > MAX_LARGE_BLOB_SIZE {
            return Err(CtapError::LargeBlobStorageFull);
        }
        if req.length < 17 {
            return Err(CtapError::InvalidParameter);
        }
        ctx.state.lba.expected_length = req.length as usize;
        ctx.state.lba.expected_next_offset = 0;
    } else if req.length != 0 {
        return Err(CtapError::InvalidParameter);
    }
    if offset != ctx.state.lba.expected_next_offset {
        return Err(CtapError::InvalidSeq);
    }

    // pinUvAuthParam MAC over 0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le(4) ‖ sha256(set).
    let param = req.pin_uv_auth_param.ok_or(CtapError::PuatRequired)?;
    if req.proto == 0 {
        return Err(CtapError::MissingParameter);
    }
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;
    let mut vd = [0u8; 70];
    vd[..32].fill(0xff);
    vd[32] = CTAP_LARGE_BLOBS;
    vd[34..38].copy_from_slice(&(offset as u32).to_le_bytes());
    vd[38..70].copy_from_slice(&sha256(set));
    if !ctx.state.verify_token(proto, &vd, param) || ctx.state.paut.permissions & PERM_LBW == 0 {
        return Err(CtapError::PinAuthInvalid);
    }

    if offset + set.len() > ctx.state.lba.expected_length {
        return Err(CtapError::InvalidParameter);
    }
    if offset == 0 {
        ctx.state.lba.temp.fill(0);
    }
    let next = ctx.state.lba.expected_next_offset;
    ctx.state.lba.temp[next..next + set.len()].copy_from_slice(set);
    ctx.state.lba.expected_next_offset += set.len();

    if ctx.state.lba.expected_next_offset == ctx.state.lba.expected_length {
        let total = ctx.state.lba.expected_length;
        // The platform appends left16(SHA-256(body)) as an integrity tag; verify
        // it (skipped for the 17-byte empty-array minimum, body = 1 byte).
        let sha = sha256(&ctx.state.lba.temp[..total - 16]);
        if total > 17 && sha[..16] != ctx.state.lba.temp[total - 16..total] {
            return Err(CtapError::IntegrityFailure);
        }
        ctx.fs
            .put(EF_LARGEBLOB, &ctx.state.lba.temp[..total])
            .map_err(|_| CtapError::Other)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FidoState;
    use crate::consts::LARGEBLOB_INITIAL;
    use minicbor::Encoder;
    use minicbor::encode::write::Cursor;
    use rsk_crypto::Device;
    use rsk_crypto::pinproto;
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

    const TOKEN: [u8; 32] = [0x99; 32];

    fn armed(perms: u8) -> FidoState {
        let mut s = FidoState::new();
        s.paut.token = TOKEN;
        s.paut.permissions = perms;
        s.begin_using_token(false);
        s
    }

    fn seeded_fs() -> Fs<RamStorage> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL).unwrap();
        fs
    }

    fn run(
        fs: &mut Fs<RamStorage>,
        state: &mut FidoState,
        req: &[u8],
        out: &mut [u8],
    ) -> CtapResult {
        let mut rng = SeqRng(1);
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng: &mut rng,
            state,
            now_ms: 0,
        };
        large_blobs(&mut ctx, req, out)
    }

    // A valid serialized array: `body ‖ left16(SHA-256(body))`.
    fn valid_blob(body: &[u8]) -> std::vec::Vec<u8> {
        let mut v = body.to_vec();
        v.extend_from_slice(&sha256(body)[..16]);
        v
    }

    fn get_request(get: u64, offset: u64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 32];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(2).unwrap();
            e.u8(0x01).unwrap().u64(get).unwrap();
            e.u8(0x03).unwrap().u64(offset).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // A SET request, MACing over 0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le ‖ sha256(set).
    fn set_request(
        offset: u64,
        length: Option<u64>,
        set: &[u8],
        token: &[u8; 32],
    ) -> std::vec::Vec<u8> {
        let mut vd = [0u8; 70];
        vd[..32].fill(0xff);
        vd[32] = CTAP_LARGE_BLOBS;
        vd[34..38].copy_from_slice(&(offset as u32).to_le_bytes());
        vd[38..70].copy_from_slice(&sha256(set));
        let mut mac = [0u8; 32];
        let mlen = pinproto::authenticate(PinProto::Two, token, &vd, &mut mac).unwrap();

        let mut buf = [0u8; 1100];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4 + u64::from(length.is_some())).unwrap();
            e.u8(0x02).unwrap().bytes(set).unwrap();
            e.u8(0x03).unwrap().u64(offset).unwrap();
            if let Some(l) = length {
                e.u8(0x04).unwrap().u64(l).unwrap();
            }
            e.u8(0x05).unwrap().bytes(&mac[..mlen]).unwrap();
            e.u8(0x06).unwrap().u8(2).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn get_bytes(out: &[u8], n: usize) -> std::vec::Vec<u8> {
        let mut d = Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.u8().unwrap(), 0x01);
        d.bytes().unwrap().to_vec()
    }

    #[test]
    fn get_default_blob() {
        let mut fs = seeded_fs();
        let mut state = FidoState::new();
        let mut out = [0u8; 128];
        // A fresh device returns the 17-byte CTAP2.1 default array.
        let n = run(&mut fs, &mut state, &get_request(1000, 0), &mut out).unwrap();
        assert_eq!(get_bytes(&out, n), LARGEBLOB_INITIAL.to_vec());
    }

    #[test]
    fn get_at_offset_truncates() {
        let mut fs = seeded_fs();
        let mut state = FidoState::new();
        let mut out = [0u8; 128];
        // Read 5 bytes from offset 2 → blob[2..7].
        let n = run(&mut fs, &mut state, &get_request(5, 2), &mut out).unwrap();
        assert_eq!(get_bytes(&out, n), LARGEBLOB_INITIAL[2..7].to_vec());
        // Read past the end clamps to size - offset.
        let n = run(&mut fs, &mut state, &get_request(1000, 15), &mut out).unwrap();
        assert_eq!(get_bytes(&out, n), LARGEBLOB_INITIAL[15..].to_vec());
    }

    #[test]
    fn get_offset_beyond_size_rejected() {
        let mut fs = seeded_fs();
        let mut state = FidoState::new();
        let mut out = [0u8; 64];
        // The default blob is 17 bytes; offset 100 is past the end.
        assert_eq!(
            run(&mut fs, &mut state, &get_request(10, 100), &mut out),
            Err(CtapError::InvalidParameter)
        );
    }

    #[test]
    fn set_single_fragment_roundtrips() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        let blob = valid_blob(b"a serialized large-blob array payload");
        let req = set_request(0, Some(blob.len() as u64), &blob, &TOKEN);
        assert_eq!(run(&mut fs, &mut state, &req, &mut out), Ok(0));
        // Persisted verbatim.
        let mut stored = [0u8; 256];
        let sn = fs.read(EF_LARGEBLOB, &mut stored).unwrap();
        assert_eq!(&stored[..sn], &blob[..]);
        // And read back through GET.
        let n = run(&mut fs, &mut state, &get_request(1000, 0), &mut out).unwrap();
        assert_eq!(get_bytes(&out, n), blob);
    }

    #[test]
    fn set_multi_fragment_assembles() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        let blob = valid_blob(&[0xCD; 60]); // 76 bytes total
        let split = 50;
        let r1 = set_request(0, Some(blob.len() as u64), &blob[..split], &TOKEN);
        assert_eq!(run(&mut fs, &mut state, &r1, &mut out), Ok(0));
        // Not committed yet — flash still holds the previous (default) value.
        assert_eq!(fs.size(EF_LARGEBLOB), Some(LARGEBLOB_INITIAL.len()));
        let r2 = set_request(split as u64, None, &blob[split..], &TOKEN);
        assert_eq!(run(&mut fs, &mut state, &r2, &mut out), Ok(0));
        let mut stored = [0u8; 256];
        let sn = fs.read(EF_LARGEBLOB, &mut stored).unwrap();
        assert_eq!(&stored[..sn], &blob[..]);
    }

    #[test]
    fn set_wrong_sequence_rejected() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        let blob = valid_blob(&[0x01; 60]);
        let r1 = set_request(0, Some(blob.len() as u64), &blob[..50], &TOKEN);
        run(&mut fs, &mut state, &r1, &mut out).unwrap();
        // Resume at the wrong offset → INVALID_SEQ.
        let bad = set_request(99, None, &blob[50..], &TOKEN);
        assert_eq!(
            run(&mut fs, &mut state, &bad, &mut out),
            Err(CtapError::InvalidSeq)
        );
    }

    #[test]
    fn set_integrity_failure_rejected() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        let mut blob = valid_blob(&[0x22; 40]);
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // corrupt the trailing SHA-256 tag
        let req = set_request(0, Some(blob.len() as u64), &blob, &TOKEN);
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::IntegrityFailure)
        );
    }

    #[test]
    fn set_bad_mac_rejected() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        let blob = valid_blob(&[0x33; 30]);
        // MAC under the wrong token.
        let req = set_request(0, Some(blob.len() as u64), &blob, &[0x11; 32]);
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::PinAuthInvalid)
        );
    }

    #[test]
    fn set_without_lbw_permission_rejected() {
        let mut fs = seeded_fs();
        // A correctly-MACed request but the token lacks largeBlobWrite.
        let mut state = armed(crate::state::PERM_MC);
        let mut out = [0u8; 64];
        let blob = valid_blob(&[0x44; 30]);
        let req = set_request(0, Some(blob.len() as u64), &blob, &TOKEN);
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::PinAuthInvalid)
        );
    }

    #[test]
    fn set_length_bounds_enforced() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        // length < 17 → INVALID_PARAMETER.
        let req = set_request(0, Some(10), &[0u8; 10], &TOKEN);
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::InvalidParameter)
        );
        // length > MAX_LARGE_BLOB_SIZE → LARGE_BLOB_STORAGE_FULL.
        let req = set_request(0, Some(MAX_LARGE_BLOB_SIZE as u64 + 1), &[0u8; 10], &TOKEN);
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::LargeBlobStorageFull)
        );
    }

    #[test]
    fn missing_offset_rejected() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        // {0x01: 100} — get without offset.
        let req = std::vec![0xA1, 0x01, 0x18, 100];
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::InvalidParameter)
        );
    }

    #[test]
    fn neither_get_nor_set_rejected() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        // {0x03: 0} — offset present, but no get and no set.
        let req = std::vec![0xA1, 0x03, 0x00];
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::InvalidParameter)
        );
    }

    #[test]
    fn both_get_and_set_rejected() {
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        // {0x01: 10, 0x02: h'00', 0x03: 0} — get and set together.
        let req = std::vec![0xA3, 0x01, 0x0A, 0x02, 0x41, 0x00, 0x03, 0x00];
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::InvalidParameter)
        );
    }

    #[test]
    fn max_u64_key_rejected_not_overflow() {
        // Regression for the fuzz crash `a1 1b ff..ff`: a map whose key is
        // `u64::MAX`. The ascending-key watermark `key + 1` used to overflow
        // (panic under debug-assertions, silent wrap on-device); it must now
        // reject the request instead of either.
        let mut fs = seeded_fs();
        let mut state = armed(PERM_LBW);
        let mut out = [0u8; 64];
        // {u64::MAX: ...} — one entry, key 0xffff_ffff_ffff_ffff.
        let req = std::vec![
            0xA1, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ];
        assert_eq!(
            run(&mut fs, &mut state, &req, &mut out),
            Err(CtapError::InvalidCbor)
        );
    }
}
