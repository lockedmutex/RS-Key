// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorMakeCredential`: packed **self-attestation** (no x5c) by
//! default. Resident keys (rk) are stored; non-resident credentials carry the
//! full box in authData. A configured PIN requires a verified `pinUvAuthParam`
//! ([`enforce_pin`]), which sets the `uv` flag. Request extensions are sealed
//! into the box and echoed in the authData extension output (ED flag);
//! excludeList is credProtect-aware. Enterprise attestation (request field
//! 0x0A): level 2 emits a full attestation signed by the device key with its
//! x5c cert and the `ep` response flag; level 1 is accepted but stays
//! self-attestation.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::pinproto::PinProto;
use rsk_crypto::sha256;
use rsk_fs::{Fs, Storage};

use crate::cbordec::{cbor, def_arr, def_map};
use crate::cert;
use crate::consts::{
    AAGUID, ALG_ED25519, ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_ESP256,
    ALG_ESP384, ALG_ESP512, ALG_MLDSA44, CRED_PROT_UV_REQUIRED, CURVE_ED25519, CURVE_MLDSA44,
    CURVE_P256, CURVE_P256K1, CURVE_P384, CURVE_P521, EF_ALWAYS_UV, EF_ATT_CHAIN, EF_EA_ENABLED,
    EF_EE_DEV, EF_MINPINLEN, EF_PIN, FLAG_AT, FLAG_ED, FLAG_UP, FLAG_UV, MAX_CREDBLOB_LENGTH,
    MAX_RESIDENT_CREDENTIALS, PREFER_PQC,
};
use crate::credential::{
    CRED_RESIDENT_LEN, CredExt, CredInput, Credential, RECORD_PREFIX, credential_create,
    credential_load, credential_store, derive_large_blob_key, derive_resident, is_resident,
    slot_map,
};
use crate::ec::{CredKey, MAX_SIG_LEN, P256Key};
use crate::error::{CtapError, CtapResult};
use crate::hmacsecret::{self, HmacSecretReq};
use crate::journal;
use crate::keyderiv::fido_load_key;
use crate::seed::{bump_sign_counter, get_sign_counter, load_att_key};
use crate::state::PERM_MC;
use crate::{Ctx, Rng};

const MAX_EXCLUDE: usize = 16;

/// Map a requested COSE alg (incl. the curve-explicit aliases) to its canonical
/// `(alg, curve)`, or `None` if unsupported.
fn alg_to_curve(alg: i64) -> Option<(i64, u8)> {
    match alg {
        ALG_ES256 | ALG_ESP256 => Some((ALG_ES256, CURVE_P256)),
        ALG_ES384 | ALG_ESP384 => Some((ALG_ES384, CURVE_P384)),
        ALG_ES512 | ALG_ESP512 => Some((ALG_ES512, CURVE_P521)),
        // The FIPS-style profile keeps secp256k1 out of new credentials
        // (existing K1 credentials still assert — creation is the policy gate).
        ALG_ES256K if cfg!(not(feature = "fips-profile")) => Some((ALG_ES256K, CURVE_P256K1)),
        ALG_EDDSA | ALG_ED25519 => Some((ALG_EDDSA, CURVE_ED25519)),
        // ML-DSA-44 only — -49/-50 fall through as unsupported (no enabled backend).
        ALG_MLDSA44 => Some((ALG_MLDSA44, CURVE_MLDSA44)),
        _ => None,
    }
}

struct Request<'a> {
    client_data_hash: &'a [u8],
    rp_id: &'a str,
    user_id: &'a [u8],
    user_name: &'a str,
    user_display_name: &'a str,
    has_pubkey_param: bool,
    /// First supported algorithm + its curve (`0` / unset = none supported).
    sel_alg: i64,
    sel_curve: i64,
    exclude: [&'a [u8]; MAX_EXCLUDE],
    exclude_len: usize,
    rk: bool,
    /// The `up` option as supplied (absent = implicit true). `up=false` is
    /// rejected (§6.1.2); `up=true` is accepted as the default.
    up: Option<bool>,
    uv: bool,
    pin_uv_auth_param: Option<&'a [u8]>,
    pin_uv_auth_protocol: u64,
    ext_cred_protect: u64,
    ext_cred_blob: &'a [u8],
    ext_min_pin_length: bool,
    ext_third_party_payment: bool,
    ext_hmac_secret: bool,
    ext_large_blob_key: Option<bool>,
    hmac_secret_mc: HmacSecretReq<'a>,
    /// enterpriseAttestation (request field 0x0A): 0 none, 1 vendor-facilitated,
    /// 2 platform-managed (full attestation by the device key).
    enterprise_attestation: u64,
}

fn parse(data: &[u8]) -> Result<Request<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Request {
        client_data_hash: &[],
        rp_id: "",
        user_id: &[],
        user_name: "",
        user_display_name: "",
        has_pubkey_param: false,
        sel_alg: 0,
        sel_curve: 0,
        exclude: [&[]; MAX_EXCLUDE],
        exclude_len: 0,
        rk: false,
        up: None,
        uv: false,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: 0,
        ext_cred_protect: 0,
        ext_cred_blob: &[],
        ext_min_pin_length: false,
        ext_third_party_payment: false,
        ext_hmac_secret: false,
        ext_large_blob_key: None,
        hmac_secret_mc: HmacSecretReq::default(),
        enterprise_attestation: 0,
    };

    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Keys 1..=4 are mandatory and must appear first, in order.
        if expected <= 4 && key != expected {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.client_data_hash = cbor(d.bytes())?,
            2 => {
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.str())? {
                        "id" => req.rp_id = cbor(d.str())?,
                        // rp.name must be a text string when present (conformance
                        // MakeCredential Req-2 F-2); read-as-text so a non-text
                        // value surfaces as CBOR_UNEXPECTED_TYPE.
                        "name" => {
                            let _: &str = cbor(d.str())?;
                        }
                        _ => cbor(d.skip())?,
                    }
                }
            }
            3 => {
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.str())? {
                        "id" => req.user_id = cbor(d.bytes())?,
                        "name" => req.user_name = cbor(d.str())?,
                        "displayName" => req.user_display_name = cbor(d.str())?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            4 => {
                let a = def_arr(&mut d)?;
                for _ in 0..a {
                    req.has_pubkey_param = true;
                    let m = def_map(&mut d)?;
                    let (mut ty, mut alg, mut ty_present, mut alg_present) =
                        ("", 0i64, false, false);
                    for _ in 0..m {
                        match cbor(d.str())? {
                            "type" => {
                                ty = cbor(d.str())?;
                                ty_present = true;
                            }
                            "alg" => {
                                alg = cbor(d.i64())?;
                                alg_present = true;
                            }
                            _ => cbor(d.skip())?,
                        }
                    }
                    // Every entry is a PublicKeyCredentialParameters and must carry
                    // both "type" and "alg" (conformance MakeCredential Req-4 F-4).
                    if !ty_present || !alg_present {
                        return Err(CtapError::InvalidCbor);
                    }
                    // Pick the first supported algorithm offered. Under PREFER_PQC
                    // a later ML-DSA-44 entry overrides a classic pick — see the
                    // const's rationale.
                    if ty == "public-key"
                        && let Some((ca, cv)) = alg_to_curve(alg)
                    {
                        let upgrade = PREFER_PQC && ca == ALG_MLDSA44 && req.sel_alg != ALG_MLDSA44;
                        if req.sel_alg == 0 || upgrade {
                            req.sel_alg = ca;
                            req.sel_curve = cv as i64;
                        }
                    }
                }
            }
            5 => {
                let a = def_arr(&mut d)?;
                for _ in 0..a {
                    let m = def_map(&mut d)?;
                    let mut id: &[u8] = &[];
                    let (mut id_present, mut type_present) = (false, false);
                    for _ in 0..m {
                        match cbor(d.str())? {
                            "id" => {
                                id = cbor(d.bytes())?;
                                id_present = true;
                            }
                            // Read "type" as text so a byte-string yields CborUnexpectedType.
                            "type" => {
                                let _: &str = cbor(d.str())?;
                                type_present = true;
                            }
                            _ => cbor(d.skip())?,
                        }
                    }
                    // A credential descriptor needs both "type" and "id".
                    if !type_present || !id_present {
                        return Err(CtapError::MissingParameter);
                    }
                    if req.exclude_len < MAX_EXCLUDE {
                        req.exclude[req.exclude_len] = id;
                        req.exclude_len += 1;
                    }
                }
            }
            6 => {
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.str())? {
                        "credProtect" => req.ext_cred_protect = cbor(d.u32())? as u64,
                        "credBlob" => req.ext_cred_blob = cbor(d.bytes())?,
                        "minPinLength" => req.ext_min_pin_length = cbor(d.bool())?,
                        "thirdPartyPayment" => req.ext_third_party_payment = cbor(d.bool())?,
                        "hmac-secret" => req.ext_hmac_secret = cbor(d.bool())?,
                        "hmac-secret-mc" => req.hmac_secret_mc = hmacsecret::parse(&mut d)?,
                        "largeBlobKey" => req.ext_large_blob_key = Some(cbor(d.bool())?),
                        _ => cbor(d.skip())?,
                    }
                }
            }
            7 => {
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.str())? {
                        "rk" => req.rk = cbor(d.bool())?,
                        "up" => req.up = Some(cbor(d.bool())?),
                        "uv" => req.uv = cbor(d.bool())?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            8 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            9 => req.pin_uv_auth_protocol = cbor(d.u32())? as u64,
            10 => req.enterprise_attestation = cbor(d.u32())? as u64,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// `authenticatorMakeCredential`: write the response CBOR into `out`, returning
/// its length.
pub fn make_credential<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;

    if req.client_data_hash.len() != 32 || req.rp_id.is_empty() || req.user_id.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    if !req.has_pubkey_param {
        return Err(CtapError::MissingParameter);
    }
    if req.sel_alg == 0 {
        return Err(CtapError::UnsupportedAlgorithm);
    }
    // makeCredential forbids built-in "uv" (no on-device UV) and an explicit
    // up=false; up is implicitly true, and an explicit up=true is accepted
    // (conformance MakeCredential Req-6: P-3 up=true succeeds, F-1 up=false fails).
    if req.uv || req.up == Some(false) {
        return Err(CtapError::InvalidOption);
    }
    // largeBlobKey may not be requested as false and requires a resident key.
    if req.ext_large_blob_key == Some(false) || (req.ext_large_blob_key == Some(true) && !req.rk) {
        return Err(CtapError::InvalidOption);
    }
    // hmac-secret-mc requires the hmac-secret flag to also be set.
    if req.hmac_secret_mc.present && !req.ext_hmac_secret {
        return Err(CtapError::MissingParameter);
    }
    // Enterprise attestation (§6.1.2): only when enabled via authenticatorConfig,
    // and only levels 1/2. Whether it is actually performed (and the `ep` flag set)
    // is decided later: type 2 for any RP, type 1 only for a vendor-listed RP — see
    // `rp_eligible_for_vendor_ea` and `full_ea` in `make_credential_inner`.
    if req.enterprise_attestation > 0 {
        if !ctx.fs.has_data(EF_EA_ENABLED) {
            return Err(CtapError::InvalidParameter);
        }
        if req.enterprise_attestation != 1 && req.enterprise_attestation != 2 {
            return Err(CtapError::InvalidOption);
        }
    }

    let rp_id_hash = sha256(req.rp_id.as_bytes());
    let uv = enforce_pin(ctx, &req, &rp_id_hash)?;

    let mut seed = ctx.load_keydev().ok_or(CtapError::Other)?;
    let result = make_credential_inner(ctx, &req, &rp_id_hash, &seed, uv, out);
    seed.zeroize();
    result
}

/// Whether `rp_id` is on the built-in vendor-facilitated (type 1) enterprise
/// attestation list. Shipping firmware carries an EMPTY list — no RP qualifies,
/// so type-1 EA never fires by default. The `ea-conformance-rpid` feature adds the
/// FIDO Conformance Tool's fixed test RPID so its Enterprise-Attestation type-1
/// case can be exercised; it is never enabled in a shipped image.
fn rp_eligible_for_vendor_ea(rp_id: &str) -> bool {
    let _ = rp_id;
    #[cfg(feature = "ea-conformance-rpid")]
    if rp_id == "enterprisetest.certinfra.fidoalliance.org" {
        return true;
    }
    false
}

/// CTAP2.1 PIN/UV enforcement (§8.1/§11.1): verifies a `pinUvAuthParam`
/// against the token and reports whether to set the `uv` flag.
fn enforce_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
) -> Result<bool, CtapError> {
    let pin_set = ctx.fs.has_data(EF_PIN);
    match req.pin_uv_auth_param {
        // Zero-length probe: a selection gesture — wait for a touch, then report
        // the PIN state. With no button configured this confirms instantly.
        Some(&[]) => {
            ctx.require_presence()?;
            Err(if pin_set {
                CtapError::PinAuthInvalid
            } else {
                CtapError::PinNotSet
            })
        }
        Some(param) => {
            let proto = match req.pin_uv_auth_protocol {
                0 => return Err(CtapError::MissingParameter),
                p => PinProto::from_u64(p).ok_or(CtapError::InvalidParameter)?,
            };
            if !ctx.state.verify_token(proto, req.client_data_hash, param)
                || ctx.state.paut.permissions & PERM_MC == 0
                || (ctx.state.paut.has_rp_id && ctx.state.paut.rp_id_hash != *rp_id_hash)
                || !ctx.state.user_verified()
            {
                return Err(CtapError::PinAuthInvalid);
            }
            if !ctx.state.paut.has_rp_id {
                ctx.state.paut.rp_id_hash = *rp_id_hash;
                ctx.state.paut.has_rp_id = true;
            }
            Ok(true)
        }
        // §8.1: a configured PIN must be exercised. alwaysUv additionally forces
        // user verification even when no PIN is set (CTAP 2.1 alwaysUv).
        None if pin_set || ctx.fs.has_data(EF_ALWAYS_UV) => Err(CtapError::PuatRequired),
        None => Ok(false),
    }
}

fn make_credential_inner<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    uv: bool,
    out: &mut [u8],
) -> CtapResult {
    // excludeList: refuse if any listed credential is already ours and visible
    // (a UV-required credProtect credential is invisible without UV — §12.1).
    for &id in &req.exclude[..req.exclude_len] {
        if exclude_hit(ctx.fs, seed, rp_id_hash, id, uv) {
            return Err(CtapError::CredentialExcluded);
        }
    }

    // Seal the credential.
    let mut iv = [0u8; 12];
    ctx.rng.fill(&mut iv);
    let input = CredInput {
        rp_id: req.rp_id,
        user_id: req.user_id,
        user_name: req.user_name,
        user_display_name: req.user_display_name,
        use_sign_count: true,
        rk: req.rk,
        created_ms: ctx.now_ms,
        alg: req.sel_alg,
        curve: req.sel_curve,
        ext: CredExt {
            cred_protect: req.ext_cred_protect,
            cred_blob: req.ext_cred_blob,
            hmac_secret: req.ext_hmac_secret,
            large_blob_key: req.ext_large_blob_key == Some(true),
            third_party_payment: req.ext_third_party_payment,
        },
    };
    let mut cred_box = [0u8; 640];
    let box_len = credential_create(seed, &ctx.dev, &input, rp_id_hash, &iv, &mut cred_box)
        .map_err(|_| CtapError::Other)?;

    // Derive the credential keypair from the box for the selected curve.
    let mut raw = fido_load_key(seed, &cred_box[..box_len]).ok_or(CtapError::Other)?;
    let key = CredKey::from_raw(req.sel_curve, &raw).ok_or(CtapError::Other)?;
    raw.zeroize();

    // hmac-secret-mc output (an hmac-secret evaluation at registration time).
    let mut hs = [0u8; 80];
    let hs_len = if req.hmac_secret_mc.present {
        let ephemeral = *ctx.state.ephemeral_scalar();
        hmacsecret::eval(
            &req.hmac_secret_mc,
            &ephemeral,
            seed,
            &cred_box[..box_len],
            uv,
            ctx.rng,
            &mut hs,
        )?
    } else {
        0
    };

    // authData extension output (credBlob / credProtect / hmac-secret / minPinLength / hmac-secret-mc).
    let mut ext = [0u8; 192];
    let ext_len = encode_mc_extensions(ctx.fs, req, rp_id_hash, &hs[..hs_len], &mut ext)?;
    let ed = if ext_len > 0 { FLAG_ED } else { 0 };

    // §6.1.2 user presence: makeCredential's `up` is implicitly true and cannot
    // be disabled, so a configured button is ALWAYS polled before creating the
    // credential — matching getAssertion — even on the no-PIN path (e.g. an SSH
    // `ed25519-sk` enrollment with no FIDO PIN set). The zero-length
    // pinUvAuthParam probe already took its own touch in `enforce_pin` and
    // returned early, so it never reaches here. No button → instant. A
    // CTAPHID_CANCEL during the wait surfaces as KEEPALIVE_CANCEL.
    ctx.require_presence()?;

    // authData = rpIdHash | flags | counter | aaguid | credIdLen | credId | COSEpubkey | ext
    // Sized for the ML-DSA-44 worst case: 55 header + a non-resident box (≤640)
    // + the 1342-byte AKP COSE key + extensions (≤192) + the appended 32-byte
    // clientDataHash.
    let ctr = get_sign_counter(ctx.fs);
    let mut ad = [0u8; 2304];
    let mut p = 0;
    ad[p..p + 32].copy_from_slice(rp_id_hash);
    p += 32;
    ad[p] = FLAG_AT | FLAG_UP | ed | if uv { FLAG_UV } else { 0 };
    p += 1;
    ad[p..p + 4].copy_from_slice(&ctr.to_be_bytes());
    p += 4;
    ad[p..p + 16].copy_from_slice(&AAGUID);
    p += 16;
    if req.rk {
        let rid = derive_resident(&cred_box[..box_len], &ctx.dev);
        ad[p..p + 2].copy_from_slice(&(rid.len() as u16).to_be_bytes());
        p += 2;
        ad[p..p + rid.len()].copy_from_slice(&rid);
        p += rid.len();
    } else {
        ad[p..p + 2].copy_from_slice(&(box_len as u16).to_be_bytes());
        p += 2;
        ad[p..p + box_len].copy_from_slice(&cred_box[..box_len]);
        p += box_len;
    }
    let cose_len = {
        let mut enc = Encoder::new(Cursor::new(&mut ad[p..]));
        key.cose_public(&mut enc).map_err(|_| CtapError::Other)?;
        enc.writer().position()
    };
    p += cose_len;
    ad[p..p + ext_len].copy_from_slice(&ext[..ext_len]);
    p += ext_len;
    let ad_len = p;

    // Attestation over authData ‖ clientDataHash. Self-attestation (the default)
    // signs with the credential key; enterprise level 2 produces a full ("basic")
    // attestation signed by the device key, carrying its x5c cert and the `ep`
    // response flag.
    ad[ad_len..ad_len + 32].copy_from_slice(req.client_data_hash);
    // Any enterpriseAttestation request (type 1/2, with EA enabled) yields a
    // basic_full (x5c) attestation; a request WITHOUT it keeps the default
    // self-attestation. `ea_performed` — platform-managed (type 2), or
    // vendor-facilitated (type 1) for an RP on the built-in enterprise list (empty
    // in shipping firmware) — presents the org/EP cert and sets the `ep` flag. A
    // type-1 request for a non-listed RP is NOT enterprise: it presents the device's
    // own cert with no `ep` (a normal, non-enterprise attestation — CTAP2.1 §6.1.3,
    // conformance Enterprise-Attestation F-6). The EP/org cert comes from an
    // org-provisioned key (vendor ATT_IMPORT); the non-enterprise / no-org-key path
    // signs with the device key (the seed scalar) + its self-signed EF_EE_DEV cert
    // (the pair U2F register uses).
    let ea_performed = req.enterprise_attestation == 2
        || (req.enterprise_attestation == 1 && rp_eligible_for_vendor_ea(req.rp_id));
    let full_attestation = req.enterprise_attestation > 0;
    let org_key = if ea_performed {
        load_att_key(&ctx.dev, ctx.fs)
    } else {
        None
    };
    let mut sig = [0u8; MAX_SIG_LEN];
    let mut chain = [0u8; cert::ATT_CHAIN_MAX + 1 + 2 * cert::ATT_CHAIN_MAX_CERTS];
    let (att_alg, sig_len, chain_len, certs) = if full_attestation {
        if let Some(mut scalar) = org_key {
            let k = P256Key::from_scalar(&scalar);
            scalar.zeroize();
            let k = k.ok_or(CtapError::Other)?;
            let sl = k.sign_der(&ad[..ad_len + 32], &mut sig);
            let cl = ctx
                .fs
                .read(EF_ATT_CHAIN, &mut chain)
                .filter(|&n| cert::att_chain_count(&chain[..n]) > 0)
                .ok_or(CtapError::Other)?;
            let count = cert::att_chain_count(&chain[..cl]);
            (ALG_ES256, sl, cl, count)
        } else {
            let device_key = P256Key::from_scalar(seed).ok_or(CtapError::Other)?;
            let sl = device_key.sign_der(&ad[..ad_len + 32], &mut sig);
            let mut one = [0u8; 512];
            let cl = match ctx.fs.read(EF_EE_DEV, &mut one) {
                Some(n) if n > 0 => n.min(one.len()),
                _ => return Err(CtapError::Other),
            };
            // Wrap the single self-signed cert in the packed-chain layout so
            // the x5c encode below has one shape.
            chain[0] = 1;
            chain[1..3].copy_from_slice(&(cl as u16).to_le_bytes());
            chain[3..3 + cl].copy_from_slice(&one[..cl]);
            (ALG_ES256, sl, 3 + cl, 1)
        }
    } else {
        let sl = key.sign(&ad[..ad_len + 32], ctx.rng, &mut sig);
        (key.alg(), sl, 0, 0)
    };

    // largeBlobKey response field (0x05) — resident credentials only.
    let large_blob_key = if req.ext_large_blob_key == Some(true) && req.rk {
        Some(derive_large_blob_key(seed, &cred_box[..box_len]))
    } else {
        None
    };

    // Response: { 1: "packed", 2: authData, 3: attStmt [, 4: ep] [, 5: largeBlobKey] }.
    // attStmt = { alg, sig } for self-attestation, + x5c for any basic_full /
    // enterprise attestation. `ep` (field 4) only when EA was actually performed.
    let resp_len = {
        let mut enc = Encoder::new(Cursor::new(&mut *out));
        enc.map(3 + u64::from(ea_performed) + u64::from(large_blob_key.is_some()))
            .and_then(|e| e.u8(1)?.str("packed"))
            .and_then(|e| e.u8(2)?.bytes(&ad[..ad_len]))
            .and_then(|e| e.u8(3)?.map(2 + u64::from(full_attestation)))
            .and_then(|e| e.str("alg")?.i64(att_alg))
            .and_then(|e| e.str("sig")?.bytes(&sig[..sig_len]))
            .map_err(|_| CtapError::Other)?;
        if full_attestation {
            enc.str("x5c")
                .and_then(|e| e.array(u64::from(certs)))
                .map_err(|_| CtapError::Other)?;
            for i in 0..certs {
                let c = cert::att_chain_cert(&chain[..chain_len], i).ok_or(CtapError::Other)?;
                enc.bytes(c).map_err(|_| CtapError::Other)?;
            }
        }
        if ea_performed {
            enc.u8(4)
                .and_then(|e| e.bool(true)) // ep: enterprise attestation used
                .map_err(|_| CtapError::Other)?;
        }
        if let Some(lbk) = large_blob_key {
            enc.u8(5)
                .and_then(|e| e.bytes(&lbk))
                .map_err(|_| CtapError::Other)?;
        }
        enc.writer().position()
    };

    if req.rk
        && credential_store(
            seed,
            &ctx.dev,
            ctx.fs,
            &cred_box[..box_len],
            rp_id_hash,
            req.rp_id,
            req.user_id,
        )
        .is_err()
    {
        return Err(CtapError::KeyStoreFull);
    }
    bump_sign_counter(ctx.fs).map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_MAKE_CRED, 0, &rp_id_hash[..8]);
    Ok(resp_len)
}

/// Is `id` an existing credential for this rp that is *visible* now? A
/// UV-required credProtect credential is hidden without UV, so it does not
/// count as an excludeList hit (§12.1).
fn exclude_hit<S: Storage>(
    fs: &mut Fs<S>,
    seed: &[u8; 32],
    rp_id_hash: &[u8; 32],
    id: &[u8],
    uv: bool,
) -> bool {
    let visible = |c: &Credential| c.ext.cred_protect != CRED_PROT_UV_REQUIRED || uv;
    let mut scratch = [0u8; 1024];
    if is_resident(id) {
        if id.len() != CRED_RESIDENT_LEN {
            return false;
        }
        let mut rec = [0u8; 1024];
        let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
        slot_map(fs, crate::consts::EF_CRED, &mut occupied);
        for i in 0..MAX_RESIDENT_CREDENTIALS {
            if !occupied[i as usize] {
                continue;
            }
            let Some(n) = fs.read(crate::consts::EF_CRED + i, &mut rec) else {
                continue;
            };
            let n = n.min(rec.len());
            if n >= RECORD_PREFIX && rec[..32] == *rp_id_hash && rec[32..RECORD_PREFIX] == *id {
                return credential_load(seed, &rec[RECORD_PREFIX..n], rp_id_hash, &mut scratch)
                    .map(|c| visible(&c))
                    .unwrap_or(false);
            }
        }
        false
    } else {
        credential_load(seed, id, rp_id_hash, &mut scratch)
            .map(|c| visible(&c))
            .unwrap_or(false)
    }
}

/// Build the makeCredential authData extension map (credBlob bool / credProtect /
/// hmac-secret / minPinLength / hmac-secret-mc) into `out`; returns its length
/// (0 if none apply). `hmac_mc` is the already-evaluated hmac-secret-mc output.
fn encode_mc_extensions<S: Storage>(
    fs: &mut Fs<S>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    hmac_mc: &[u8],
    out: &mut [u8],
) -> Result<usize, CtapError> {
    let blob_present = !req.ext_cred_blob.is_empty();
    let min_pin = if req.ext_min_pin_length {
        rp_min_pin_len(fs, rp_id_hash)
    } else {
        0
    };
    let l = u64::from(blob_present)
        + u64::from(req.ext_cred_protect != 0)
        + u64::from(req.ext_hmac_secret)
        + u64::from(min_pin > 0)
        + u64::from(!hmac_mc.is_empty());
    if l == 0 {
        return Ok(0);
    }
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(l).map_err(|_| CtapError::Other)?;
    if blob_present {
        // The flag reports whether the blob was short enough to seal.
        enc.str("credBlob")
            .and_then(|e| e.bool(req.ext_cred_blob.len() < MAX_CREDBLOB_LENGTH))
            .map_err(|_| CtapError::Other)?;
    }
    if req.ext_cred_protect != 0 {
        enc.str("credProtect")
            .and_then(|e| e.u64(req.ext_cred_protect))
            .map_err(|_| CtapError::Other)?;
    }
    if req.ext_hmac_secret {
        enc.str("hmac-secret")
            .and_then(|e| e.bool(true))
            .map_err(|_| CtapError::Other)?;
    }
    if min_pin > 0 {
        enc.str("minPinLength")
            .and_then(|e| e.u8(min_pin))
            .map_err(|_| CtapError::Other)?;
    }
    if !hmac_mc.is_empty() {
        enc.str("hmac-secret-mc")
            .and_then(|e| e.bytes(hmac_mc))
            .map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// The per-RP minimum PIN length from EF_MINPINLEN (`[len, force, rpIdHash…]`), or
/// 0 if this rp is not in the authorised list (set via authenticatorConfig).
fn rp_min_pin_len<S: Storage>(fs: &mut Fs<S>, rp_id_hash: &[u8; 32]) -> u8 {
    let mut buf = [0u8; 2 + 32 * 8];
    let Some(n) = fs.read(EF_MINPINLEN, &mut buf) else {
        return 0;
    };
    let n = n.min(buf.len());
    let mut o = 2;
    while o + 32 <= n {
        if buf[o..o + 32] == *rp_id_hash {
            return buf[0];
        }
        o += 32;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::ensure_seed;
    use minicbor::Decoder;
    use p256::EncodedPoint;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use rsk_crypto::Device;
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

    fn build_request(rk: bool) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(if rk { 5 } else { 4 }).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap(); // clientDataHash
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            if rk {
                e.u8(7)
                    .unwrap()
                    .map(1)
                    .unwrap()
                    .str("rk")
                    .unwrap()
                    .bool(true)
                    .unwrap();
            }
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn run(req: &[u8]) -> (std::vec::Vec<u8>, Fs<RamStorage>) {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 1024];
        let len = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev,
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 1000,
            };
            make_credential(&mut ctx, req, &mut out).unwrap()
        };
        (out[..len].to_vec(), fs)
    }

    fn run_err(req: &[u8]) -> CtapError {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, req, &mut out).unwrap_err()
    }

    // A presence that never confirms — a button left untouched.
    struct Decline;
    impl crate::UserPresence for Decline {
        fn request(&mut self) -> crate::Presence {
            crate::Presence::Timeout
        }
    }

    // `run_err` with a declining button, to prove an operation is touch-gated.
    fn run_err_no_touch(req: &[u8]) -> CtapError {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, req, &mut out).unwrap_err()
    }

    // Build a makeCredential request, writing keys 1–3 then invoking `tail` for the
    // pubKeyCredParams (4) and any excludeList (5). `nkeys` is the total map size.
    fn mc_build(nkeys: u64, tail: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(nkeys).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str("example.com").unwrap();
            e.u8(3).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            tail(&mut e);
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // A valid pubKeyCredParams entry ({4: [{alg: ES256, type: public-key}]}).
    fn good_params(e: &mut Encoder<Cursor<&mut [u8]>>) {
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
    }

    #[test]
    fn makecred_requires_touch() {
        // A bare no-PIN makeCredential must obtain user presence — `up` is
        // implicitly true. A confirming button succeeds; a declining one fails
        // with OperationDenied (guards the no-PIN SSH `ed25519-sk` enrollment path).
        let req = mc_build(4, good_params);
        let _ = run(&req); // AlwaysConfirm → succeeds
        assert_eq!(run_err_no_touch(&req), CtapError::OperationDenied);
    }

    #[test]
    fn malformed_param_error_codes() {
        // pubKeyCredParams entry missing "type" → INVALID_CBOR.
        let req = mc_build(4, |e| {
            e.u8(4).unwrap().array(1).unwrap().map(1).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        });
        assert_eq!(run_err(&req), CtapError::InvalidCbor);

        // pubKeyCredParams "alg" as a text string → CBOR_UNEXPECTED_TYPE.
        let req = mc_build(4, |e| {
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().str("7").unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
        });
        assert_eq!(run_err(&req), CtapError::CborUnexpectedType);

        // excludeList entry missing "type" → MISSING_PARAMETER.
        let req = mc_build(5, |e| {
            good_params(e);
            e.u8(5).unwrap().array(1).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        });
        assert_eq!(run_err(&req), CtapError::MissingParameter);

        // excludeList entry missing "id" → MISSING_PARAMETER.
        let req = mc_build(5, |e| {
            good_params(e);
            e.u8(5).unwrap().array(1).unwrap().map(1).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
        });
        assert_eq!(run_err(&req), CtapError::MissingParameter);

        // excludeList "type" as a byte string → CBOR_UNEXPECTED_TYPE.
        let req = mc_build(5, |e| {
            good_params(e);
            e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().bytes(b"public-key").unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        });
        assert_eq!(run_err(&req), CtapError::CborUnexpectedType);

        // pubKeyCredParams entry missing "alg" → INVALID_CBOR (Req-4 F-4).
        let req = mc_build(4, |e| {
            e.u8(4).unwrap().array(1).unwrap().map(1).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
        });
        assert_eq!(run_err(&req), CtapError::InvalidCbor);
    }

    #[test]
    fn rp_name_must_be_text() {
        // rp.name as a non-text value → CBOR_UNEXPECTED_TYPE (Req-2 F-2). Built
        // inline because mc_build emits rp = {id} only.
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2).unwrap().map(2).unwrap();
            e.str("id").unwrap().str("example.com").unwrap();
            e.str("name").unwrap().u8(7).unwrap(); // name as an integer
            e.u8(3).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            good_params(&mut e);
            e.writer().position()
        };
        assert_eq!(run_err(&buf[..n]), CtapError::CborUnexpectedType);
    }

    #[test]
    fn makecred_up_option() {
        // up=true is accepted (the default); up=false is rejected with
        // INVALID_OPTION (conformance MakeCredential Req-6 P-3 / F-1).
        let up_true = mc_build(5, |e| {
            good_params(e);
            e.u8(7).unwrap().map(1).unwrap();
            e.str("up").unwrap().bool(true).unwrap();
        });
        let (resp, _) = run(&up_true);
        assert!(!resp.is_empty());

        let up_false = mc_build(5, |e| {
            good_params(e);
            e.u8(7).unwrap().map(1).unwrap();
            e.str("up").unwrap().bool(false).unwrap();
        });
        assert_eq!(run_err(&up_false), CtapError::InvalidOption);
    }

    #[test]
    fn makecred_cancel_maps_keepalive_cancel() {
        // A CTAPHID_CANCEL during the user-presence wait makes makeCredential
        // answer CTAP2_ERR_KEEPALIVE_CANCEL (conformance HID-1 P-10).
        struct Cancel;
        impl crate::UserPresence for Cancel {
            fn request(&mut self) -> crate::Presence {
                crate::Presence::Cancelled
            }
        }
        let req = mc_build(4, good_params);
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = Cancel;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        assert_eq!(
            make_credential(&mut ctx, &req, &mut out),
            Err(CtapError::KeepAliveCancel)
        );
    }

    // Parse the response, pull out authData + sig, and check the attestation
    // signature verifies under the credential public key embedded in authData.
    fn verify_response(resp: &[u8], client_data_hash: &[u8; 32]) -> std::vec::Vec<u8> {
        let mut d = Decoder::new(resp);
        // 3 base fields ({1,2,3}); a largeBlobKey credential adds field 0x05.
        assert!(d.map().unwrap().unwrap() >= 3);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let auth_data = d.bytes().unwrap().to_vec();
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.str().unwrap(), "alg");
        assert_eq!(d.i64().unwrap(), ALG_ES256);
        assert_eq!(d.str().unwrap(), "sig");
        let sig = d.bytes().unwrap().to_vec();

        // authData layout: rpIdHash(32) flags(1) ctr(4) aaguid(16) credLen(2) credId COSEkey
        assert_eq!(&auth_data[..32], &sha256(b"example.com")[..]);
        // AT + UP always set; UV may also be set when a pinUvAuthParam was verified.
        assert_eq!(auth_data[32] & (FLAG_AT | FLAG_UP), FLAG_AT | FLAG_UP);
        let cred_len = u16::from_be_bytes([auth_data[37 + 16], auth_data[38 + 16]]) as usize;
        let cose_off = 39 + 16 + cred_len;

        // Parse the COSE EC2 key (1:2, 3:-7, -1:1, -2:x, -3:y).
        let mut cd = Decoder::new(&auth_data[cose_off..]);
        assert_eq!(cd.map().unwrap().unwrap(), 5);
        assert_eq!(cd.u8().unwrap(), 1);
        assert_eq!(cd.u8().unwrap(), 2);
        assert_eq!(cd.u8().unwrap(), 3);
        assert_eq!(cd.i64().unwrap(), ALG_ES256);
        assert_eq!(cd.i8().unwrap(), -1);
        assert_eq!(cd.u8().unwrap(), 1);
        assert_eq!(cd.i8().unwrap(), -2);
        let x = cd.bytes().unwrap().to_vec();
        assert_eq!(cd.i8().unwrap(), -3);
        let y = cd.bytes().unwrap().to_vec();

        let pt = EncodedPoint::from_affine_coordinates(x[..].into(), y[..].into(), false);
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(client_data_hash);
        let s = Signature::from_der(&sig).unwrap();
        vk.verify(&signed, &s)
            .expect("attestation signature verifies");

        auth_data
    }

    #[test]
    fn non_resident_make_credential_self_attestation() {
        let req = build_request(false);
        let (resp, _fs) = run(&req);
        let auth_data = verify_response(&resp, &[0xCD; 32]);
        // Non-resident: credId in authData is the full box (starts with proto f1d00202).
        let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert!(cred_len > 42);
        assert_eq!(&auth_data[55..59], b"\xf1\xd0\x02\x02");
    }

    #[test]
    fn resident_make_credential_stores_and_returns_resident_id() {
        let req = build_request(true);
        let (resp, mut fs) = run(&req);
        let auth_data = verify_response(&resp, &[0xCD; 32]);
        // Resident: credId in authData is the 42-byte resident id (proto f1d00203).
        let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert_eq!(cred_len, 42);
        assert_eq!(&auth_data[59..63], b"\xf1\xd0\x02\x03");
        // The credential was persisted.
        assert!(fs.has_data(crate::consts::EF_CRED));
        assert!(fs.has_data(crate::consts::EF_RP));
        // Counter advanced past zero.
        assert_eq!(get_sign_counter(&mut fs), 1);
    }

    #[test]
    fn unsupported_alg_rejected() {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .bytes(&[1, 2])
                .unwrap();
            // Only RS256 (-257) offered → unsupported.
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(-257).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.writer().position()
        };
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 512];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            make_credential(&mut ctx, &buf[..n], &mut out),
            Err(CtapError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn enterprise_attestation_uses_org_chain_when_provisioned() {
        use p256::EncodedPoint;
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();

        // Org provisioning: sealed key, packed 2-cert chain, EA enabled.
        let org_scalar = [0x21u8; 32];
        crate::seed::store_att_key(&dev, &mut fs, &org_scalar).unwrap();
        let c1 = [0x30u8, 0x03, 1, 2, 3];
        let c2 = [0x30u8, 0x02, 7, 7];
        let mut chain = std::vec::Vec::new();
        chain.extend_from_slice(&c1);
        chain.extend_from_slice(&c2);
        let mut packed = [0u8; 64];
        let plen = crate::cert::att_chain_pack(&chain, &mut packed).unwrap();
        fs.put(EF_ATT_CHAIN, &packed[..plen]).unwrap();
        fs.put(EF_EA_ENABLED, &[1]).unwrap();

        // makeCredential with enterpriseAttestation (0x0A) = 2.
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(10).unwrap().u8(2).unwrap();
            e.writer().position()
        };
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let rlen = make_credential(&mut ctx, &buf[..n], &mut out).unwrap();

        // {1: "packed", 2: authData, 3: {alg, sig, x5c: [c1, c2]}, 4: ep true}.
        let mut d = Decoder::new(&out[..rlen]);
        assert_eq!(d.map().unwrap().unwrap(), 4);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let auth_data = d.bytes().unwrap().to_vec();
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(d.map().unwrap().unwrap(), 3);
        assert_eq!(d.str().unwrap(), "alg");
        assert_eq!(d.i64().unwrap(), ALG_ES256);
        assert_eq!(d.str().unwrap(), "sig");
        let sig = d.bytes().unwrap().to_vec();
        assert_eq!(d.str().unwrap(), "x5c");
        assert_eq!(d.array().unwrap().unwrap(), 2);
        assert_eq!(d.bytes().unwrap(), &c1);
        assert_eq!(d.bytes().unwrap(), &c2);
        assert_eq!(d.u8().unwrap(), 4);
        assert!(d.bool().unwrap());

        // The signature is the org key's, over authData ‖ clientDataHash.
        let (x, y) = P256Key::from_scalar(&org_scalar).unwrap().public_xy();
        let pt = EncodedPoint::from_affine_coordinates((&x).into(), (&y).into(), false);
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        let mut msg = auth_data;
        msg.extend_from_slice(&[0xCD; 32]);
        vk.verify(&msg, &Signature::from_der(&sig).unwrap())
            .unwrap();
    }

    #[cfg(feature = "fips-profile")]
    #[test]
    fn fips_es256k_not_negotiable() {
        // The profile drops secp256k1 from negotiation; the approved set stays.
        assert_eq!(alg_to_curve(ALG_ES256K), None);
        assert!(alg_to_curve(ALG_ES256).is_some());
        assert!(alg_to_curve(ALG_EDDSA).is_some());
        assert!(alg_to_curve(ALG_MLDSA44).is_some());
    }

    #[test]
    fn missing_mandatory_param_rejected() {
        // Map starting at key 2 (clientDataHash missing) → MissingParameter.
        let mut buf = [0u8; 64];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(1).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("x")
                .unwrap();
            e.writer().position()
        };
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        let mut out = [0u8; 64];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            make_credential(&mut ctx, &buf[..n], &mut out),
            Err(CtapError::MissingParameter)
        );
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    /// Configure fs + state as clientPIN leaves them after setPIN + getPinToken:
    /// EF_PIN present (the seed stays plain — PIN ops never wrap it), a live
    /// token with MC|GA permissions. Returns the token so the test can compute
    /// a valid pinUvAuthParam.
    fn arm_pin(fs: &mut Fs<RamStorage>, state: &mut crate::FidoState) -> [u8; 32] {
        let mut pin_file = [0u8; 35];
        pin_file[0] = 8; // retries
        pin_file[1] = 4; // length
        pin_file[2] = 1; // format
        fs.put(EF_PIN, &pin_file).unwrap();
        let token = [0x99u8; 32];
        state.paut.token = token;
        state.paut.permissions = PERM_MC | crate::state::PERM_GA;
        state.begin_using_token(false);
        token
    }

    fn build_request_pin(param: &[u8], proto: u64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(8).unwrap().bytes(param).unwrap();
            e.u8(9).unwrap().u64(proto).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // A resident makeCredential request carrying credBlob + credProtect.
    fn mc_request_ext() -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6).unwrap().map(2).unwrap();
            e.str("credBlob")
                .unwrap()
                .bytes(&[0xAA, 0xBB, 0xCC])
                .unwrap();
            e.str("credProtect").unwrap().u64(2).unwrap();
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // The CBOR bytes of the authData extension map (after the COSE public key).
    fn auth_data_ext(ad: &[u8]) -> std::vec::Vec<u8> {
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cose_off = 55 + cred_len;
        let mut d = Decoder::new(&ad[cose_off..]);
        let nk = d.map().unwrap().unwrap();
        for _ in 0..nk {
            d.skip().unwrap(); // key
            d.skip().unwrap(); // value
        }
        ad[cose_off + d.position()..].to_vec()
    }

    #[test]
    fn make_credential_extensions_stored_and_emitted() {
        let req = mc_request_ext();
        let (resp, mut fs) = run(&req);
        let ad = verify_response(&resp, &[0xCD; 32]);
        assert_eq!(ad[32] & FLAG_ED, FLAG_ED, "ED flag set");

        // authData extension map: credBlob bool (sealed ok) + credProtect 2.
        let ext = auth_data_ext(&ad);
        let mut d = Decoder::new(&ext);
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.str().unwrap(), "credBlob");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "credProtect");
        assert_eq!(d.u64().unwrap(), 2);

        // The stored box carries the extensions.
        let mut rec = [0u8; 1024];
        let n = fs.read(crate::consts::EF_CRED, &mut rec).unwrap();
        let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
        let mut scratch = [0u8; 1024];
        let c = crate::credential::credential_load(
            &seed,
            &rec[crate::credential::RECORD_PREFIX..n],
            &sha256(b"example.com"),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(c.ext.cred_protect, 2);
        assert_eq!(c.ext.cred_blob, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn min_pin_length_extension_for_listed_rp() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        // EF_MINPINLEN = [minLen=6, force=0, sha256("example.com")].
        let mut mp = [0u8; 2 + 32];
        mp[0] = 6;
        mp[2..].copy_from_slice(&sha256(b"example.com"));
        fs.put(EF_MINPINLEN, &mp).unwrap();

        // makeCredential with the minPinLength extension flag.
        let mut buf = [0u8; 512];
        let req = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .bytes(&[1, 2, 3, 4])
                .unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6)
                .unwrap()
                .map(1)
                .unwrap()
                .str("minPinLength")
                .unwrap()
                .bool(true)
                .unwrap();
            let n = e.writer().position();
            buf[..n].to_vec()
        };
        let mut out = [0u8; 1024];
        let len = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 1000,
            };
            make_credential(&mut ctx, &req, &mut out).unwrap()
        };
        let ad = verify_response(&out[..len], &[0xCD; 32]);
        assert_eq!(ad[32] & FLAG_ED, FLAG_ED);
        let ext = auth_data_ext(&ad);
        let mut d = Decoder::new(&ext);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "minPinLength");
        assert_eq!(d.u8().unwrap(), 6);
    }

    #[test]
    fn large_blob_key_in_make_credential() {
        // A resident request opting into largeBlobKey returns the derived key (0x05).
        let mut buf = [0u8; 512];
        let req = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6)
                .unwrap()
                .map(1)
                .unwrap()
                .str("largeBlobKey")
                .unwrap()
                .bool(true)
                .unwrap();
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
            let n = e.writer().position();
            buf[..n].to_vec()
        };
        let (resp, mut fs) = run(&req);
        verify_response(&resp, &[0xCD; 32]);

        // Field 0x05 is the 32-byte largeBlobKey for the stored credential.
        let mut d = Decoder::new(&resp);
        let fields = d.map().unwrap().unwrap();
        let mut lbk = None;
        for _ in 0..fields {
            if d.u8().unwrap() == 5 {
                lbk = Some(d.bytes().unwrap().to_vec());
            } else {
                d.skip().unwrap();
            }
        }
        let mut rec = [0u8; 1024];
        let n = fs.read(crate::consts::EF_CRED, &mut rec).unwrap();
        let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
        let cred_box = &rec[crate::credential::RECORD_PREFIX..n];
        let expected = crate::credential::derive_large_blob_key(&seed, cred_box);
        assert_eq!(lbk.as_deref(), Some(&expected[..]));
    }

    #[test]
    fn make_credential_with_pin_sets_uv_flag() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let mut state = crate::FidoState::new();
        let token = arm_pin(&mut fs, &mut state);
        // Platform MACs the clientDataHash with the token (protocol two).
        let cdh = [0xCDu8; 32];
        let mut param = [0u8; 32];
        let plen =
            rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &cdh, &mut param).unwrap();
        let req = build_request_pin(&param[..plen], 2);
        let mut out = [0u8; 1024];
        let len = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 1000,
            };
            make_credential(&mut ctx, &req, &mut out).unwrap()
        };
        let auth_data = verify_response(&out[..len], &cdh);
        assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV, "UV flag must be set");
    }

    #[test]
    fn make_credential_requires_pin_when_set() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let mut state = crate::FidoState::new();
        arm_pin(&mut fs, &mut state);
        // A PIN is set but the request carries no pinUvAuthParam → PUAT_REQUIRED.
        let mut out = [0u8; 256];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            make_credential(&mut ctx, &build_request(false), &mut out),
            Err(CtapError::PuatRequired)
        );
    }

    #[test]
    fn always_uv_requires_user_verification_without_pin() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let mut state = crate::FidoState::new();
        // No PIN, but alwaysUv is on → makeCredential still demands UV (a verified
        // pinUvAuthToken) and rejects an up-only request. Without the EF_ALWAYS_UV
        // guard this same request succeeds, so the assert is mutation-proof.
        fs.put(EF_ALWAYS_UV, &[1]).unwrap();
        let mut out = [0u8; 256];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            make_credential(&mut ctx, &build_request(false), &mut out),
            Err(CtapError::PuatRequired)
        );
    }

    #[test]
    fn make_credential_bad_pin_auth_rejected() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let mut state = crate::FidoState::new();
        arm_pin(&mut fs, &mut state);
        // A wrong (all-zero) pinUvAuthParam fails the token check.
        let req = build_request_pin(&[0u8; 32], 2);
        let mut out = [0u8; 256];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            make_credential(&mut ctx, &req, &mut out),
            Err(CtapError::PinAuthInvalid)
        );
    }

    // ---- PQC algorithm selection ----

    // makeCredential with a multi-entry pubKeyCredParams; returns the attStmt alg.
    fn selected_alg(algs: &[i64]) -> Result<i64, CtapError> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str("example.com").unwrap();
            e.u8(3).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.u8(4).unwrap().array(algs.len() as u64).unwrap();
            for &alg in algs {
                e.map(2).unwrap();
                e.str("alg").unwrap().i64(alg).unwrap();
                e.str("type").unwrap().str("public-key").unwrap();
            }
            e.writer().position()
        };

        let mut fs = Fs::new(RamStorage::new(), &[]);
        let dev = Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        };
        let mut rng = SeqRng(1);
        ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 8192];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        let len = make_credential(&mut ctx, &buf[..n], &mut out)?;

        let mut d = Decoder::new(&out[..len]);
        let fields = d.map().unwrap().unwrap();
        for _ in 0..fields {
            if d.u8().unwrap() == 3 {
                d.map().unwrap();
                assert_eq!(d.str().unwrap(), "alg");
                return Ok(d.i64().unwrap());
            }
            d.skip().unwrap();
        }
        panic!("attStmt missing");
    }

    #[test]
    fn pqc_priority_selection() {
        use crate::consts::{ALG_MLDSA44, ALG_MLDSA65, ALG_MLDSA87};
        // PREFER_PQC: ML-DSA-44 wins even when listed after a classic alg —
        // and, trivially, when listed first.
        assert_eq!(selected_alg(&[ALG_ES256, ALG_MLDSA44]), Ok(ALG_MLDSA44));
        assert_eq!(selected_alg(&[ALG_MLDSA44, ALG_ES256]), Ok(ALG_MLDSA44));
        // No PQC offered → the first supported entry.
        assert_eq!(selected_alg(&[ALG_ES256]), Ok(ALG_ES256));
        assert_eq!(
            selected_alg(&[crate::consts::ALG_ES384, ALG_ES256]),
            Ok(crate::consts::ALG_ES384)
        );
        // -49/-50 are recognized ids without a backend: alone they are
        // unsupported; alongside a classic alg the classic one is selected.
        assert_eq!(
            selected_alg(&[ALG_MLDSA65]),
            Err(CtapError::UnsupportedAlgorithm)
        );
        assert_eq!(selected_alg(&[ALG_MLDSA87, ALG_ES256]), Ok(ALG_ES256));
    }

    // ---- Enterprise attestation ----

    // makeCredential request carrying enterpriseAttestation (field 0x0A).
    fn build_request_ea(ea: u64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str("example.com").unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(10).unwrap().u64(ea).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // Run makeCredential with enterprise attestation enabled/disabled (the
    // enable persists in flash — EF_EA_ENABLED — per CTAP 2.1).
    fn run_ea(req: &[u8], enable: bool) -> Result<(std::vec::Vec<u8>, Fs<RamStorage>), CtapError> {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        if enable {
            fs.put(EF_EA_ENABLED, &[1]).unwrap();
        }
        let len = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 1000,
            };
            make_credential(&mut ctx, req, &mut out)?
        };
        Ok((out[..len].to_vec(), fs))
    }

    #[test]
    fn enterprise_attestation_level2_full_attestation() {
        let req = build_request_ea(2);
        let (resp, mut fs) = run_ea(&req, true).unwrap();
        let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();

        let mut d = Decoder::new(&resp);
        // { 1: "packed", 2: authData, 3: attStmt, 4: ep } — 4 fields, no largeBlobKey.
        assert_eq!(d.map().unwrap().unwrap(), 4);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let ad = d.bytes().unwrap().to_vec();
        assert_eq!(d.u8().unwrap(), 3);
        // attStmt = { alg: -7, sig, x5c: [cert] } — full attestation.
        assert_eq!(d.map().unwrap().unwrap(), 3);
        assert_eq!(d.str().unwrap(), "alg");
        assert_eq!(d.i64().unwrap(), ALG_ES256);
        assert_eq!(d.str().unwrap(), "sig");
        let sig = d.bytes().unwrap().to_vec();
        assert_eq!(d.str().unwrap(), "x5c");
        assert_eq!(d.array().unwrap().unwrap(), 1);
        let cert = d.bytes().unwrap().to_vec();
        assert!(!cert.is_empty(), "x5c carries the device EE cert");
        // 4: ep = true.
        assert_eq!(d.u8().unwrap(), 4);
        assert!(d.bool().unwrap());

        // The attestation signature verifies under the DEVICE key (the seed
        // scalar), not the credential key.
        let device_key = P256Key::from_scalar(&seed).unwrap();
        let (x, y) = device_key.public_xy();
        let pt = EncodedPoint::from_affine_coordinates(x[..].into(), y[..].into(), false);
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        let mut signed = ad.clone();
        signed.extend_from_slice(&[0xCD; 32]);
        let s = Signature::from_der(&sig).unwrap();
        vk.verify(&signed, &s)
            .expect("enterprise attestation verifies under the device key");
    }

    #[test]
    fn enterprise_attestation_requires_enable() {
        // EA requested but not enabled via authenticatorConfig → INVALID_PARAMETER.
        assert_eq!(
            run_ea(&build_request_ea(2), false).map(|_| ()).unwrap_err(),
            CtapError::InvalidParameter
        );
    }

    #[test]
    fn enterprise_attestation_bad_level_rejected() {
        // Enabled, but an out-of-range level (3) → INVALID_OPTION.
        assert_eq!(
            run_ea(&build_request_ea(3), true).map(|_| ()).unwrap_err(),
            CtapError::InvalidOption
        );
    }

    #[test]
    fn enterprise_type1_non_listed_rp_is_basic_full_no_ep() {
        // A vendor-facilitated (type-1) request for an RP NOT on the enterprise list
        // returns a NORMAL, non-enterprise attestation: basic_full (x5c present) with
        // NO `ep` flag (CTAP2.1 §6.1.3, conformance Enterprise-Attestation F-6, which
        // asserts attStmt.x5c is an array). No org key here → the device's own cert.
        let (resp, _fs) = run_ea(&build_request_ea(1), true).unwrap();
        let mut d = Decoder::new(&resp);
        assert_eq!(
            d.map().unwrap().unwrap(),
            3,
            "no `ep` field for a non-enterprise attestation"
        );
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        d.bytes().unwrap(); // authData
        assert_eq!(d.u8().unwrap(), 3);
        // attStmt = { alg, sig, x5c } — basic_full (self would be 2 entries, no x5c).
        assert_eq!(
            d.map().unwrap().unwrap(),
            3,
            "basic_full attStmt carries x5c, not self"
        );
        assert_eq!(d.str().unwrap(), "alg");
        d.i64().unwrap();
        assert_eq!(d.str().unwrap(), "sig");
        d.bytes().unwrap();
        assert_eq!(d.str().unwrap(), "x5c");
        assert_eq!(d.array().unwrap().unwrap(), 1, "one cert");
        assert!(
            !d.bytes().unwrap().is_empty(),
            "x5c carries the device cert"
        );
    }

    #[test]
    fn enterprise_type1_non_eligible_ignores_org_key() {
        // Regression for conformance Enterprise-Attestation F-6: even with an org/EP
        // attestation key provisioned and EA enabled, a vendor-facilitated (type 1)
        // request for an RP NOT on the enterprise list must NOT use the org/EP cert.
        // It returns a normal basic_full attestation with the DEVICE's own cert and
        // no `ep` — never the enterprise batch cert.
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        crate::seed::store_att_key(&dev(), &mut fs, &[0x21u8; 32]).unwrap();
        let c1 = [0x30u8, 0x03, 1, 2, 3];
        let mut packed = [0u8; 64];
        let plen = crate::cert::att_chain_pack(&c1, &mut packed).unwrap();
        fs.put(EF_ATT_CHAIN, &packed[..plen]).unwrap();
        fs.put(EF_EA_ENABLED, &[1]).unwrap();

        let req = build_request_ea(1); // rp_id "example.com" — not enterprise-eligible
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let resp = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 1000,
            };
            let len = make_credential(&mut ctx, &req, &mut out).unwrap();
            out[..len].to_vec()
        };
        let mut d = Decoder::new(&resp);
        // No `ep` (3 top-level fields), basic_full attStmt (x5c), and the x5c is NOT
        // the provisioned org/EP cert (`c1`) — the device's own cert instead.
        assert_eq!(
            d.map().unwrap().unwrap(),
            3,
            "type-1 non-eligible must not add ep"
        );
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        d.bytes().unwrap();
        assert_eq!(d.u8().unwrap(), 3);
        assert_eq!(
            d.map().unwrap().unwrap(),
            3,
            "basic_full attStmt (x5c), not self"
        );
        assert_eq!(d.str().unwrap(), "alg");
        d.i64().unwrap();
        assert_eq!(d.str().unwrap(), "sig");
        d.bytes().unwrap();
        assert_eq!(d.str().unwrap(), "x5c");
        assert_eq!(d.array().unwrap().unwrap(), 1);
        assert_ne!(
            d.bytes().unwrap(),
            &c1,
            "non-eligible type-1 must NOT present the org/EP cert"
        );
    }

    #[test]
    fn vendor_ea_eligibility() {
        // No RP qualifies for vendor-facilitated EA by default; the FIDO conformance
        // test RPID qualifies only under the `ea-conformance-rpid` feature.
        assert!(!rp_eligible_for_vendor_ea("example.com"));
        assert_eq!(
            rp_eligible_for_vendor_ea("enterprisetest.certinfra.fidoalliance.org"),
            cfg!(feature = "ea-conformance-rpid")
        );
    }
}
