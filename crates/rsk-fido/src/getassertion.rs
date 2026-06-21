// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorGetAssertion`: resolve the credential from the allowList
//! (resident-id lookup or a non-resident box) or, if the allowList is empty, by
//! scanning resident credentials for the rp; sign authData ‖ clientDataHash
//! with the credential key. A verified `pinUvAuthParam` sets the `uv` flag
//! ([`enforce_pin`]); credProtect visibility is enforced in [`Best::consider`].
//! When resident discovery finds more than one credential, the sorted EF_CRED
//! slots are saved so [`get_next_assertion`] can return the rest one at a time.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::sha256;
use rsk_fs::Storage;

use crate::cbordec::{cbor, def_arr, def_map};
use crate::consts::{
    CRED_PROT_UV_OPTIONAL_WITH_LIST, CRED_PROT_UV_REQUIRED, CURVE_P256, EF_ALWAYS_UV, EF_CRED,
    EF_PIN, FLAG_ED, FLAG_UP, FLAG_UV, MAX_RESIDENT_CREDENTIALS,
};
use crate::credential::{
    CRED_RESIDENT_LEN, Credential, RECORD_PREFIX, credential_load, derive_large_blob_key,
    is_resident, slot_map,
};
use crate::ec::{CredKey, MAX_SIG_LEN};
use crate::error::{CtapError, CtapResult};
use crate::hmacsecret::{self, HmacSecretReq};
use crate::journal;
use crate::keyderiv::{KEY_HANDLE_LEN, fido_load_key, verify_key};
use crate::seed::{bump_sign_counter, get_sign_counter};
use crate::state::{MAX_ASSERTION_CREDS, PERM_GA};
use crate::{Ctx, Rng};
use rsk_crypto::pinproto::PinProto;

const MAX_ALLOW: usize = 16;
const MAX_CRED_ID: usize = 512;
const MAX_USER_ID: usize = 64;

struct Request<'a> {
    rp_id: &'a str,
    client_data_hash: &'a [u8],
    allow: [&'a [u8]; MAX_ALLOW],
    allow_len: usize,
    rk_option: bool,
    uv: bool,
    /// The `up` option (default true). `up:false` is the platform's silent
    /// pre-flight probe; honoring it (no touch, UP flag 0) is what keeps a
    /// WebAuthn login to a single touch. See the presence check in
    /// `get_assertion_inner` and the `strict-up` feature.
    up: bool,
    pin_uv_auth_param: Option<&'a [u8]>,
    pin_uv_auth_protocol: u64,
    ext_cred_blob: bool,
    ext_third_party_payment: bool,
    ext_large_blob_key: Option<bool>,
    hmac_secret: HmacSecretReq<'a>,
}

fn parse(data: &[u8]) -> Result<Request<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Request {
        rp_id: "",
        client_data_hash: &[],
        allow: [&[]; MAX_ALLOW],
        allow_len: 0,
        rk_option: false,
        uv: false,
        up: true,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: 0,
        ext_cred_blob: false,
        ext_third_party_payment: false,
        ext_large_blob_key: None,
        hmac_secret: HmacSecretReq::default(),
    };
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Keys 1..=2 (rpId, clientDataHash) are mandatory and ordered first.
        if expected <= 2 && key != expected {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.rp_id = cbor(d.str())?,
            2 => req.client_data_hash = cbor(d.bytes())?,
            3 => {
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
                    if req.allow_len < MAX_ALLOW {
                        req.allow[req.allow_len] = id;
                        req.allow_len += 1;
                    }
                }
            }
            5 => {
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.str())? {
                        "rk" => req.rk_option = cbor(d.bool())?,
                        "uv" => req.uv = cbor(d.bool())?,
                        "up" => req.up = cbor(d.bool())?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            4 => {
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    match cbor(d.str())? {
                        "credBlob" => req.ext_cred_blob = cbor(d.bool())?,
                        "thirdPartyPayment" => req.ext_third_party_payment = cbor(d.bool())?,
                        "largeBlobKey" => req.ext_large_blob_key = Some(cbor(d.bool())?),
                        "hmac-secret" => req.hmac_secret = hmacsecret::parse(&mut d)?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            6 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            7 => req.pin_uv_auth_protocol = cbor(d.u32())? as u64,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Max user name / displayName length echoed in an assertion (truncated to 64).
const MAX_USER_NAME: usize = 64;

/// The newest matching credential found so far.
struct Best {
    id: [u8; MAX_CRED_ID],
    len: usize,
    created: u64,
    resident: bool,
    /// For a resident credential, its STORED 42-byte resident id — the stable
    /// credentialId returned to the platform. Kept verbatim rather than
    /// re-derived from the box so it survives an updateUserInformation reseal.
    resident_id: [u8; CRED_RESIDENT_LEN],
    user: [u8; MAX_USER_ID],
    user_len: usize,
    // name / displayName, returned only on a multi-credential resident discovery.
    name: [u8; MAX_USER_NAME],
    name_len: usize,
    display: [u8; MAX_USER_NAME],
    display_len: usize,
    found: u32,
    any: bool,
}

impl Best {
    fn new() -> Self {
        Self {
            id: [0; MAX_CRED_ID],
            len: 0,
            created: 0,
            resident: false,
            resident_id: [0; CRED_RESIDENT_LEN],
            user: [0; MAX_USER_ID],
            user_len: 0,
            name: [0; MAX_USER_NAME],
            name_len: 0,
            display: [0; MAX_USER_NAME],
            display_len: 0,
            found: 0,
            any: false,
        }
    }

    /// Load `cand` and, if it decrypts for this rp and is visible, fold it in
    /// (keeping the newest). Returns the credential's creation time when it
    /// counted. A credProtect-hidden credential is skipped (returns `None`) so it
    /// neither signs nor counts toward `numberOfCredentials`.
    #[allow(clippy::too_many_arguments)]
    fn consider(
        &mut self,
        seed: &[u8; 32],
        rp_id_hash: &[u8; 32],
        cand: &[u8],
        resident_id: Option<&[u8]>,
        uv: bool,
        has_allow: bool,
        scratch: &mut [u8],
    ) -> Option<u64> {
        if cand.len() > self.id.len() {
            return None;
        }
        let c = credential_load(seed, cand, rp_id_hash, scratch)?;
        // credProtect visibility (§7): a UV-required
        // credential is invisible without UV; a UV-optional-with-list credential
        // is invisible during resident discovery (no allowList) without UV.
        let hidden = (c.ext.cred_protect == CRED_PROT_UV_REQUIRED && !uv)
            || (c.ext.cred_protect == CRED_PROT_UV_OPTIONAL_WITH_LIST && !has_allow && !uv);
        if hidden {
            return None;
        }
        self.found += 1;
        if !self.any || c.created >= self.created {
            self.any = true;
            self.created = c.created;
            // A resident candidate carries its stored 42-byte id; a non-resident
            // (allowList box) carries none.
            self.resident = resident_id.is_some();
            if let Some(rid) = resident_id {
                let m = rid.len().min(CRED_RESIDENT_LEN);
                self.resident_id[..m].copy_from_slice(&rid[..m]);
            }
            self.len = cand.len();
            self.id[..cand.len()].copy_from_slice(cand);
            self.user_len = c.user_id.len().min(MAX_USER_ID);
            self.user[..self.user_len].copy_from_slice(&c.user_id[..self.user_len]);
            self.name_len = c.user_name.len().min(MAX_USER_NAME);
            self.name[..self.name_len].copy_from_slice(&c.user_name.as_bytes()[..self.name_len]);
            self.display_len = c.user_display_name.len().min(MAX_USER_NAME);
            self.display[..self.display_len]
                .copy_from_slice(&c.user_display_name.as_bytes()[..self.display_len]);
        }
        Some(c.created)
    }
}

/// `authenticatorGetAssertion`: write the response CBOR into `out`, returning its
/// length.
pub fn get_assertion<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;
    if req.rp_id.is_empty() || req.client_data_hash.len() != 32 {
        return Err(CtapError::MissingParameter);
    }
    if req.uv {
        return Err(CtapError::InvalidOption);
    }
    if req.rk_option {
        return Err(CtapError::UnsupportedOption);
    }
    // largeBlobKey may only be requested as `true`.
    if req.ext_large_blob_key == Some(false) {
        return Err(CtapError::InvalidOption);
    }
    if req.hmac_secret.present
        && (req.hmac_secret.salt_enc.is_empty() || req.hmac_secret.salt_auth.is_empty())
    {
        return Err(CtapError::MissingParameter);
    }

    let rp_id_hash = sha256(req.rp_id.as_bytes());
    let uv = enforce_pin(ctx, &req, &rp_id_hash)?;

    let mut seed = ctx.load_keydev().ok_or(CtapError::Other)?;
    let result = get_assertion_inner(ctx, &req, &rp_id_hash, &seed, uv, out);
    seed.zeroize();
    if result.is_ok() {
        journal::append(ctx, journal::EV_GET_ASSERT, 0, &rp_id_hash[..8]);
    }
    result
}

/// CTAP2.1 PIN/UV enforcement (§6.1): verifies a `pinUvAuthParam` against the
/// token and reports whether to set the `uv` flag.
/// Unlike makeCredential, an absent param is allowed (the assertion just lacks UV).
fn enforce_pin<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
) -> Result<bool, CtapError> {
    match req.pin_uv_auth_param {
        // Zero-length probe (selection gesture): touch, then report PIN state.
        // With no button configured this confirms instantly.
        Some(&[]) => {
            ctx.require_presence()?;
            Err(if ctx.fs.has_data(EF_PIN) {
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
                || !ctx.state.user_verified()
                || ctx.state.paut.permissions & PERM_GA == 0
                || (ctx.state.paut.has_rp_id && ctx.state.paut.rp_id_hash != *rp_id_hash)
            {
                return Err(CtapError::PinAuthInvalid);
            }
            Ok(true)
        }
        // alwaysUv forces user verification (CTAP 2.1 alwaysUv); otherwise an
        // absent param simply yields an assertion without the uv flag.
        None if ctx.fs.has_data(EF_ALWAYS_UV) => Err(CtapError::PuatRequired),
        None => Ok(false),
    }
}

fn get_assertion_inner<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Request,
    rp_id_hash: &[u8; 32],
    seed: &[u8; 32],
    uv: bool,
    out: &mut [u8],
) -> CtapResult {
    // User-presence decision for the whole call: honor `up:false` (the platform's
    // silent pre-flight) unless the `strict-up` build forces a touch on every
    // assertion. getNextAssertion reuses it via `gna.up`.
    let want_up = cfg!(feature = "strict-up") || req.up;
    let mut best = Best::new();
    let mut scratch = [0u8; 1024];
    let mut rec = [0u8; 1024];

    // One storage pass for the EF_CRED occupancy; both arms only `read` live slots.
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);

    if req.allow_len > 0 {
        for &id in &req.allow[..req.allow_len] {
            if is_resident(id) {
                // Look up the full box by its 42-byte resident id.
                for i in 0..MAX_RESIDENT_CREDENTIALS {
                    if !occupied[i as usize] {
                        continue;
                    }
                    let Some(n) = ctx.fs.read(EF_CRED + i, &mut rec) else {
                        continue;
                    };
                    let n = n.min(rec.len());
                    if n >= RECORD_PREFIX
                        && rec[..32] == *rp_id_hash
                        && id.len() == CRED_RESIDENT_LEN
                        && rec[32..RECORD_PREFIX] == *id
                    {
                        best.consider(
                            seed,
                            rp_id_hash,
                            &rec[RECORD_PREFIX..n],
                            Some(&rec[32..RECORD_PREFIX]),
                            uv,
                            true,
                            &mut scratch,
                        );
                        break;
                    }
                }
            } else {
                best.consider(seed, rp_id_hash, id, None, uv, true, &mut scratch);
            }
        }
    } else {
        // Resident discovery: every stored credential for this rp. Collect the
        // matching EF_CRED slots so getNextAssertion can walk them.
        let mut cands: [(u16, u64); MAX_ASSERTION_CREDS] = [(0, 0); MAX_ASSERTION_CREDS];
        let mut ncand = 0usize;
        for i in 0..MAX_RESIDENT_CREDENTIALS {
            if !occupied[i as usize] {
                continue;
            }
            let Some(n) = ctx.fs.read(EF_CRED + i, &mut rec) else {
                continue;
            };
            let n = n.min(rec.len());
            if n >= RECORD_PREFIX
                && rec[..32] == *rp_id_hash
                && let Some(created) = best.consider(
                    seed,
                    rp_id_hash,
                    &rec[RECORD_PREFIX..n],
                    Some(&rec[32..RECORD_PREFIX]),
                    uv,
                    false,
                    &mut scratch,
                )
                && ncand < MAX_ASSERTION_CREDS
            {
                cands[ncand] = (i, created);
                ncand += 1;
            }
        }
        // Arm getNextAssertion when more than one credential matched (newest first).
        if ncand > 1 {
            cands[..ncand].sort_unstable_by_key(|c| core::cmp::Reverse(c.1));
            let gna = &mut ctx.state.gna;
            gna.active = true;
            gna.rp_id_hash = *rp_id_hash;
            gna.client_data_hash.copy_from_slice(req.client_data_hash);
            gna.uv = uv;
            gna.up = want_up;
            gna.total = ncand as u8;
            gna.counter = 1;
            gna.started_ms = ctx.now_ms;
            for (k, &(slot, _)) in cands[..ncand].iter().enumerate() {
                gna.slots[k] = slot;
            }
            // Carry the request's extension inputs so getNextAssertion
            // re-evaluates them (hmac-secret included) per credential.
            gna.hmac_present = req.hmac_secret.present;
            if req.hmac_secret.present {
                gna.hmac_proto = req.hmac_secret.proto;
                gna.hmac_peer_x = req.hmac_secret.peer_x;
                gna.hmac_peer_y = req.hmac_secret.peer_y;
                let se = req.hmac_secret.salt_enc.len().min(gna.hmac_salt_enc.len());
                gna.hmac_salt_enc[..se].copy_from_slice(&req.hmac_secret.salt_enc[..se]);
                gna.hmac_salt_enc_len = se as u8;
                let sa = req
                    .hmac_secret
                    .salt_auth
                    .len()
                    .min(gna.hmac_salt_auth.len());
                gna.hmac_salt_auth[..sa].copy_from_slice(&req.hmac_secret.salt_auth[..sa]);
                gna.hmac_salt_auth_len = sa as u8;
            }
            gna.ext_cred_blob = req.ext_cred_blob;
            gna.ext_third_party_payment = req.ext_third_party_payment;
        }
    }

    if !best.any {
        return Err(CtapError::NoCredentials);
    }

    // Re-load the selected credential for its stored extension data + curve.
    let mut sel_scratch = [0u8; 1024];
    let sel = credential_load(seed, &best.id[..best.len], rp_id_hash, &mut sel_scratch);
    let sel_large_blob = sel.as_ref().map(|c| c.ext.large_blob_key).unwrap_or(false);
    let curve = sel.as_ref().map_or(CURVE_P256 as i64, |c| c.curve);

    // hmac-secret output (needs the clientPIN ephemeral key + the RNG for the IV).
    let mut hs = [0u8; 80];
    let hs_len = if req.hmac_secret.present {
        let ephemeral = *ctx.state.ephemeral_scalar();
        hmacsecret::eval(
            &req.hmac_secret,
            &ephemeral,
            seed,
            &best.id[..best.len],
            uv,
            ctx.rng,
            &mut hs,
        )?
    } else {
        0
    };

    // authData extension output (credBlob / hmac-secret / thirdPartyPayment).
    let mut ext = [0u8; 320];
    let ext_len = encode_ga_extensions(
        req.ext_cred_blob,
        req.ext_third_party_payment,
        sel.as_ref(),
        &hs[..hs_len],
        &mut ext,
    )?;
    let ed = if ext_len > 0 { FLAG_ED } else { 0 };

    // largeBlobKey response field (0x07) — only when the request and the stored
    // credential both opted in.
    let large_blob_key = if req.ext_large_blob_key == Some(true) && sel_large_blob {
        Some(derive_large_blob_key(seed, &best.id[..best.len]))
    } else {
        None
    };

    // A U2F/CTAP1 key handle (loaded via the credential_load fallback) signs with
    // its path-as-is scalar (keyderiv::verify_key); fido_load_key rewrites the
    // first path entry for CTAP2 creds.
    let key = if sel.as_ref().is_some_and(|c| c.u2f) {
        let kh = <&[u8; KEY_HANDLE_LEN]>::try_from(&best.id[..best.len])
            .map_err(|_| CtapError::Other)?;
        let mut scalar = verify_key(seed, rp_id_hash, kh).ok_or(CtapError::Other)?;
        let key = CredKey::from_raw(CURVE_P256 as i64, &scalar).ok_or(CtapError::Other)?;
        scalar.zeroize();
        key
    } else {
        let mut raw = fido_load_key(seed, &best.id[..best.len]).ok_or(CtapError::Other)?;
        let key = CredKey::from_raw(curve, &raw).ok_or(CtapError::Other)?;
        raw.zeroize();
        key
    };

    // §6.2 user presence. `up` defaults to true; the platform sets up:false for
    // its silent pre-flight (credential discovery), which a spec-compliant key
    // answers with NO touch and the UP flag clear — that is what keeps a WebAuthn
    // login to one touch. The `strict-up` build opts out: it polls the button on
    // every assertion, so an allowList login asks for two touches (one for the
    // pre-flight probe, one for the real assertion). No button configured → the
    // poll confirms instantly. A CTAPHID_CANCEL during the wait surfaces as
    // KEEPALIVE_CANCEL.
    if want_up {
        ctx.require_presence()?;
    }

    // authData = rpIdHash | flags([UP][,UV][,ED]) | counter [| ext] — no attestedCredentialData.
    let ctr = get_sign_counter(ctx.fs);
    let mut ad = [0u8; 37 + 320 + 32];
    ad[..32].copy_from_slice(rp_id_hash);
    let up_flag = if want_up { FLAG_UP } else { 0 };
    ad[32] = up_flag | ed | if uv { FLAG_UV } else { 0 };
    ad[33..37].copy_from_slice(&ctr.to_be_bytes());
    ad[37..37 + ext_len].copy_from_slice(&ext[..ext_len]);
    let ad_len = 37 + ext_len;
    ad[ad_len..ad_len + 32].copy_from_slice(req.client_data_hash);
    let mut sig = [0u8; MAX_SIG_LEN];
    let sig_len = key.sign(&ad[..ad_len + 32], ctx.rng, &mut sig);

    // Response: { 1: {id,type}, 2: authData, 3: sig [, 4: user] [, 5: count] [, 7: largeBlobKey] }.
    // A resident credential's id is its STORED 42-byte resident id (stable across
    // updateUserInformation); a non-resident's is the box itself.
    let cred_id: &[u8] = if best.resident {
        &best.resident_id
    } else {
        &best.id[..best.len]
    };
    // numberOfCredentials and the full user identity are a resident-discovery
    // feature: with an allowList present, CTAP2.1 returns exactly one assertion
    // and no count. `multi` also gates name/displayName.
    let multi = best.found > 1 && req.allow_len == 0;
    let mut fields = 3u64;
    if best.resident {
        fields += 1; // user
    }
    if multi {
        fields += 1; // numberOfCredentials
    }
    if large_blob_key.is_some() {
        fields += 1; // largeBlobKey
    }

    let mut enc = Encoder::new(Cursor::new(&mut *out));
    enc.map(fields)
        .and_then(|e| e.u8(1)?.map(2))
        .and_then(|e| e.str("id")?.bytes(cred_id))
        .and_then(|e| e.str("type")?.str("public-key"))
        .and_then(|e| e.u8(2)?.bytes(&ad[..ad_len]))
        .and_then(|e| e.u8(3)?.bytes(&sig[..sig_len]))
        .map_err(|_| CtapError::Other)?;
    if best.resident {
        // name / displayName are user-identifiable info: returned only on a
        // multi-credential discovery AND only when the user is verified (§6.2.2
        // privacy rule / conformance Discoverable P-2). Without uv → id only.
        let with_name = multi && uv && best.name_len > 0;
        let with_display = multi && uv && best.display_len > 0;
        let entries = 1 + u64::from(with_name) + u64::from(with_display);
        enc.u8(4)
            .and_then(|e| e.map(entries))
            .and_then(|e| e.str("id")?.bytes(&best.user[..best.user_len]))
            .map_err(|_| CtapError::Other)?;
        if with_name {
            let s = core::str::from_utf8(&best.name[..best.name_len]).unwrap_or("");
            enc.str("name")
                .and_then(|e| e.str(s))
                .map_err(|_| CtapError::Other)?;
        }
        if with_display {
            let s = core::str::from_utf8(&best.display[..best.display_len]).unwrap_or("");
            enc.str("displayName")
                .and_then(|e| e.str(s))
                .map_err(|_| CtapError::Other)?;
        }
    }
    if multi {
        enc.u8(5)
            .and_then(|e| e.u32(best.found))
            .map_err(|_| CtapError::Other)?;
    }
    if let Some(lbk) = large_blob_key {
        enc.u8(7)
            .and_then(|e| e.bytes(&lbk))
            .map_err(|_| CtapError::Other)?;
    }
    let resp_len = enc.writer().position();

    bump_sign_counter(ctx.fs).map_err(|_| CtapError::Other)?;
    Ok(resp_len)
}

/// Build the getAssertion authData extension map (credBlob bytes / hmac-secret /
/// thirdPartyPayment) into `out`; returns its length (0 if none apply). `hmac` is
/// the already-evaluated hmac-secret output (empty when not requested). Echoes the
/// selected credential's stored extension data.
fn encode_ga_extensions(
    get_cred_blob: bool,
    third_party_payment: bool,
    sel: Option<&Credential>,
    hmac: &[u8],
    out: &mut [u8],
) -> Result<usize, CtapError> {
    let l = u64::from(get_cred_blob) + u64::from(!hmac.is_empty()) + u64::from(third_party_payment);
    if l == 0 {
        return Ok(0);
    }
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(l).map_err(|_| CtapError::Other)?;
    if get_cred_blob {
        // Echo the stored credBlob (empty byte string if the credential has none).
        let blob = sel.map(|c| c.ext.cred_blob).unwrap_or(&[]);
        enc.str("credBlob")
            .and_then(|e| e.bytes(blob))
            .map_err(|_| CtapError::Other)?;
    }
    if !hmac.is_empty() {
        enc.str("hmac-secret")
            .and_then(|e| e.bytes(hmac))
            .map_err(|_| CtapError::Other)?;
    }
    if third_party_payment {
        let tpp = sel.map(|c| c.ext.third_party_payment).unwrap_or(false);
        enc.str("thirdPartyPayment")
            .and_then(|e| e.bool(tpp))
            .map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// `authenticatorGetNextAssertion`: return the next credential from a
/// multi-credential `getAssertion`, walking the saved EF_CRED slots.
/// `NotAllowed` if there is no carry-over, it is exhausted, or the 30 s window
/// elapsed.
pub fn get_next_assertion<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    if !ctx.state.gna.active || ctx.state.gna.counter >= ctx.state.gna.total {
        return Err(CtapError::NotAllowed);
    }
    if ctx.now_ms.saturating_sub(ctx.state.gna.started_ms) > 30_000 {
        ctx.state.gna.reset();
        return Err(CtapError::NotAllowed);
    }
    let idx = ctx.state.gna.counter as usize;
    let slot = ctx.state.gna.slots[idx];
    let rp_id_hash = ctx.state.gna.rp_id_hash;
    let client_data_hash = ctx.state.gna.client_data_hash;
    let uv = ctx.state.gna.uv;
    let up = ctx.state.gna.up;

    // Re-read the credential record; the resident id is its stored 42-byte prefix.
    let mut rec = [0u8; 1024];
    let n = match ctx.fs.read(EF_CRED + slot, &mut rec) {
        Some(n) if n.min(rec.len()) >= RECORD_PREFIX => n.min(rec.len()),
        _ => {
            ctx.state.gna.reset();
            return Err(CtapError::NoCredentials);
        }
    };
    if rec[..32] != rp_id_hash {
        ctx.state.gna.reset();
        return Err(CtapError::NoCredentials);
    }
    let mut resident_id = [0u8; CRED_RESIDENT_LEN];
    resident_id.copy_from_slice(&rec[32..RECORD_PREFIX]);

    let mut seed = ctx.load_keydev().ok_or(CtapError::Other)?;
    let result = next_assertion_response(
        ctx,
        &rec[RECORD_PREFIX..n],
        &resident_id,
        &rp_id_hash,
        &client_data_hash,
        uv,
        up,
        &seed,
        out,
    );
    seed.zeroize();
    let resp_len = result?;

    ctx.state.gna.counter += 1;
    if ctx.state.gna.counter >= ctx.state.gna.total {
        ctx.state.gna.reset();
    }
    Ok(resp_len)
}

#[allow(clippy::too_many_arguments)]
fn next_assertion_response<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    cred_box: &[u8],
    resident_id: &[u8],
    rp_id_hash: &[u8; 32],
    client_data_hash: &[u8; 32],
    uv: bool,
    up: bool,
    seed: &[u8; 32],
    out: &mut [u8],
) -> CtapResult {
    let mut scratch = [0u8; 1024];
    let cred = credential_load(seed, cred_box, rp_id_hash, &mut scratch)
        .ok_or(CtapError::NoCredentials)?;
    let curve = cred.curve;

    // getNextAssertion only ever walks a multi-credential resident discovery;
    // name / displayName are user-identifiable and returned only when the user
    // is verified (§6.3 privacy rule), otherwise id only.
    let mut user = [0u8; MAX_USER_ID];
    let user_len = cred.user_id.len().min(MAX_USER_ID);
    user[..user_len].copy_from_slice(&cred.user_id[..user_len]);
    let mut name = [0u8; MAX_USER_NAME];
    let name_len = cred.user_name.len().min(MAX_USER_NAME);
    name[..name_len].copy_from_slice(&cred.user_name.as_bytes()[..name_len]);
    let mut display = [0u8; MAX_USER_NAME];
    let display_len = cred.user_display_name.len().min(MAX_USER_NAME);
    display[..display_len].copy_from_slice(&cred.user_display_name.as_bytes()[..display_len]);

    // Re-evaluate hmac-secret for this credential from the carried request.
    let mut hs = [0u8; 80];
    let hs_len = if ctx.state.gna.hmac_present {
        let g = &ctx.state.gna;
        let (se, sa) = (g.hmac_salt_enc_len as usize, g.hmac_salt_auth_len as usize);
        let (mut salt_enc, mut salt_auth) = ([0u8; 80], [0u8; 48]);
        salt_enc[..se].copy_from_slice(&g.hmac_salt_enc[..se]);
        salt_auth[..sa].copy_from_slice(&g.hmac_salt_auth[..sa]);
        let req = HmacSecretReq {
            present: true,
            proto: g.hmac_proto,
            peer_x: g.hmac_peer_x,
            peer_y: g.hmac_peer_y,
            salt_enc: &salt_enc[..se],
            salt_auth: &salt_auth[..sa],
        };
        let ephemeral = *ctx.state.ephemeral_scalar();
        hmacsecret::eval(&req, &ephemeral, seed, cred_box, uv, ctx.rng, &mut hs)?
    } else {
        0
    };

    // authData extension output (credBlob / hmac-secret / thirdPartyPayment).
    let mut ext = [0u8; 320];
    let ext_len = encode_ga_extensions(
        ctx.state.gna.ext_cred_blob,
        ctx.state.gna.ext_third_party_payment,
        Some(&cred),
        &hs[..hs_len],
        &mut ext,
    )?;
    let ed = if ext_len > 0 { FLAG_ED } else { 0 };

    let mut raw = fido_load_key(seed, cred_box).ok_or(CtapError::Other)?;
    let key = CredKey::from_raw(curve, &raw).ok_or(CtapError::Other)?;
    raw.zeroize();

    let ctr = get_sign_counter(ctx.fs);
    let mut ad = [0u8; 37 + 320];
    ad[..32].copy_from_slice(rp_id_hash);
    let up_flag = if up { FLAG_UP } else { 0 };
    ad[32] = up_flag | ed | if uv { FLAG_UV } else { 0 };
    ad[33..37].copy_from_slice(&ctr.to_be_bytes());
    ad[37..37 + ext_len].copy_from_slice(&ext[..ext_len]);
    let ad_len = 37 + ext_len;
    let mut signed = [0u8; 37 + 320 + 32];
    signed[..ad_len].copy_from_slice(&ad[..ad_len]);
    signed[ad_len..ad_len + 32].copy_from_slice(client_data_hash);
    let mut sig = [0u8; MAX_SIG_LEN];
    let sig_len = key.sign(&signed[..ad_len + 32], ctx.rng, &mut sig);

    // Response: { 1: {id,type}, 2: authData, 3: sig, 4: {id[,name,displayName]} } (no count).
    let with_name = uv && name_len > 0;
    let with_display = uv && display_len > 0;
    let entries = 1 + u64::from(with_name) + u64::from(with_display);
    let mut enc = Encoder::new(Cursor::new(&mut *out));
    enc.map(4)
        .and_then(|e| e.u8(1)?.map(2))
        .and_then(|e| e.str("id")?.bytes(resident_id))
        .and_then(|e| e.str("type")?.str("public-key"))
        .and_then(|e| e.u8(2)?.bytes(&ad[..ad_len]))
        .and_then(|e| e.u8(3)?.bytes(&sig[..sig_len]))
        .and_then(|e| e.u8(4)?.map(entries))
        .and_then(|e| e.str("id")?.bytes(&user[..user_len]))
        .map_err(|_| CtapError::Other)?;
    if with_name {
        let s = core::str::from_utf8(&name[..name_len]).unwrap_or("");
        enc.str("name")
            .and_then(|e| e.str(s))
            .map_err(|_| CtapError::Other)?;
    }
    if with_display {
        let s = core::str::from_utf8(&display[..display_len]).unwrap_or("");
        enc.str("displayName")
            .and_then(|e| e.str(s))
            .map_err(|_| CtapError::Other)?;
    }
    let resp_len = enc.writer().position();
    bump_sign_counter(ctx.fs).map_err(|_| CtapError::Other)?;
    Ok(resp_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::ALG_ES256;
    use crate::makecredential::make_credential;
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

    const CDH: [u8; 32] = [0xCD; 32];

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn mc_request(rk: bool) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(if rk { 5 } else { 4 }).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
            e.str("name").unwrap().str("bob").unwrap();
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

    // Pull (credId, pubkey x, y) out of a makeCredential response's authData.
    fn parse_mc(resp: &[u8]) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32]) {
        let mut d = Decoder::new(resp);
        // 3 base fields; a largeBlobKey credential adds field 0x05 (read 1 & 2 only).
        assert!(d.map().unwrap().unwrap() >= 3);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let ad = d.bytes().unwrap();
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cred_id = ad[55..55 + cred_len].to_vec();
        let mut cd = Decoder::new(&ad[55 + cred_len..]);
        assert_eq!(cd.map().unwrap().unwrap(), 5);
        cd.u8().unwrap(); // 1
        cd.u8().unwrap(); // kty 2
        cd.u8().unwrap(); // 3
        cd.i64().unwrap(); // alg
        cd.i8().unwrap(); // -1
        cd.u8().unwrap(); // crv 1
        cd.i8().unwrap(); // -2
        let mut x = [0u8; 32];
        x.copy_from_slice(cd.bytes().unwrap());
        cd.i8().unwrap(); // -3
        let mut y = [0u8; 32];
        y.copy_from_slice(cd.bytes().unwrap());
        (cred_id, x, y)
    }

    fn verify_assertion(resp: &[u8], x: &[u8; 32], y: &[u8; 32]) -> usize {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap() as usize;
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.str().unwrap(), "id");
        let _cred_id = d.bytes().unwrap().to_vec();
        assert_eq!(d.str().unwrap(), "type");
        assert_eq!(d.str().unwrap(), "public-key");
        assert_eq!(d.u8().unwrap(), 2);
        let auth_data = d.bytes().unwrap().to_vec();
        assert_eq!(d.u8().unwrap(), 3);
        let sig = d.bytes().unwrap().to_vec();

        // Assertion authData has UP set and NO attested-credential-data (AT) bit
        // (it is 37 bytes plus any extension output).
        assert!(auth_data.len() >= 37);
        assert_eq!(auth_data[32] & 0x01, 0x01); // UP
        assert_eq!(auth_data[32] & 0x40, 0x00); // no AT

        let pt = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        let mut signed = auth_data;
        signed.extend_from_slice(&CDH);
        let s = Signature::from_der(&sig).unwrap();
        vk.verify(&signed, &s)
            .expect("assertion signature verifies under the credential key");
        fields
    }

    /// Arm a PIN + live token (GA permission) over an already-seeded device.
    /// The seed stays plain — PIN ops never wrap it.
    fn arm_pin(fs: &mut Fs<RamStorage>, state: &mut crate::FidoState) -> [u8; 32] {
        let mut pin_file = [0u8; 35];
        pin_file[0] = 8;
        pin_file[1] = 4;
        pin_file[2] = 1;
        fs.put(EF_PIN, &pin_file).unwrap();
        let token = [0x99u8; 32];
        state.paut.token = token;
        state.paut.permissions = PERM_GA;
        state.begin_using_token(false);
        token
    }

    fn ga_request_pin(allow: &[u8], param: &[u8], proto: u64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(allow).unwrap();
            e.u8(6).unwrap().bytes(param).unwrap();
            e.u8(7).unwrap().u64(proto).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    #[test]
    fn assertion_with_pin_sets_uv_flag() {
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();
        let mut out = [0u8; 1024];
        // Register without a PIN.
        let mc = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
            out[..n].to_vec()
        };
        let (cred_id, x, y) = parse_mc(&mc);

        // Arm a PIN + token, then log in with a valid pinUvAuthParam.
        let token = arm_pin(&mut fs, &mut state);
        let mut param = [0u8; 32];
        let plen =
            rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
        let req = ga_request_pin(&cred_id, &param[..plen], 2);
        let mut out2 = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &req, &mut out2).unwrap()
        };
        verify_assertion(&out2[..n], &x, &y);
        // authData must carry the UV flag now.
        let mut d = Decoder::new(&out2[..n]);
        d.map().unwrap();
        d.u8().unwrap();
        d.skip().unwrap(); // 1: credential
        d.u8().unwrap(); // 2
        let ad = d.bytes().unwrap();
        assert_eq!(ad[32] & FLAG_UV, FLAG_UV, "UV flag must be set");
    }

    fn ga_request(allow: Option<&[u8]>) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(if allow.is_some() { 3 } else { 2 }).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            if let Some(id) = allow {
                e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
                e.str("type").unwrap().str("public-key").unwrap();
                e.str("id").unwrap().bytes(id).unwrap();
            }
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn setup() -> (Fs<RamStorage>, SeqRng) {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        (fs, rng)
    }

    /// A presence source that always declines — `require_presence` then returns
    /// `OperationDenied`, so it proves whether a touch was actually polled.
    struct Decline;
    impl crate::UserPresence for Decline {
        fn request(&mut self) -> crate::Presence {
            crate::Presence::Declined
        }
    }

    /// A getAssertion for `allow` carrying the options map `{ "up": up }`.
    fn ga_request_up(allow: &[u8], up: bool) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(allow).unwrap();
            e.u8(5)
                .unwrap()
                .map(1)
                .unwrap()
                .str("up")
                .unwrap()
                .bool(up)
                .unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn register_non_resident(fs: &mut Fs<RamStorage>, rng: &mut SeqRng) -> std::vec::Vec<u8> {
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
        let (cred_id, _x, _y) = parse_mc(&out[..n]);
        cred_id
    }

    // Default build: the platform's silent pre-flight (up:false) must return an
    // assertion WITHOUT polling the button and with the UP flag clear — that is
    // what keeps a WebAuthn login to a single touch. Mutation-proof: a Decline
    // presence would deny the operation if the touch were polled, and the same
    // credential with up:true IS denied.
    #[cfg(not(feature = "strict-up"))]
    #[test]
    fn up_false_preflight_is_silent_and_clears_up_flag() {
        let (mut fs, mut rng) = setup();
        let cred_id = register_non_resident(&mut fs, &mut rng);

        let mut out = [0u8; 1024];
        let n = {
            let mut state = crate::FidoState::new();
            let mut presence = Decline;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out)
                .expect("up:false returns an assertion without a touch")
        };
        let ad = assertion_auth_data(&out[..n]);
        assert_eq!(ad[32] & 0x01, 0x00, "up:false → UP flag clear");

        // up:true with the same declined button IS refused — the touch is normally
        // required, so this guards against the gate becoming a no-op.
        let mut out2 = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request_up(&cred_id, true), &mut out2),
            Err(CtapError::OperationDenied),
            "up:true with a declined touch must be denied",
        );
    }

    // strict-up build: even up:false polls the button, so a declined touch denies
    // the assertion (the opt-in two-touch behavior).
    #[cfg(feature = "strict-up")]
    #[test]
    fn strict_up_polls_button_even_on_up_false() {
        let (mut fs, mut rng) = setup();
        let cred_id = register_non_resident(&mut fs, &mut rng);
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out),
            Err(CtapError::OperationDenied),
            "strict-up: up:false still requires a touch",
        );
    }

    #[test]
    fn register_then_login_non_resident() {
        let (mut fs, mut rng) = setup();
        let mut out = [0u8; 1024];

        let mc = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
            out[..n].to_vec()
        };
        let (cred_id, x, y) = parse_mc(&mc);
        assert!(cred_id.len() > 42, "non-resident returns the full box");

        let mut out2 = [0u8; 1024];
        let ga = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            let n = get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut out2).unwrap();
            out2[..n].to_vec()
        };
        // No user field for a non-resident credential.
        assert_eq!(verify_assertion(&ga, &x, &y), 3);
    }

    #[test]
    fn always_uv_requires_user_verification() {
        let (mut fs, mut rng) = setup();
        // alwaysUv on → getAssertion demands UV; an up-only request is refused with
        // PUAT_REQUIRED before any credential lookup. Without the EF_ALWAYS_UV guard
        // the same request proceeds and returns NO_CREDENTIALS, so this is
        // mutation-proof for the guard.
        fs.put(EF_ALWAYS_UV, &[1]).unwrap();
        let mut out = [0u8; 256];
        let mut state = crate::FidoState::new();
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
            get_assertion(&mut ctx, &ga_request(None), &mut out),
            Err(CtapError::PuatRequired)
        );
    }

    #[test]
    fn u2f_handle_usable_via_ctap2_allowlist() {
        use crate::keyderiv::derive_new;
        use rsk_crypto::pinproto::public_xy;
        // A U2F/CTAP1 key handle bound to this rp must be usable in a CTAP2
        // getAssertion allowList.
        let (mut fs, mut rng) = setup();
        let rp_id_hash = sha256(b"example.com");
        let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
        // cmd_register would derive this handle + scalar from the device seed.
        let (kh, scalar) = derive_new(&seed, &rp_id_hash, &mut rng);
        let (x, y) = public_xy(&scalar).unwrap();

        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &ga_request(Some(&kh)), &mut out).unwrap();
        let ga = out[..n].to_vec();
        // The handle round-trips as the credential id and the assertion signature
        // verifies under the U2F-registered public key.
        assert_eq!(cred_id_of(&ga), kh.to_vec());
        assert_eq!(verify_assertion(&ga, &x, &y), 3);
    }

    #[test]
    fn register_then_login_resident_discovery() {
        let (mut fs, mut rng) = setup();
        let mut out = [0u8; 1024];

        let mc = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let n = make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
            out[..n].to_vec()
        };
        let (_resident_id, x, y) = parse_mc(&mc);

        // No allowList → the device discovers the resident credential.
        let mut out2 = [0u8; 1024];
        let ga = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            let n = get_assertion(&mut ctx, &ga_request(None), &mut out2).unwrap();
            out2[..n].to_vec()
        };
        // Resident: includes the user field (id 9,8,7,6).
        assert_eq!(verify_assertion(&ga, &x, &y), 4);
        let mut d = Decoder::new(&ga);
        d.map().unwrap();
        for _ in 0..3 {
            // skip credential, authData, sig (keys 1,2,3)
            d.u8().unwrap();
            d.skip().unwrap();
        }
        assert_eq!(d.u8().unwrap(), 4);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "id");
        assert_eq!(d.bytes().unwrap(), &[9, 8, 7, 6]);
    }

    #[test]
    fn discovery_returns_stored_resident_id() {
        // get_assertion (resident discovery) must echo the credential's STORED
        // 42-byte resident id — not one re-derived from the box — so the id stays
        // stable after an updateUserInformation reseal (CTAP2.1 §6.8.5). Proven by
        // overwriting the stored prefix: a re-derived id would not equal it.
        let (mut fs, mut rng) = setup();
        let mut out = [0u8; 1024];
        {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
        }

        // Overwrite the stored resident-id prefix with a sentinel; the box is left
        // intact, so a re-derived id would differ from this.
        let mut rec = [0u8; 1024];
        let n = fs.read(EF_CRED, &mut rec).unwrap();
        let mut sentinel = [0u8; CRED_RESIDENT_LEN];
        for (i, b) in sentinel.iter_mut().enumerate() {
            *b = 0xC0 ^ i as u8;
        }
        rec[32..RECORD_PREFIX].copy_from_slice(&sentinel);
        fs.put(EF_CRED, &rec[..n]).unwrap();

        // Discovery (no allowList) returns the stored sentinel as the credentialId.
        let mut out2 = [0u8; 1024];
        let ga = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            let m = get_assertion(&mut ctx, &ga_request(None), &mut out2).unwrap();
            out2[..m].to_vec()
        };
        assert_eq!(cred_id_of(&ga), sentinel.to_vec());
    }

    #[test]
    fn login_counter_increments() {
        let (mut fs, mut rng) = setup();
        let mut out = [0u8; 1024];
        let mc = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
            out[..n].to_vec()
        };
        let (cred_id, _x, _y) = parse_mc(&mc);

        let counter = |fs: &mut Fs<RamStorage>| crate::seed::get_sign_counter(fs);
        let c0 = counter(&mut fs);
        for _ in 0..2 {
            let mut o = [0u8; 1024];
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 30,
            };
            get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut o).unwrap();
        }
        assert_eq!(counter(&mut fs), c0 + 2);
    }

    #[test]
    fn no_matching_credentials() {
        let (mut fs, mut rng) = setup();
        let mut out = [0u8; 256];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        // No credentials registered, no allowList → NoCredentials.
        assert_eq!(
            get_assertion(&mut ctx, &ga_request(None), &mut out),
            Err(CtapError::NoCredentials)
        );
    }

    // A resident makeCredential request with a custom user id.
    fn mc_request_user(uid: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(uid).unwrap();
            e.str("name").unwrap().str("user").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
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

    // Pull (user id, numberOfCredentials) out of an assertion response.
    fn user_and_count(resp: &[u8]) -> (std::vec::Vec<u8>, Option<u32>) {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        let mut user = std::vec::Vec::new();
        let mut count = None;
        for _ in 0..fields {
            match d.u8().unwrap() {
                4 => {
                    // The user map is {id [, name, displayName]} on a multi-credential
                    // discovery; read every entry, keeping the id.
                    let entries = d.map().unwrap().unwrap();
                    for _ in 0..entries {
                        match d.str().unwrap() {
                            "id" => user = d.bytes().unwrap().to_vec(),
                            _ => {
                                d.skip().unwrap();
                            }
                        }
                    }
                }
                5 => count = Some(d.u32().unwrap()),
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        (user, count)
    }

    // The credential id from response key 1 ({id, type}).
    fn cred_id_of(resp: &[u8]) -> std::vec::Vec<u8> {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        let mut id = std::vec::Vec::new();
        for _ in 0..fields {
            match d.u8().unwrap() {
                1 => {
                    let m = d.map().unwrap().unwrap();
                    for _ in 0..m {
                        match d.str().unwrap() {
                            "id" => id = d.bytes().unwrap().to_vec(),
                            _ => {
                                d.skip().unwrap();
                            }
                        }
                    }
                }
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        id
    }

    // The user "name" (empty if absent) from an assertion response's user map.
    fn user_name_of(resp: &[u8]) -> std::string::String {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        let mut name = std::string::String::new();
        for _ in 0..fields {
            match d.u8().unwrap() {
                4 => {
                    let m = d.map().unwrap().unwrap();
                    for _ in 0..m {
                        match d.str().unwrap() {
                            "name" => name = d.str().unwrap().into(),
                            _ => {
                                d.skip().unwrap();
                            }
                        }
                    }
                }
                _ => {
                    d.skip().unwrap();
                }
            }
        }
        name
    }

    // A getAssertion request with a two-item allowList.
    fn ga_request_allow2(id1: &[u8], id2: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(3).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(3).unwrap().array(2).unwrap();
            for id in [id1, id2] {
                e.map(2).unwrap();
                e.str("type").unwrap().str("public-key").unwrap();
                e.str("id").unwrap().bytes(id).unwrap();
            }
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    #[test]
    fn allowlist_returns_single_assertion_without_count() {
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();

        // Two resident credentials for the same rp.
        for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
            let mut out = [0u8; 1024];
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: t,
            };
            make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
        }

        // Discover both ids via a no-allowList walk.
        let (id_a, id_b) = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 30,
            };
            let mut o1 = [0u8; 1024];
            let n1 = get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap();
            let a = cred_id_of(&o1[..n1]);
            let mut o2 = [0u8; 1024];
            let n2 = get_next_assertion(&mut ctx, &mut o2).unwrap();
            (a, cred_id_of(&o2[..n2]))
        };

        // With an allowList of BOTH, CTAP2.1 returns one assertion, no count, and
        // getNextAssertion is not armed.
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 40,
        };
        let mut o = [0u8; 1024];
        let n = get_assertion(&mut ctx, &ga_request_allow2(&id_a, &id_b), &mut o).unwrap();
        let (_user, count) = user_and_count(&o[..n]);
        assert_eq!(count, None);
        let mut o3 = [0u8; 256];
        assert_eq!(
            get_next_assertion(&mut ctx, &mut o3),
            Err(CtapError::NotAllowed)
        );
    }

    #[test]
    fn get_next_assertion_walks_resident_credentials() {
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();

        // Register two resident credentials for the same rp (distinct users/times).
        for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
            let mut out = [0u8; 1024];
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: t,
            };
            make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
        }

        // getAssertion (no allowList) → newest credential + numberOfCredentials = 2.
        let mut o1 = [0u8; 1024];
        let n1 = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 30,
            };
            get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap()
        };
        let (u1, count1) = user_and_count(&o1[..n1]);
        assert_eq!(count1, Some(2));
        assert_eq!(u1, &[1, 1, 1, 1]); // newest (created 20)
        // Without user verification the user map is id-only — name/displayName are
        // user-identifiable info, withheld unless uv (§6.2.2 privacy rule).
        assert_eq!(user_name_of(&o1[..n1]), "");

        // getNextAssertion → the older credential, no numberOfCredentials field.
        let mut o2 = [0u8; 1024];
        let n2 = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 31,
            };
            get_next_assertion(&mut ctx, &mut o2).unwrap()
        };
        let (u2, count2) = user_and_count(&o2[..n2]);
        assert_eq!(count2, None);
        assert_eq!(u2, &[9, 8, 7, 6]); // older (created 10)
        // getNextAssertion likewise withholds name/displayName without uv.
        assert_eq!(user_name_of(&o2[..n2]), "");

        // The list is exhausted → NOT_ALLOWED, and stays that way.
        let mut o3 = [0u8; 256];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 32,
        };
        assert_eq!(
            get_next_assertion(&mut ctx, &mut o3),
            Err(CtapError::NotAllowed)
        );
    }

    #[test]
    fn multi_cred_user_identity_returned_with_uv() {
        // The uv side of the §6.2.2 privacy rule: with user verification a
        // multi-credential discovery returns the full user identity (id + name).
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();
        for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
            let mut out = [0u8; 1024];
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: t,
            };
            make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
        }

        // Arm a PIN + token and present a valid pinUvAuthParam, no allowList
        // (so the discovery returns multiple credentials) → uv is set.
        let token = arm_pin(&mut fs, &mut state);
        let mut param = [0u8; 32];
        let plen =
            rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
        let req = {
            let mut buf = [0u8; 256];
            let n = {
                let mut e = Encoder::new(Cursor::new(&mut buf[..]));
                e.map(4).unwrap();
                e.u8(1).unwrap().str("example.com").unwrap();
                e.u8(2).unwrap().bytes(&CDH).unwrap();
                e.u8(6).unwrap().bytes(&param[..plen]).unwrap();
                e.u8(7).unwrap().u64(2).unwrap();
                e.writer().position()
            };
            buf[..n].to_vec()
        };
        let mut o = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 30,
            };
            get_assertion(&mut ctx, &req, &mut o).unwrap()
        };
        let (_u, count) = user_and_count(&o[..n]);
        assert_eq!(count, Some(2));
        assert_eq!(user_name_of(&o[..n]), "user");
    }

    // A resident makeCredential request carrying a credProtect level.
    fn mc_request_credprotect(level: u64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
            e.str("name").unwrap().str("bob").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6)
                .unwrap()
                .map(1)
                .unwrap()
                .str("credProtect")
                .unwrap()
                .u64(level)
                .unwrap();
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

    fn run_mc(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, req: &[u8]) -> std::vec::Vec<u8> {
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, req, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn run_ga(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, req: &[u8]) -> CtapResult {
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, req, &mut out).map(|n| out[..n].to_vec().len())
    }

    #[test]
    fn credprotect_optional_with_list_hidden_in_discovery() {
        let (mut fs, mut rng) = setup();
        // Register a UV-optional-with-list (level 2) resident credential.
        let mc = run_mc(&mut fs, &mut rng, &mc_request_credprotect(2));
        let (resident_id, x, y) = parse_mc(&mc);

        // Resident discovery (no allowList) without UV → hidden → NoCredentials.
        assert_eq!(
            run_ga(&mut fs, &mut rng, &ga_request(None)),
            Err(CtapError::NoCredentials)
        );

        // The same credential via an allowList is visible.
        let mut out = [0u8; 1024];
        let n = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &ga_request(Some(&resident_id)), &mut out).unwrap()
        };
        verify_assertion(&out[..n], &x, &y);
    }

    #[test]
    fn credprotect_uv_required_hidden_even_with_allow_list() {
        let (mut fs, mut rng) = setup();
        // Register a UV-required (level 3) resident credential.
        let mc = run_mc(&mut fs, &mut rng, &mc_request_credprotect(3));
        let (resident_id, _x, _y) = parse_mc(&mc);

        // Hidden in discovery and via the allowList without UV.
        assert_eq!(
            run_ga(&mut fs, &mut rng, &ga_request(None)),
            Err(CtapError::NoCredentials)
        );
        assert_eq!(
            run_ga(&mut fs, &mut rng, &ga_request(Some(&resident_id))),
            Err(CtapError::NoCredentials)
        );
    }

    // A resident makeCredential request carrying a credBlob.
    fn mc_request_credblob(blob: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
            e.str("name").unwrap().str("bob").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6)
                .unwrap()
                .map(1)
                .unwrap()
                .str("credBlob")
                .unwrap()
                .bytes(blob)
                .unwrap();
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

    fn ga_request_credblob(allow: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(allow).unwrap();
            e.u8(4)
                .unwrap()
                .map(1)
                .unwrap()
                .str("credBlob")
                .unwrap()
                .bool(true)
                .unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    fn assertion_auth_data(resp: &[u8]) -> std::vec::Vec<u8> {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        let mut ad = std::vec::Vec::new();
        for _ in 0..fields {
            if d.u8().unwrap() == 2 {
                ad = d.bytes().unwrap().to_vec();
            } else {
                d.skip().unwrap();
            }
        }
        ad
    }

    #[test]
    fn credblob_echoed_in_assertion() {
        let (mut fs, mut rng) = setup();
        let mc = run_mc(&mut fs, &mut rng, &mc_request_credblob(&[0x11, 0x22, 0x33]));
        let (resident_id, x, y) = parse_mc(&mc);

        let mut out = [0u8; 1024];
        let n = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &ga_request_credblob(&resident_id), &mut out).unwrap()
        };
        verify_assertion(&out[..n], &x, &y);
        let ad = assertion_auth_data(&out[..n]);
        assert_eq!(ad[32] & FLAG_ED, FLAG_ED, "ED flag set");
        // authData extension map: credBlob bytes echoed from the stored credential.
        let mut d = Decoder::new(&ad[37..]);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "credBlob");
        assert_eq!(d.bytes().unwrap(), &[0x11, 0x22, 0x33]);
    }

    // A resident makeCredential request that opts into largeBlobKey (+ hmac-secret).
    fn mc_request_lbk_hmac() -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2)
                .unwrap()
                .map(1)
                .unwrap()
                .str("id")
                .unwrap()
                .str("example.com")
                .unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
            e.str("name").unwrap().str("bob").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(6).unwrap().map(2).unwrap();
            e.str("hmac-secret").unwrap().bool(true).unwrap();
            e.str("largeBlobKey").unwrap().bool(true).unwrap();
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

    // The stored credential box for EF_CRED slot 0, and the device seed.
    fn stored_box_and_seed(fs: &mut Fs<RamStorage>) -> (std::vec::Vec<u8>, [u8; 32]) {
        let mut rec = [0u8; 1024];
        let n = fs.read(EF_CRED, &mut rec).unwrap();
        let seed = crate::seed::load_keydev(&dev(), fs).unwrap();
        (rec[RECORD_PREFIX..n].to_vec(), seed)
    }

    fn cose_xy(e: &mut Encoder<Cursor<&mut [u8]>>, x: &[u8; 32], y: &[u8; 32]) {
        e.map(5).unwrap();
        e.u8(1).unwrap().u8(2).unwrap(); // kty EC2
        e.u8(3).unwrap().i64(-25).unwrap(); // alg ECDH
        e.i8(-1).unwrap().u8(1).unwrap(); // crv P-256
        e.i8(-2).unwrap().bytes(x).unwrap();
        e.i8(-3).unwrap().bytes(y).unwrap();
    }

    fn ga_request_hmac(
        allow: &[u8],
        px: &[u8; 32],
        py: &[u8; 32],
        se: &[u8],
        sa: &[u8],
    ) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(allow).unwrap();
            e.u8(4).unwrap().map(1).unwrap();
            e.str("hmac-secret").unwrap().map(4).unwrap();
            e.u8(1).unwrap();
            cose_xy(&mut e, px, py);
            e.u8(2).unwrap().bytes(se).unwrap();
            e.u8(3).unwrap().bytes(sa).unwrap();
            e.u8(4).unwrap().u8(2).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    #[test]
    fn hmac_secret_assertion_end_to_end() {
        use rsk_crypto::pinproto::{authenticate, ecdh, encrypt, public_xy};
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();
        state.regenerate(&mut rng); // the clientPIN getKeyAgreement ephemeral key
        let (ax, ay) = state.ephemeral_public().unwrap();

        let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc_request_lbk_hmac());
        let (resident_id, _x, _y) = parse_mc(&mc);

        // Platform half (protocol two): ECDH, encrypt the salt, MAC it.
        let plat = {
            let mut s = [0u8; 32];
            s[0] = 0x22;
            s[31] = 0x22;
            s
        };
        let (px, py) = public_xy(&plat).unwrap();
        let mut shared = [0u8; 64];
        let slen = ecdh(PinProto::Two, &plat, &ax, &ay, &mut shared).unwrap();
        let salt = [0x77u8; 32];
        let iv = [0x01u8; 16];
        let mut se = [0u8; 48];
        let ne = encrypt(PinProto::Two, &shared[..slen], &iv, &salt, &mut se).unwrap();
        let mut sa = [0u8; 32];
        let na = authenticate(PinProto::Two, &shared[..slen], &se[..ne], &mut sa).unwrap();

        let req = ga_request_hmac(&resident_id, &px, &py, &se[..ne], &sa[..na]);
        let mut out = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &req, &mut out).unwrap()
        };
        let ad = assertion_auth_data(&out[..n]);
        assert_eq!(ad[32] & FLAG_ED, FLAG_ED);

        // Pull the hmac-secret output from the authData extensions and decrypt it.
        let mut d = Decoder::new(&ad[37..]);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "hmac-secret");
        let hmac_out = d.bytes().unwrap();
        assert_eq!(hmac_out.len(), 48); // v2: 16 IV + 32
        let mut dec = [0u8; 32];
        rsk_crypto::pinproto::decrypt(PinProto::Two, &shared[..slen], hmac_out, &mut dec).unwrap();

        // It must equal HMAC(CredRandomWithoutUV, salt) for the stored credential.
        let (cred_box, seed) = stored_box_and_seed(&mut fs);
        let cr = crate::credential::derive_hmac_key(&seed, &cred_box);
        assert_eq!(&dec[..], &rsk_crypto::hmac_sha256(&cr[..32], &salt)[..]);
    }

    fn run_mc_state(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        state: &mut crate::FidoState,
        req: &[u8],
    ) -> std::vec::Vec<u8> {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, req, &mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn large_blob_key_in_assertion() {
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();
        let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc_request_lbk_hmac());
        let (resident_id, _x, _y) = parse_mc(&mc);

        // getAssertion requesting largeBlobKey → response field 0x07 with the key.
        let mut buf = [0u8; 512];
        let req = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(&resident_id).unwrap();
            e.u8(4)
                .unwrap()
                .map(1)
                .unwrap()
                .str("largeBlobKey")
                .unwrap()
                .bool(true)
                .unwrap();
            let n = e.writer().position();
            buf[..n].to_vec()
        };
        let mut out = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &req, &mut out).unwrap()
        };
        // Field 0x07 is the 32-byte largeBlobKey for this credential.
        let mut d = Decoder::new(&out[..n]);
        let fields = d.map().unwrap().unwrap();
        let mut lbk = None;
        for _ in 0..fields {
            if d.u8().unwrap() == 7 {
                lbk = Some(d.bytes().unwrap().to_vec());
            } else {
                d.skip().unwrap();
            }
        }
        let (cred_box, seed) = stored_box_and_seed(&mut fs);
        let expected = crate::credential::derive_large_blob_key(&seed, &cred_box);
        assert_eq!(lbk.as_deref(), Some(&expected[..]));
    }

    // makeCredential request offering a single non-default algorithm.
    fn mc_request_alg(alg: i64) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str("example.com").unwrap();
            e.u8(3).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(&[7, 7, 7, 7]).unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(alg).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    // makeCredential authData → (credId, cose x, cose y) for any EC2 curve.
    fn parse_mc_ec2(resp: &[u8]) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let mut d = Decoder::new(resp);
        assert!(d.map().unwrap().unwrap() >= 3);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let ad = d.bytes().unwrap();
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cred_id = ad[55..55 + cred_len].to_vec();
        let mut cd = Decoder::new(&ad[55 + cred_len..]);
        assert_eq!(cd.map().unwrap().unwrap(), 5);
        cd.u8().unwrap();
        cd.u8().unwrap(); // 1: kty 2
        cd.u8().unwrap();
        cd.i64().unwrap(); // 3: alg
        cd.i8().unwrap();
        cd.u8().unwrap(); // -1: crv
        cd.i8().unwrap();
        let x = cd.bytes().unwrap().to_vec(); // -2
        cd.i8().unwrap();
        let y = cd.bytes().unwrap().to_vec(); // -3
        (cred_id, x, y)
    }

    fn assertion_sig(resp: &[u8]) -> std::vec::Vec<u8> {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        let mut sig = std::vec::Vec::new();
        for _ in 0..fields {
            if d.u8().unwrap() == 3 {
                sig = d.bytes().unwrap().to_vec();
            } else {
                d.skip().unwrap();
            }
        }
        sig
    }

    #[test]
    fn es384_register_then_login_verifies() {
        use crate::consts::ALG_ES384;
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let (mut fs, mut rng) = setup();

        // Register a P-384 (ES384) credential and pull its COSE public key.
        let mut o1 = [0u8; 1024];
        let mc = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let n = make_credential(&mut ctx, &mc_request_alg(ALG_ES384), &mut o1).unwrap();
            o1[..n].to_vec()
        };
        let (cred_id, x, y) = parse_mc_ec2(&mc);
        assert_eq!(x.len(), 48, "P-384 coordinates are 48 bytes");

        // Log in with the credential and verify the assertion under the P-384 key.
        let mut o2 = [0u8; 1024];
        let ga = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            let n = get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut o2).unwrap();
            o2[..n].to_vec()
        };
        let ad = assertion_auth_data(&ga);
        let sig = assertion_sig(&ga);
        let pt = p384::EncodedPoint::from_affine_coordinates(
            p384::FieldBytes::from_slice(&x),
            p384::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        let mut signed = ad;
        signed.extend_from_slice(&CDH);
        vk.verify(&signed, &Signature::from_der(&sig).unwrap())
            .expect("ES384 assertion verifies under the credential key");
    }

    // makeCredential authData → (credId, OKP pubkey) for Ed25519.
    fn parse_mc_okp(resp: &[u8]) -> (std::vec::Vec<u8>, [u8; 32]) {
        let mut d = Decoder::new(resp);
        assert!(d.map().unwrap().unwrap() >= 3);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let ad = d.bytes().unwrap();
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cred_id = ad[55..55 + cred_len].to_vec();
        let mut cd = Decoder::new(&ad[55 + cred_len..]);
        assert_eq!(cd.map().unwrap().unwrap(), 4);
        cd.u8().unwrap();
        assert_eq!(cd.u8().unwrap(), 1); // kty OKP
        cd.u8().unwrap();
        cd.i64().unwrap(); // alg
        cd.i8().unwrap();
        cd.u8().unwrap(); // crv
        cd.i8().unwrap();
        let pk: [u8; 32] = cd.bytes().unwrap().try_into().unwrap();
        (cred_id, pk)
    }

    #[test]
    fn ed25519_register_then_login_verifies() {
        use crate::consts::ALG_EDDSA;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let (mut fs, mut rng) = setup();

        let mut o1 = [0u8; 1024];
        let mc = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let n = make_credential(&mut ctx, &mc_request_alg(ALG_EDDSA), &mut o1).unwrap();
            o1[..n].to_vec()
        };
        let (cred_id, pk) = parse_mc_okp(&mc);

        let mut o2 = [0u8; 1024];
        let ga = {
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            let n = get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut o2).unwrap();
            o2[..n].to_vec()
        };
        let ad = assertion_auth_data(&ga);
        let sig = assertion_sig(&ga);
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let mut signed = ad;
        signed.extend_from_slice(&CDH);
        vk.verify(&signed, &Signature::from_slice(&sig).unwrap())
            .expect("Ed25519 assertion verifies under the credential key");
    }

    #[test]
    fn get_next_assertion_without_state_is_not_allowed() {
        let (mut fs, mut rng) = setup();
        let mut state = crate::FidoState::new();
        let mut out = [0u8; 64];
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
            get_next_assertion(&mut ctx, &mut out),
            Err(CtapError::NotAllowed)
        );
    }

    // ---- ML-DSA-44 (PQC) end-to-end ----

    // Run one CTAP call against `fs` with a PQC-sized response buffer.
    fn call(
        fs: &mut Fs<RamStorage>,
        rng: &mut SeqRng,
        now_ms: u64,
        f: impl FnOnce(&mut Ctx<RamStorage, SeqRng>, &mut [u8]) -> crate::error::CtapResult,
    ) -> Result<std::vec::Vec<u8>, CtapError> {
        let mut out = [0u8; 8192];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms,
        };
        let n = f(&mut ctx, &mut out)?;
        Ok(out[..n].to_vec())
    }

    // makeCredential authData → (credId, AKP alg, AKP pubkey) for ML-DSA.
    fn parse_mc_akp(resp: &[u8]) -> (std::vec::Vec<u8>, i64, std::vec::Vec<u8>) {
        let mut d = Decoder::new(resp);
        assert!(d.map().unwrap().unwrap() >= 3);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.str().unwrap(), "packed");
        assert_eq!(d.u8().unwrap(), 2);
        let ad = d.bytes().unwrap();
        let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cred_id = ad[55..55 + cred_len].to_vec();
        let mut cd = Decoder::new(&ad[55 + cred_len..]);
        assert_eq!(
            cd.map().unwrap().unwrap(),
            3,
            "AKP COSE key is a 3-entry map"
        );
        cd.u8().unwrap();
        assert_eq!(cd.u8().unwrap(), crate::consts::KTY_AKP); // 1: kty
        cd.u8().unwrap();
        let alg = cd.i64().unwrap(); // 3: alg
        cd.i8().unwrap(); // -1: pub
        let pk = cd.bytes().unwrap().to_vec();
        (cred_id, alg, pk)
    }

    // Pull the packed attStmt `(alg, sig)` and authData out of a makeCredential
    // response.
    fn mc_att(resp: &[u8]) -> (i64, std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let mut d = Decoder::new(resp);
        let fields = d.map().unwrap().unwrap();
        let (mut alg, mut sig, mut ad) = (0i64, std::vec::Vec::new(), std::vec::Vec::new());
        for _ in 0..fields {
            match d.u8().unwrap() {
                2 => ad = d.bytes().unwrap().to_vec(),
                3 => {
                    assert_eq!(d.map().unwrap().unwrap(), 2);
                    assert_eq!(d.str().unwrap(), "alg");
                    alg = d.i64().unwrap();
                    assert_eq!(d.str().unwrap(), "sig");
                    sig = d.bytes().unwrap().to_vec();
                }
                _ => d.skip().unwrap(),
            }
        }
        (alg, sig, ad)
    }

    fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let pk: [u8; rsk_crypto::MLDSA44_PK_LEN] = pk.try_into().expect("AKP pk length");
        let sig: [u8; rsk_crypto::MLDSA44_SIG_LEN] = sig.try_into().expect("ML-DSA sig length");
        rsk_crypto::mldsa44_verify(&pk, msg, &sig)
    }

    #[test]
    fn mldsa44_register_then_login_verifies() {
        use crate::consts::ALG_MLDSA44;
        let (mut fs, mut rng) = setup();

        // Register: the self-attestation must verify under the AKP COSE key.
        let mc = call(&mut fs, &mut rng, 10, |ctx, out| {
            make_credential(ctx, &mc_request_alg(ALG_MLDSA44), out)
        })
        .unwrap();
        let (cred_id, alg, pk) = parse_mc_akp(&mc);
        assert_eq!(alg, ALG_MLDSA44);
        assert_eq!(pk.len(), rsk_crypto::MLDSA44_PK_LEN);
        let (att_alg, att_sig, ad) = mc_att(&mc);
        assert_eq!(att_alg, ALG_MLDSA44);
        let mut signed = ad;
        signed.extend_from_slice(&CDH);
        assert!(
            mldsa_verify(&pk, &signed, &att_sig),
            "ML-DSA-44 self-attestation verifies"
        );

        // Login with the returned credential id; the assertion signature must
        // verify under the same key.
        let ga = call(&mut fs, &mut rng, 20, |ctx, out| {
            get_assertion(ctx, &ga_request(Some(&cred_id)), out)
        })
        .unwrap();
        let ad = assertion_auth_data(&ga);
        let sig = assertion_sig(&ga);
        assert_eq!(sig.len(), rsk_crypto::MLDSA44_SIG_LEN);
        let mut signed = ad;
        signed.extend_from_slice(&CDH);
        assert!(
            mldsa_verify(&pk, &signed, &sig),
            "ML-DSA-44 assertion verifies under the credential key"
        );
    }

    // rk makeCredential with an explicit algorithm and user id (the upgrade flow).
    fn mc_request_alg_rk(alg: i64, uid: &[u8]) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str("example.com").unwrap();
            e.u8(3).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(uid).unwrap();
            e.str("name").unwrap().str("user").unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(alg).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.u8(7).unwrap().map(1).unwrap();
            e.str("rk").unwrap().bool(true).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// The classic→PQC upgrade: re-registering the same rp/user with ML-DSA-44
    /// overwrites the resident slot (one credential, now PQC) while an old
    /// *non-resident* ES256 credential id keeps asserting — the box is
    /// self-contained, so downstream state survives the upgrade.
    #[test]
    fn classic_to_pqc_upgrade() {
        use crate::consts::{ALG_ES256, ALG_MLDSA44};
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let (mut fs, mut rng) = setup();
        let uid = [9u8, 9, 9];

        // An old non-resident ES256 credential (the box IS the credential id).
        let mc_old = call(&mut fs, &mut rng, 10, |ctx, out| {
            make_credential(ctx, &mc_request_alg(ALG_ES256), out)
        })
        .unwrap();
        let (old_id, x, y) = parse_mc_ec2(&mc_old);

        // A resident ES256 credential, then the PQC re-registration of the SAME
        // rp/user — the slot is overwritten, not duplicated.
        call(&mut fs, &mut rng, 20, |ctx, out| {
            make_credential(ctx, &mc_request_alg_rk(ALG_ES256, &uid), out)
        })
        .unwrap();
        let mc_pqc = call(&mut fs, &mut rng, 30, |ctx, out| {
            make_credential(ctx, &mc_request_alg_rk(ALG_MLDSA44, &uid), out)
        })
        .unwrap();
        let (_, alg, pqc_pk) = parse_mc_akp(&mc_pqc);
        assert_eq!(alg, ALG_MLDSA44);

        // Resident discovery: exactly one credential survives, and it signs
        // with ML-DSA-44.
        let ga = call(&mut fs, &mut rng, 40, |ctx, out| {
            get_assertion(ctx, &ga_request(None), out)
        })
        .unwrap();
        let (_, n_creds) = user_and_count(&ga);
        assert_eq!(n_creds, None, "a single credential omits the count");
        let sig = assertion_sig(&ga);
        assert_eq!(sig.len(), rsk_crypto::MLDSA44_SIG_LEN);
        let mut signed = assertion_auth_data(&ga);
        signed.extend_from_slice(&CDH);
        assert!(mldsa_verify(&pqc_pk, &signed, &sig));

        // The old non-resident ES256 id still works via allowList.
        let ga_old = call(&mut fs, &mut rng, 50, |ctx, out| {
            get_assertion(ctx, &ga_request(Some(&old_id)), out)
        })
        .unwrap();
        let sig = assertion_sig(&ga_old);
        let mut signed = assertion_auth_data(&ga_old);
        signed.extend_from_slice(&CDH);
        let pt = p256::EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(&x),
            p256::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&pt).unwrap();
        vk.verify(&signed, &Signature::from_der(&sig).unwrap())
            .expect("pre-upgrade ES256 credential still asserts");
    }
}
