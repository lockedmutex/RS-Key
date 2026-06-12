// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! U2F / CTAP1: register, authenticate, version — ISO-7816 APDUs over
//! CTAPHID_MSG. Registration returns the new public key, a 64-byte key handle,
//! the attestation certificate and a signature by the device key;
//! authentication signs a challenge with the credential key.

use zeroize::Zeroize;

use rsk_fs::Storage;
use rsk_sdk::apdu::Apdu;
use rsk_sdk::sw::Sw;

use crate::consts::{
    CTAP_AUTHENTICATE, CTAP_REGISTER, CTAP_VERSION, EF_ATT_CHAIN, EF_EE_DEV, U2F_AUTH_CHECK_ONLY,
    U2F_AUTH_ENFORCE, U2F_AUTH_FLAG_TUP, U2F_REGISTER_ID,
};
use crate::credential::credential_load;
use crate::ec::{MAX_DER_SIG, P256Key};
use crate::journal;
use crate::keyderiv::{KEY_HANDLE_LEN, derive_new, fido_load_key, verify_key};
use crate::seed::{bump_sign_counter, get_sign_counter, load_att_key};
use crate::{Ctx, Rng};

/// Dispatch a U2F APDU; writes the response body into `out`, returns `(SW, len)`.
pub fn process_u2f<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    apdu: &Apdu,
    out: &mut [u8],
) -> (Sw, usize) {
    // U2F APDUs are CLA 0x00.
    if apdu.cla != 0x00 {
        return (Sw::CLA_NOT_SUPPORTED, 0);
    }
    match apdu.ins {
        CTAP_REGISTER => cmd_register(ctx, apdu, out),
        CTAP_AUTHENTICATE => cmd_authenticate(ctx, apdu, out),
        CTAP_VERSION => {
            out[..6].copy_from_slice(b"U2F_V2");
            (Sw::OK, 6)
        }
        _ => (Sw::INS_NOT_SUPPORTED, 0),
    }
}

fn cmd_register<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    apdu: &Apdu,
    out: &mut [u8],
) -> (Sw, usize) {
    if apdu.nc != 64 {
        return (Sw::WRONG_LENGTH, 0);
    }
    // U2F register requires a physical touch; no button → instant.
    if !ctx.check_user_presence() {
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }
    // U2F register request is challenge(32) ‖ application(32). The key handle
    // binds to the application and the signature base is
    // 0x00 ‖ application ‖ challenge ‖ … (note the swap).
    let chal = &apdu.data[..32];
    let mut app = [0u8; 32];
    app.copy_from_slice(&apdu.data[32..64]);

    let mut seed = match ctx.load_keydev() {
        Some(s) => s,
        None => return (Sw::EXEC_ERROR, 0),
    };
    let (key_handle, mut scalar) = derive_new(&seed, &app, ctx.rng);
    let cred_key = P256Key::from_scalar(&scalar);
    scalar.zeroize();
    // Org-provisioned attestation (vendor ATT_IMPORT) wins — classic U2F batch
    // attestation; otherwise the per-device key (the seed scalar) with its
    // self-signed EF_EE_DEV cert.
    let mut att_scalar = load_att_key(&ctx.dev, ctx.fs);
    let org = att_scalar.is_some();
    let device_key = match att_scalar.as_mut() {
        Some(s) => {
            let k = P256Key::from_scalar(s);
            s.zeroize();
            k
        }
        None => P256Key::from_scalar(&seed),
    };
    seed.zeroize();
    let (cred_key, device_key) = match (cred_key, device_key) {
        (Some(c), Some(d)) => (c, d),
        _ => return (Sw::EXEC_ERROR, 0),
    };
    let (x, y) = cred_key.public_xy();

    // sign base: 0x00 ‖ appId ‖ chal ‖ keyHandle ‖ (0x04 ‖ x ‖ y)
    let mut base = [0u8; 1 + 32 + 32 + KEY_HANDLE_LEN + 65];
    let mut p = 0;
    base[p] = 0x00;
    p += 1;
    base[p..p + 32].copy_from_slice(&app);
    p += 32;
    base[p..p + 32].copy_from_slice(chal);
    p += 32;
    base[p..p + KEY_HANDLE_LEN].copy_from_slice(&key_handle);
    p += KEY_HANDLE_LEN;
    base[p] = 0x04;
    p += 1;
    base[p..p + 32].copy_from_slice(&x);
    p += 32;
    base[p..p + 32].copy_from_slice(&y);
    p += 32;
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = device_key.sign_der(&base[..p], &mut sig);

    let mut cert = [0u8; 2064];
    let clen = if org {
        // The chain's leaf — a U2F response carries exactly one certificate.
        let n = match ctx.fs.read(EF_ATT_CHAIN, &mut cert) {
            Some(n) if n > 3 => n,
            _ => return (Sw::EXEC_ERROR, 0),
        };
        let Some((off, len)) = crate::cert::att_chain_cert_range(&cert[..n], 0) else {
            return (Sw::EXEC_ERROR, 0);
        };
        cert.copy_within(off..off + len, 0);
        len
    } else {
        match ctx.fs.read(EF_EE_DEV, &mut cert) {
            Some(n) if n > 0 => n.min(cert.len()),
            _ => return (Sw::EXEC_ERROR, 0),
        }
    };

    // response: 0x05 ‖ (0x04 ‖ x ‖ y) ‖ 64 ‖ keyHandle ‖ cert ‖ sig
    let total = 1 + 65 + 1 + KEY_HANDLE_LEN + clen + sl;
    if out.len() < total {
        return (Sw::EXEC_ERROR, 0);
    }
    let mut q = 0;
    out[q] = U2F_REGISTER_ID;
    q += 1;
    out[q] = 0x04;
    q += 1;
    out[q..q + 32].copy_from_slice(&x);
    q += 32;
    out[q..q + 32].copy_from_slice(&y);
    q += 32;
    out[q] = KEY_HANDLE_LEN as u8;
    q += 1;
    out[q..q + KEY_HANDLE_LEN].copy_from_slice(&key_handle);
    q += KEY_HANDLE_LEN;
    out[q..q + clen].copy_from_slice(&cert[..clen]);
    q += clen;
    out[q..q + sl].copy_from_slice(&sig[..sl]);
    q += sl;
    journal::append(ctx, journal::EV_U2F_REGISTER, 0, &apdu.data[32..40]);
    (Sw::OK, q)
}

fn cmd_authenticate<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    apdu: &Apdu,
    out: &mut [u8],
) -> (Sw, usize) {
    // chal(32) ‖ appId(32) ‖ khLen(1) ‖ keyHandle
    if apdu.nc < 32 + 32 + 1 + 1 {
        return (Sw::INCORRECT_PARAMS, 0);
    }
    let chal = &apdu.data[..32];
    let mut app = [0u8; 32];
    app.copy_from_slice(&apdu.data[32..64]);
    let kh_len = apdu.data[64] as usize;
    if kh_len < KEY_HANDLE_LEN || 65 + kh_len > apdu.nc {
        return (Sw::INCORRECT_PARAMS, 0);
    }
    // "Enforce user presence" (P1=0x03) requires a touch; check-only (0x07) and
    // don't-enforce (0x08) do not. No button → instant.
    if apdu.p1 == U2F_AUTH_ENFORCE && !ctx.check_user_presence() {
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }
    let key_handle = &apdu.data[65..65 + kh_len];

    let mut seed = match ctx.load_keydev() {
        Some(s) => s,
        None => return (Sw::EXEC_ERROR, 0),
    };
    // credential_load resolves both a CTAP2 box and a U2F key handle, flagging the
    // latter via `u2f`: a box signs with fido_load_key, a handle with its path-as-is
    // scalar (verify_key, which fido_load_key would clobber by rewriting path[0]).
    // U2F is P-256 only, so take the leading 32 bytes of the ratchet as the scalar.
    let mut scratch = [0u8; 1024];
    let scalar: Option<[u8; 32]> =
        match credential_load(&seed, key_handle, &app, &mut scratch).map(|c| c.u2f) {
            Some(false) => fido_load_key(&seed, key_handle).map(|raw| {
                let mut s = [0u8; 32];
                s.copy_from_slice(&raw[..32]);
                s
            }),
            Some(true) => {
                let mut kh = [0u8; KEY_HANDLE_LEN];
                kh.copy_from_slice(&key_handle[..KEY_HANDLE_LEN]);
                verify_key(&seed, &app, &kh)
            }
            None => None,
        };
    seed.zeroize();
    let mut scalar = match scalar {
        Some(s) => s,
        None => return (Sw::INCORRECT_PARAMS, 0),
    };

    // check-only: a valid handle reports "would require user presence".
    if apdu.p1 == U2F_AUTH_CHECK_ONLY {
        scalar.zeroize();
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }
    let key = P256Key::from_scalar(&scalar);
    scalar.zeroize();
    let key = match key {
        Some(k) => k,
        None => return (Sw::EXEC_ERROR, 0),
    };

    let flags = if apdu.p1 == U2F_AUTH_ENFORCE {
        U2F_AUTH_FLAG_TUP
    } else {
        0
    };
    let ctr = get_sign_counter(ctx.fs);

    // sign base: appId ‖ flags ‖ counter(BE) ‖ chal
    let mut base = [0u8; 32 + 1 + 4 + 32];
    base[..32].copy_from_slice(&app);
    base[32] = flags;
    base[33..37].copy_from_slice(&ctr.to_be_bytes());
    base[37..69].copy_from_slice(chal);
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&base, &mut sig);

    // response: flags ‖ counter(BE) ‖ signature
    out[0] = flags;
    out[1..5].copy_from_slice(&ctr.to_be_bytes());
    out[5..5 + sl].copy_from_slice(&sig[..sl]);
    let _ = bump_sign_counter(ctx.fs);
    journal::append(ctx, journal::EV_U2F_AUTH, 0, &app[..8]);
    (Sw::OK, 5 + sl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::ensure_seed;
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

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    const APP: [u8; 32] = [0x5A; 32];
    const CHAL: [u8; 32] = [0xC4; 32];

    fn ext_apdu(ins: u8, p1: u8, data: &[u8]) -> std::vec::Vec<u8> {
        let mut v = std::vec![
            0x00,
            ins,
            p1,
            0x00,
            0x00,
            (data.len() >> 8) as u8,
            data.len() as u8
        ];
        v.extend_from_slice(data);
        v.extend_from_slice(&[0x00, 0x00]); // extended Le
        v
    }

    fn vkey(x: &[u8], y: &[u8]) -> VerifyingKey {
        let pt = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        VerifyingKey::from_encoded_point(&pt).unwrap()
    }

    struct Fixed(crate::Presence);
    impl crate::UserPresence for Fixed {
        fn request(&mut self) -> crate::Presence {
            self.0
        }
    }

    #[test]
    fn register_without_touch_is_refused() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let mut data = std::vec::Vec::new();
        data.extend_from_slice(&CHAL);
        data.extend_from_slice(&APP);
        let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
        let reg_apdu = Apdu::parse(&reg_bytes).unwrap();
        let mut out = [0u8; 1024];
        let (sw, n) = {
            let mut state = crate::FidoState::new();
            let mut presence = Fixed(crate::Presence::Timeout);
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            process_u2f(&mut ctx, &reg_apdu, &mut out)
        };
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
        assert_eq!(n, 0);
    }

    #[test]
    fn register_then_authenticate() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

        // --- register ---
        let mut data = std::vec::Vec::new();
        data.extend_from_slice(&CHAL); // U2F register request: challenge then application
        data.extend_from_slice(&APP);
        let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
        let reg_apdu = Apdu::parse(&reg_bytes).unwrap();
        let mut out = [0u8; 1024];
        let (sw, n) = {
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
            process_u2f(&mut ctx, &reg_apdu, &mut out)
        };
        assert_eq!(sw, Sw::OK);
        let resp = &out[..n];
        assert_eq!(resp[0], U2F_REGISTER_ID);
        assert_eq!(resp[1], 0x04);
        let pub_x = &resp[2..34];
        let pub_y = &resp[34..66];
        assert_eq!(resp[66] as usize, KEY_HANDLE_LEN);
        let key_handle = resp[67..67 + KEY_HANDLE_LEN].to_vec();
        let cert_and_sig = &resp[67 + KEY_HANDLE_LEN..];
        // The cert is a SEQUENCE; the registration signature follows it.
        assert_eq!(cert_and_sig[0], 0x30);
        let cert_len = 4 + (((cert_and_sig[2] as usize) << 8) | cert_and_sig[3] as usize);
        let reg_sig = &cert_and_sig[cert_len..];

        // Verify the registration signature under the device (attestation) key.
        let mut seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
        let device_key = P256Key::from_scalar(&seed).unwrap();
        seed.zeroize();
        let (dx, dy) = device_key.public_xy();
        let mut base = std::vec![0x00u8];
        base.extend_from_slice(&APP);
        base.extend_from_slice(&CHAL);
        base.extend_from_slice(&key_handle);
        base.push(0x04);
        base.extend_from_slice(pub_x);
        base.extend_from_slice(pub_y);
        vkey(&dx, &dy)
            .verify(&base, &Signature::from_der(reg_sig).unwrap())
            .expect("registration signature verifies under the attestation key");

        // --- authenticate ---
        let mut ad = std::vec::Vec::new();
        ad.extend_from_slice(&CHAL);
        ad.extend_from_slice(&APP);
        ad.push(KEY_HANDLE_LEN as u8);
        ad.extend_from_slice(&key_handle);
        let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad);
        let auth_apdu = Apdu::parse(&auth_bytes).unwrap();
        let mut out2 = [0u8; 256];
        let (sw, n) = {
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
            process_u2f(&mut ctx, &auth_apdu, &mut out2)
        };
        assert_eq!(sw, Sw::OK);
        let a = &out2[..n];
        assert_eq!(a[0] & U2F_AUTH_FLAG_TUP, U2F_AUTH_FLAG_TUP);
        let ctr = u32::from_be_bytes([a[1], a[2], a[3], a[4]]);
        let auth_sig = &a[5..];

        // The assertion signs appId ‖ flags ‖ counter ‖ chal under the credential key.
        let mut sbase = std::vec::Vec::new();
        sbase.extend_from_slice(&APP);
        sbase.push(a[0]);
        sbase.extend_from_slice(&ctr.to_be_bytes());
        sbase.extend_from_slice(&CHAL);
        vkey(pub_x, pub_y)
            .verify(&sbase, &Signature::from_der(auth_sig).unwrap())
            .expect("authentication signature verifies under the credential key");
    }

    #[test]
    fn check_only_and_bad_handle() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(2);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

        // Register to get a valid handle.
        let mut data = std::vec::Vec::new();
        data.extend_from_slice(&CHAL); // U2F register request: challenge then application
        data.extend_from_slice(&APP);
        let mut out = [0u8; 1024];
        let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
        let kh = {
            let reg = Apdu::parse(&reg_bytes).unwrap();
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
            let (_, _n) = process_u2f(&mut ctx, &reg, &mut out);
            out[67..67 + KEY_HANDLE_LEN].to_vec()
        };

        // check-only on a valid handle → CONDITIONS_NOT_SATISFIED.
        let mut ad = std::vec::Vec::new();
        ad.extend_from_slice(&CHAL);
        ad.extend_from_slice(&APP);
        ad.push(KEY_HANDLE_LEN as u8);
        ad.extend_from_slice(&kh);
        let mut o = [0u8; 256];
        let chk_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_CHECK_ONLY, &ad);
        let chk = Apdu::parse(&chk_bytes).unwrap();
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
            process_u2f(&mut ctx, &chk, &mut o).0,
            Sw::CONDITIONS_NOT_SATISFIED
        );

        // A bogus handle (wrong tag) → INCORRECT_PARAMS.
        let mut bad = ad.clone();
        let l = bad.len();
        bad[l - 1] ^= 0xFF; // corrupt the handle's HMAC tag
        let bad_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &bad);
        let badc = Apdu::parse(&bad_bytes).unwrap();
        assert_eq!(process_u2f(&mut ctx, &badc, &mut o).0, Sw::INCORRECT_PARAMS);
    }

    #[test]
    fn version() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(3);
        let ver = Apdu::parse(&[0x00, CTAP_VERSION, 0x00, 0x00]).unwrap();
        let mut o = [0u8; 16];
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
        let (sw, n) = process_u2f(&mut ctx, &ver, &mut o);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&o[..n], b"U2F_V2");
    }

    #[test]
    fn bad_cla_and_ins() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(9);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
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
        let mut o = [0u8; 64];
        // Non-zero CLA → 0x6E00 CLA_NOT_SUPPORTED.
        let bad_cla = Apdu::parse(&[0x01, CTAP_VERSION, 0x00, 0x00]).unwrap();
        assert_eq!(
            process_u2f(&mut ctx, &bad_cla, &mut o).0,
            Sw::CLA_NOT_SUPPORTED
        );
        // Unknown INS (CLA 0) → 0x6D00 INS_NOT_SUPPORTED.
        let bad_ins = Apdu::parse(&[0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(
            process_u2f(&mut ctx, &bad_ins, &mut o).0,
            Sw::INS_NOT_SUPPORTED
        );
    }
}
