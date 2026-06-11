// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! hmac-secret extension, shared by getAssertion (`hmac-secret`) and
//! makeCredential (`hmac-secret-mc`): ECDH against the platform's keyAgreement,
//! verify the platform salt MAC, decrypt the salts, HMAC each under the
//! credential's `cred_random` (the UV half selected by the UV flag), re-encrypt.
//! The ECDH key is the same ephemeral one `clientPIN getKeyAgreement`
//! published, so the platform must have fetched it first.

use minicbor::Decoder;
use zeroize::Zeroize;

use rsk_crypto::hmac_sha256;
use rsk_crypto::pinproto::{self, IV_SIZE, PinProto};

use crate::Rng;
use crate::cbordec::{cbor, def_map};
use crate::credential::derive_hmac_key;
use crate::error::CtapError;

/// A parsed hmac-secret / hmac-secret-mc request map.
pub struct HmacSecretReq<'a> {
    pub peer_x: [u8; 32],
    pub peer_y: [u8; 32],
    pub salt_enc: &'a [u8],
    pub salt_auth: &'a [u8],
    pub proto: u64,
    pub present: bool,
}

impl Default for HmacSecretReq<'_> {
    fn default() -> Self {
        Self {
            peer_x: [0; 32],
            peer_y: [0; 32],
            salt_enc: &[],
            salt_auth: &[],
            proto: 1,
            present: false,
        }
    }
}

/// Right-align a COSE coordinate (≤ 32 bytes, big-endian) into a 32-byte buffer.
fn coord(dst: &mut [u8; 32], src: &[u8]) -> Result<(), CtapError> {
    if src.len() > 32 {
        return Err(CtapError::InvalidParameter);
    }
    *dst = [0; 32];
    dst[32 - src.len()..].copy_from_slice(src);
    Ok(())
}

/// Parse the extension map `{1: keyAgreement(COSE), 2: salt_enc, 3: salt_auth,
/// 4: pinUvAuthProtocol}`.
pub fn parse<'a>(d: &mut Decoder<'a>) -> Result<HmacSecretReq<'a>, CtapError> {
    let mut req = HmacSecretReq {
        present: true,
        ..Default::default()
    };
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.u32())? {
            0x01 => {
                let km = def_map(d)?;
                for _ in 0..km {
                    match cbor(d.i32())? {
                        -2 => coord(&mut req.peer_x, cbor(d.bytes())?)?,
                        -3 => coord(&mut req.peer_y, cbor(d.bytes())?)?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            0x02 => req.salt_enc = cbor(d.bytes())?,
            0x03 => req.salt_auth = cbor(d.bytes())?,
            0x04 => req.proto = cbor(d.u32())? as u64,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Parse an hmac-secret extension map from raw CBOR bytes (test / fuzz entry).
pub fn parse_bytes(data: &[u8]) -> Result<HmacSecretReq<'_>, CtapError> {
    parse(&mut Decoder::new(data))
}

/// Validate `salt_enc.len()` for `proto`, returning the plaintext salt length (32
/// for one salt, 64 for two).
fn salt_plaintext_len(proto: PinProto, salt_enc_len: usize) -> Option<usize> {
    let off = proto.iv_overhead();
    if salt_enc_len == 32 + off {
        Some(32)
    } else if salt_enc_len == 64 + off {
        Some(64)
    } else {
        None
    }
}

/// Evaluate hmac-secret for `cred_id`: write the encrypted HMAC output into `out`
/// and return its length (= `req.salt_enc.len()`). `ephemeral` is the
/// authenticator's clientPIN ECDH scalar.
#[allow(clippy::too_many_arguments)]
pub fn eval<R: Rng>(
    req: &HmacSecretReq,
    ephemeral: &[u8; 32],
    seed: &[u8; 32],
    cred_id: &[u8],
    uv: bool,
    rng: &mut R,
    out: &mut [u8],
) -> Result<usize, CtapError> {
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;
    let n_salt = salt_plaintext_len(proto, req.salt_enc.len()).ok_or(CtapError::InvalidLength)?;

    let mut shared = [0u8; 64];
    let slen = pinproto::ecdh(proto, ephemeral, &req.peer_x, &req.peer_y, &mut shared)
        .map_err(|_| CtapError::InvalidParameter)?;

    if !pinproto::verify(proto, &shared[..slen], req.salt_enc, req.salt_auth) {
        shared.zeroize();
        return Err(CtapError::ExtensionFirst);
    }

    let mut salt_dec = [0u8; 64];
    let r = pinproto::decrypt(proto, &shared[..slen], req.salt_enc, &mut salt_dec);
    if r.is_err() {
        shared.zeroize();
        return Err(CtapError::InvalidParameter);
    }

    let mut cred_random = derive_hmac_key(seed, cred_id);
    let crd: &[u8] = if uv {
        &cred_random[32..]
    } else {
        &cred_random[..32]
    };
    let mut out1 = [0u8; 64];
    out1[..32].copy_from_slice(&hmac_sha256(crd, &salt_dec[..32]));
    if n_salt == 64 {
        let h2 = hmac_sha256(crd, &salt_dec[32..64]);
        out1[32..64].copy_from_slice(&h2);
    }

    let mut iv = [0u8; IV_SIZE];
    rng.fill(&mut iv);
    let nout = pinproto::encrypt(proto, &shared[..slen], &iv, &out1[..n_salt], out)
        .map_err(|_| CtapError::Other)?;

    shared.zeroize();
    salt_dec.zeroize();
    cred_random.zeroize();
    out1.zeroize();
    Ok(nout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_crypto::hmac_sha256;
    use rsk_crypto::pinproto::{authenticate, encrypt, public_xy};

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    fn scalar(seed: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = seed;
        s[31] = seed;
        s
    }

    const SEED: [u8; 32] = [0x42; 32];
    const CRED_ID: [u8; 80] = [0x55; 80];

    // The platform half: encrypt + MAC the salts under the shared secret.
    fn platform(
        proto: PinProto,
        plat_scalar: &[u8; 32],
        auth_x: &[u8; 32],
        auth_y: &[u8; 32],
        salt: &[u8],
    ) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(proto, plat_scalar, auth_x, auth_y, &mut shared).unwrap();
        let shared = &shared[..slen];
        let iv = [0x33u8; 16];
        let mut enc = [0u8; 16 + 64];
        let ne = encrypt(proto, shared, &iv, salt, &mut enc).unwrap();
        let mut auth = [0u8; 32];
        let na = authenticate(proto, shared, &enc[..ne], &mut auth).unwrap();
        (enc[..ne].to_vec(), auth[..na].to_vec(), shared.to_vec())
    }

    fn roundtrip(proto: PinProto, two_salts: bool) {
        let auth_scalar = scalar(0x11);
        let plat_scalar = scalar(0x22);
        let (ax, ay) = public_xy(&auth_scalar).unwrap();
        let (px, py) = public_xy(&plat_scalar).unwrap();

        let salt64 = [0xA1u8; 64];
        let salt: &[u8] = if two_salts { &salt64 } else { &salt64[..32] };
        let (salt_enc, salt_auth, shared) = platform(proto, &plat_scalar, &ax, &ay, salt);

        let req = HmacSecretReq {
            peer_x: px,
            peer_y: py,
            salt_enc: &salt_enc,
            salt_auth: &salt_auth,
            proto: if proto == PinProto::One { 1 } else { 2 },
            present: true,
        };
        let mut rng = SeqRng(1);
        let mut out = [0u8; 80];
        let nout = eval(
            &req,
            &auth_scalar,
            &SEED,
            &CRED_ID,
            false,
            &mut rng,
            &mut out,
        )
        .unwrap();
        assert_eq!(nout, salt_enc.len());

        // The platform decrypts the output and checks it against its own HMAC.
        let mut dec = [0u8; 64];
        let ndec = pinproto::decrypt(proto, &shared, &out[..nout], &mut dec).unwrap();
        let cr = derive_hmac_key(&SEED, &CRED_ID);
        assert_eq!(&dec[..32], &hmac_sha256(&cr[..32], &salt[..32])[..]);
        if two_salts {
            assert_eq!(ndec, 64);
            assert_eq!(&dec[32..64], &hmac_sha256(&cr[..32], &salt[32..64])[..]);
        } else {
            assert_eq!(ndec, 32);
        }
    }

    #[test]
    fn hmac_secret_roundtrip() {
        for proto in [PinProto::One, PinProto::Two] {
            roundtrip(proto, false);
            roundtrip(proto, true);
        }
    }

    #[test]
    fn uv_half_differs_from_non_uv() {
        let auth_scalar = scalar(0x11);
        let plat_scalar = scalar(0x22);
        let (ax, ay) = public_xy(&auth_scalar).unwrap();
        let (px, py) = public_xy(&plat_scalar).unwrap();
        let salt = [0xA1u8; 32];
        let (salt_enc, salt_auth, shared) = platform(PinProto::Two, &plat_scalar, &ax, &ay, &salt);
        let req = HmacSecretReq {
            peer_x: px,
            peer_y: py,
            salt_enc: &salt_enc,
            salt_auth: &salt_auth,
            proto: 2,
            present: true,
        };
        let mut rng = SeqRng(1);
        let mut decrypt_out = |uv: bool| {
            let mut out = [0u8; 80];
            let n = eval(&req, &auth_scalar, &SEED, &CRED_ID, uv, &mut rng, &mut out).unwrap();
            let mut dec = [0u8; 64];
            pinproto::decrypt(PinProto::Two, &shared, &out[..n], &mut dec).unwrap();
            dec
        };
        let cr = derive_hmac_key(&SEED, &CRED_ID);
        let without = decrypt_out(false);
        let with = decrypt_out(true);
        assert_eq!(&without[..32], &hmac_sha256(&cr[..32], &salt)[..]);
        assert_eq!(&with[..32], &hmac_sha256(&cr[32..], &salt)[..]);
        assert_ne!(&without[..32], &with[..32]);
    }

    #[test]
    fn bad_salt_auth_is_extension_first() {
        let auth_scalar = scalar(0x11);
        let plat_scalar = scalar(0x22);
        let (ax, ay) = public_xy(&auth_scalar).unwrap();
        let (px, py) = public_xy(&plat_scalar).unwrap();
        let salt = [0xA1u8; 32];
        let (salt_enc, mut salt_auth, _shared) =
            platform(PinProto::Two, &plat_scalar, &ax, &ay, &salt);
        salt_auth[0] ^= 0xFF; // corrupt the MAC
        let req = HmacSecretReq {
            peer_x: px,
            peer_y: py,
            salt_enc: &salt_enc,
            salt_auth: &salt_auth,
            proto: 2,
            present: true,
        };
        let mut rng = SeqRng(1);
        let mut out = [0u8; 80];
        assert_eq!(
            eval(
                &req,
                &auth_scalar,
                &SEED,
                &CRED_ID,
                false,
                &mut rng,
                &mut out
            ),
            Err(CtapError::ExtensionFirst)
        );
    }

    #[test]
    fn bad_salt_length_rejected() {
        let auth_scalar = scalar(0x11);
        let req = HmacSecretReq {
            salt_enc: &[0u8; 20], // neither 32 nor 64 (+ v2 IV)
            salt_auth: &[0u8; 32],
            proto: 2,
            present: true,
            ..Default::default()
        };
        let mut rng = SeqRng(1);
        let mut out = [0u8; 80];
        assert_eq!(
            eval(
                &req,
                &auth_scalar,
                &SEED,
                &CRED_ID,
                false,
                &mut rng,
                &mut out
            ),
            Err(CtapError::InvalidLength)
        );
    }
}
