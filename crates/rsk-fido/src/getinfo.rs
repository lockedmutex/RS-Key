// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorGetInfo`: advertise the implemented surface — versions,
//! extensions, options, algorithms and limits. ML-DSA-44 is deliberately NOT in
//! `algorithms` (0x0A) by default: shipped Firefoxes (authenticator-rs before
//! 2026-06-02) hard-fail the whole getInfo parse on an unknown COSE id, while
//! makeCredential still negotiates -48 from the request's `pubKeyCredParams`;
//! the `advertise-pqc` feature opts back into the advertisement.

use minicbor::Encoder;
use minicbor::encode::{Error, Write};

use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_MLDSA44, FIRMWARE_VERSION,
    MAX_CRED_ID_LENGTH, MAX_CREDBLOB_LENGTH, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_LARGE_BLOB_SIZE,
    MAX_MSG_SIZE,
};
use crate::cose::cose_public_key;
use crate::error::{CtapError, CtapResult};

/// Encode the getInfo response map into `out`; returns the byte length.
/// `pin_set` reflects whether a PIN is configured (`options.clientPin`);
/// `min_pin_len` / `force_change` mirror EF_MINPINLEN (0x0D / 0x0C);
/// `ea_enabled` is the enterprise-attestation state (`options.ep`).
pub fn get_info(
    pin_set: bool,
    min_pin_len: u8,
    force_change: bool,
    ea_enabled: bool,
    out: &mut [u8],
) -> CtapResult {
    let mut enc = Encoder::new(minicbor::encode::write::Cursor::new(out));
    write_info(&mut enc, pin_set, min_pin_len, force_change, ea_enabled)
        .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

fn write_info<W: Write>(
    enc: &mut Encoder<W>,
    pin_set: bool,
    min_pin_len: u8,
    force_change: bool,
    ea_enabled: bool,
) -> Result<(), Error<W::Error>> {
    // Keys are ascending uints → CTAP canonical order.
    enc.map(14)?;

    // 0x01 versions
    enc.u8(0x01)?.array(2)?.str("U2F_V2")?.str("FIDO_2_0")?;

    // 0x02 extensions
    enc.u8(0x02)?
        .array(7)?
        .str("credBlob")?
        .str("credProtect")?
        .str("hmac-secret")?
        .str("largeBlobKey")?
        .str("minPinLength")?
        .str("hmac-secret-mc")?
        .str("thirdPartyPayment")?;

    // 0x03 aaguid
    enc.u8(0x03)?.bytes(&AAGUID)?;

    // 0x04 options — text keys in canonical order (length, then bytewise).
    // "ep" (enterprise attestation enabled) sorts first among the 2-char keys.
    enc.u8(0x04)?
        .map(9)?
        .str("ep")?
        .bool(ea_enabled)?
        .str("rk")?
        .bool(true)?
        .str("up")?
        .bool(true)?
        .str("credMgmt")?
        .bool(true)?
        .str("authnrCfg")?
        .bool(true)?
        .str("clientPin")?
        .bool(pin_set)?
        .str("largeBlobs")?
        .bool(true)?
        .str("pinUvAuthToken")?
        .bool(true)?
        .str("setMinPINLength")?
        .bool(true)?;

    // 0x05 maxMsgSize
    enc.u8(0x05)?.u64(MAX_MSG_SIZE)?;

    // 0x06 pinUvAuthProtocols (protocol two preferred, then one).
    enc.u8(0x06)?.array(2)?.u8(2)?.u8(1)?;

    // 0x07 maxCredentialCountInList
    enc.u8(0x07)?.u64(MAX_CREDENTIAL_COUNT_IN_LIST)?;

    // 0x08 maxCredentialIdLength
    enc.u8(0x08)?.u64(MAX_CRED_ID_LENGTH)?;

    // 0x0A algorithms — the classic list (ES256, EdDSA, ES384, ES512, ES256K);
    // `advertise-pqc` prepends ML-DSA-44. Off by default: shipped Firefoxes
    // reject the whole getInfo on an unknown COSE id (see module docs).
    let pqc = cfg!(feature = "advertise-pqc");
    enc.u8(0x0A)?.array(5 + u64::from(pqc))?;
    if pqc {
        cose_public_key(enc, ALG_MLDSA44)?;
    }
    cose_public_key(enc, ALG_ES256)?;
    cose_public_key(enc, ALG_EDDSA)?;
    cose_public_key(enc, ALG_ES384)?;
    cose_public_key(enc, ALG_ES512)?;
    cose_public_key(enc, ALG_ES256K)?;

    // 0x0B maxSerializedLargeBlobArray
    enc.u8(0x0B)?.u64(MAX_LARGE_BLOB_SIZE as u64)?;

    // 0x0C forceChangePin (EF_MINPINLEN[1]); enforced at token issuance (clientpin).
    enc.u8(0x0C)?.bool(force_change)?;

    // 0x0D minPINLength (EF_MINPINLEN[0], default MIN_PIN_LENGTH)
    enc.u8(0x0D)?.u8(min_pin_len)?;

    // 0x0E firmwareVersion
    enc.u8(0x0E)?.u32(FIRMWARE_VERSION)?;

    // 0x0F maxCredBlobLength
    enc.u8(0x0F)?.u64(MAX_CREDBLOB_LENGTH as u64)?;

    // 0x15 (vendorPrototypeConfigCommands) is never advertised; a real YubiKey
    // hides it too, so the default Yubikey5 VID/PID stays consistent.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minicbor::Decoder;

    #[test]
    fn get_info_fields() {
        let mut buf = [0u8; 512];
        let n = get_info(true, 4, false, false, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);

        let entries = d.map().unwrap().unwrap();
        assert_eq!(entries, 14);

        // 0x01 versions
        assert_eq!(d.u8().unwrap(), 0x01);
        let nv = d.array().unwrap().unwrap();
        assert_eq!(nv, 2);
        assert_eq!(d.str().unwrap(), "U2F_V2");
        assert_eq!(d.str().unwrap(), "FIDO_2_0");

        // 0x02 extensions
        assert_eq!(d.u8().unwrap(), 0x02);
        assert_eq!(d.array().unwrap().unwrap(), 7);
        assert_eq!(d.str().unwrap(), "credBlob");
        assert_eq!(d.str().unwrap(), "credProtect");
        assert_eq!(d.str().unwrap(), "hmac-secret");
        assert_eq!(d.str().unwrap(), "largeBlobKey");
        assert_eq!(d.str().unwrap(), "minPinLength");
        assert_eq!(d.str().unwrap(), "hmac-secret-mc");
        assert_eq!(d.str().unwrap(), "thirdPartyPayment");

        // 0x03 aaguid
        assert_eq!(d.u8().unwrap(), 0x03);
        assert_eq!(d.bytes().unwrap(), &AAGUID);

        // 0x04 options — ep (EA disabled here), rk, up, credMgmt, authnrCfg,
        // clientPin (PIN set → true), largeBlobs, pinUvAuthToken, setMinPINLength
        // (canonical: length then bytewise).
        assert_eq!(d.u8().unwrap(), 0x04);
        assert_eq!(d.map().unwrap().unwrap(), 9);
        assert_eq!(d.str().unwrap(), "ep");
        assert!(!d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "rk");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "up");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "credMgmt");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "authnrCfg");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "clientPin");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "largeBlobs");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "pinUvAuthToken");
        assert!(d.bool().unwrap());
        assert_eq!(d.str().unwrap(), "setMinPINLength");
        assert!(d.bool().unwrap());

        // 0x05 maxMsgSize
        assert_eq!(d.u8().unwrap(), 0x05);
        assert_eq!(d.u64().unwrap(), MAX_MSG_SIZE);

        // 0x06 pinUvAuthProtocols [2, 1]
        assert_eq!(d.u8().unwrap(), 0x06);
        assert_eq!(d.array().unwrap().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 2);
        assert_eq!(d.u8().unwrap(), 1);

        // 0x07 maxCredentialCountInList
        assert_eq!(d.u8().unwrap(), 0x07);
        assert_eq!(d.u64().unwrap(), MAX_CREDENTIAL_COUNT_IN_LIST);

        // 0x08 maxCredentialIdLength
        assert_eq!(d.u8().unwrap(), 0x08);
        assert_eq!(d.u64().unwrap(), MAX_CRED_ID_LENGTH);

        // 0x0A algorithms: [{alg, type:"public-key"} …] — classic ids; the
        // `advertise-pqc` feature prepends ML-DSA-44 (default stays without it:
        // Firefox authenticator-rs strict parse).
        assert_eq!(d.u8().unwrap(), 0x0A);
        let pqc = cfg!(feature = "advertise-pqc");
        assert_eq!(d.array().unwrap().unwrap(), 5 + u64::from(pqc));
        let mut algs = vec![];
        if pqc {
            algs.push(ALG_MLDSA44);
        }
        algs.extend([ALG_ES256, ALG_EDDSA, ALG_ES384, ALG_ES512, ALG_ES256K]);
        for alg in algs {
            assert_eq!(d.map().unwrap().unwrap(), 2);
            assert_eq!(d.str().unwrap(), "alg");
            assert_eq!(d.i64().unwrap(), alg);
            assert_eq!(d.str().unwrap(), "type");
            assert_eq!(d.str().unwrap(), "public-key");
        }

        // 0x0B maxSerializedLargeBlobArray
        assert_eq!(d.u8().unwrap(), 0x0B);
        assert_eq!(d.u64().unwrap(), MAX_LARGE_BLOB_SIZE as u64);

        // 0x0C forceChangePin, 0x0D minPINLength
        assert_eq!(d.u8().unwrap(), 0x0C);
        assert!(!d.bool().unwrap());
        assert_eq!(d.u8().unwrap(), 0x0D);
        assert_eq!(d.u8().unwrap(), 4);

        // 0x0E firmwareVersion
        assert_eq!(d.u8().unwrap(), 0x0E);
        assert_eq!(d.u32().unwrap(), FIRMWARE_VERSION);

        // 0x0F maxCredBlobLength
        assert_eq!(d.u8().unwrap(), 0x0F);
        assert_eq!(d.u64().unwrap(), MAX_CREDBLOB_LENGTH as u64);

        // Map fully consumed.
        assert!(d.datatype().is_err());
    }

    #[test]
    fn client_pin_reflects_pin_state() {
        // options.clientPin is false before a PIN is set, true after.
        let mut buf = [0u8; 512];
        for pin_set in [false, true] {
            let n = get_info(pin_set, 4, false, false, &mut buf).unwrap();
            let mut d = Decoder::new(&buf[..n]);
            d.map().unwrap();
            // skip to 0x04 options.
            assert_eq!(d.u8().unwrap(), 0x01);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 0x02);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 0x03);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 0x04);
            d.map().unwrap();
            d.str().unwrap();
            d.bool().unwrap(); // ep
            d.str().unwrap();
            d.bool().unwrap(); // rk
            d.str().unwrap();
            d.bool().unwrap(); // up
            d.str().unwrap();
            d.bool().unwrap(); // credMgmt
            d.str().unwrap();
            d.bool().unwrap(); // authnrCfg
            assert_eq!(d.str().unwrap(), "clientPin");
            assert_eq!(d.bool().unwrap(), pin_set);
        }
    }

    #[test]
    fn min_pin_policy_reflected() {
        // 0x0D mirrors minPINLength, 0x0C the forceChangePin flag.
        let mut buf = [0u8; 512];
        let n = get_info(true, 8, true, false, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        let (mut force, mut min) = (None, None);
        while let Ok(key) = d.u8() {
            match key {
                0x0C => force = Some(d.bool().unwrap()),
                0x0D => min = Some(d.u8().unwrap()),
                _ => d.skip().unwrap(),
            }
        }
        assert_eq!(force, Some(true));
        assert_eq!(min, Some(8));
    }

    #[test]
    fn get_info_buffer_too_small() {
        let mut tiny = [0u8; 8];
        assert_eq!(
            get_info(false, 4, false, false, &mut tiny),
            Err(CtapError::Other)
        );
    }
}
