// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! COSE key encoders: the getInfo algorithms-list entries and the credential
//! public keys (EC2 / OKP / AKP) in attestedCredentialData.

use minicbor::Encoder;
use minicbor::encode::{Error, Write};

use crate::consts::{ALG_ECDH_ES_HKDF_256, ALG_ES256, CURVE_P256, KTY_AKP};

/// The `{"alg": alg, "type": "public-key"}` map used in the getInfo algorithms
/// array. `alg` is the negative COSE id (e.g. -7 for ES256).
pub fn cose_public_key<W: Write>(enc: &mut Encoder<W>, alg: i64) -> Result<(), Error<W::Error>> {
    enc.map(2)?
        .str("alg")?
        .i64(alg)?
        .str("type")?
        .str("public-key")?;
    Ok(())
}

/// EC2 public key with a given curve and field-length coordinates:
/// `{1: 2, 3: alg, -1: crv, -2: x, -3: y}` in CTAP canonical order.
/// `x`/`y` are big-endian, left-padded to the curve's field size (32/48/66).
pub fn cose_key_ec2_var<W: Write>(
    enc: &mut Encoder<W>,
    alg: i64,
    crv: u8,
    x: &[u8],
    y: &[u8],
) -> Result<(), Error<W::Error>> {
    enc.map(5)?
        .u8(1)?
        .u8(2)? // kty: EC2
        .u8(3)?
        .i64(alg)?
        .i8(-1)?
        .u8(crv)?
        .i8(-2)?
        .bytes(x)? // x coordinate
        .i8(-3)?
        .bytes(y)?; // y coordinate
    Ok(())
}

/// AKP (Algorithm Key Pair) public key — ML-DSA: `{1: 7, 3: alg, -1: pub}` in
/// CTAP canonical order. AKP keys carry no curve; the algorithm id alone fixes
/// the parameter set, and `pub` is the serialized FIPS 204 public key
/// (1312 bytes for ML-DSA-44).
pub fn cose_key_akp<W: Write>(
    enc: &mut Encoder<W>,
    alg: i64,
    pubkey: &[u8],
) -> Result<(), Error<W::Error>> {
    enc.map(3)?
        .u8(1)?
        .u8(KTY_AKP)?
        .u8(3)?
        .i64(alg)?
        .i8(-1)?
        .bytes(pubkey)?;
    Ok(())
}

/// OKP public key (Ed25519): `{1: 1, 3: alg, -1: crv, -2: x}` — kty OKP, the
/// 32-byte compressed point as `x`, no `y`.
pub fn cose_key_okp_var<W: Write>(
    enc: &mut Encoder<W>,
    alg: i64,
    crv: u8,
    x: &[u8],
) -> Result<(), Error<W::Error>> {
    enc.map(4)?
        .u8(1)?
        .u8(1)? // kty: OKP
        .u8(3)?
        .i64(alg)?
        .i8(-1)?
        .u8(crv)?
        .i8(-2)?
        .bytes(x)?;
    Ok(())
}

/// EC2 P-256 helper for the fixed-32-byte coordinate callers (ES256 / ECDH).
fn cose_key_ec2<W: Write>(
    enc: &mut Encoder<W>,
    alg: i64,
    x: &[u8; 32],
    y: &[u8; 32],
) -> Result<(), Error<W::Error>> {
    cose_key_ec2_var(enc, alg, CURVE_P256, x, y)
}

/// EC2 ES256 (P-256) public key — the credential public key in
/// attestedCredentialData.
pub fn cose_key_es256<W: Write>(
    enc: &mut Encoder<W>,
    x: &[u8; 32],
    y: &[u8; 32],
) -> Result<(), Error<W::Error>> {
    cose_key_ec2(enc, ALG_ES256, x, y)
}

/// The authenticator's ECDH key-agreement public key returned by clientPIN
/// `getKeyAgreement` (alg = ECDH-ES + HKDF-256).
pub fn cose_key_ecdh<W: Write>(
    enc: &mut Encoder<W>,
    x: &[u8; 32],
    y: &[u8; 32],
) -> Result<(), Error<W::Error>> {
    cose_key_ec2(enc, ALG_ECDH_ES_HKDF_256, x, y)
}
