// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CCID secure PIN entry (PC/SC v2 Part 10 `PIN_VERIFY`): the host-tested,
//! HAL-free byte logic for the on-device pinpad. When a host driver drives a
//! pinpad reader it sends a `PC_to_RDR_Secure` (0x69) whose payload is the CCID
//! `abPINDataStructure` for VERIFY — a fixed prefix followed by a VERIFY APDU
//! *template* with no PIN. The device collects the PIN on its own trusted screen
//! and builds the real VERIFY APDU itself, so the secret never crosses USB.
//!
//! This module only parses the structure and assembles the VERIFY APDU; the
//! firmware glue (`ccid_handler`/`worker`) does the on-screen collection and runs
//! the assembled APDU through the applet dispatcher. The host-controlled bytes are
//! treated as untrusted: every field is bounds-checked with `get`, the format/
//! offset bits are deliberately ignored, and the APDU is built from our own
//! buffers — so a crafted structure can never index out of bounds.
//!
//! Layout (CCID 1.1 `abPINDataStructure` for VERIFY, little-endian):
//!
//! ```text
//! 0    bPINOperation        (0x00 = verify)
//! 1    bTimeOut
//! 2    bmFormatString       (bits[1:0] PIN type: 0 binary, 1 BCD, 2 ASCII)
//! 3    bmPINBlockString
//! 4    bmPINLengthFormat
//! 5..7 wPINMaxExtraDigit
//! 7    bEntryValidationCondition
//! 8    bNumberMessage
//! 9..11 wLangId
//! 11   bMsgIndex
//! 12..15 bTeoPrologue
//! 15.. abPINApdu            (CLA INS P1 P2 [Lc] [data]) — the VERIFY template
//! ```

/// ISO-7816 VERIFY instruction.
pub const INS_VERIFY: u8 = 0x20;
/// PIV application-PIN reference (`P2`); PIV pads the PIN with `0xFF` to 8 bytes.
pub const PIV_PIN_P2: u8 = 0x80;
/// PIV's fixed on-wire PIN block length (SP 800-73): ASCII digits, `0xFF`-padded.
pub const PIV_PIN_LEN: usize = 8;
/// PIV PIN padding filler.
pub const PIV_PAD: u8 = 0xFF;
/// Offset of the VERIFY APDU template within the `abPINDataStructure`.
pub const APDU_TEMPLATE_OFFSET: usize = 15;
/// Longest PIN we accept (OpenPGP allows up to 127; PIV is capped at 8 by `assemble_verify`).
pub const MAX_PIN: usize = 127;

/// The parsed parts of a secure-PIN request the firmware needs: the operation
/// (only `0x00` verify is supported), whether the PIN is ASCII, and the bare
/// VERIFY APDU template (`CLA INS P1 P2 …`). All other fields are ignored on
/// purpose (we build the APDU body ourselves).
pub struct SecurePinReq<'a> {
    pub operation: u8,
    pub ascii: bool,
    pub apdu_template: &'a [u8],
}

/// Parse a `PC_to_RDR_Secure` `abPINDataStructure`. Returns `None` if it is too
/// short to hold the fixed prefix plus a 4-byte APDU header — never panics on
/// host-controlled input.
pub fn parse_secure(abdata: &[u8]) -> Option<SecurePinReq<'_>> {
    let operation = *abdata.first()?;
    let format = *abdata.get(2)?;
    let apdu_template = abdata.get(APDU_TEMPLATE_OFFSET..)?;
    if apdu_template.len() < 4 {
        return None;
    }
    // bmFormatString bits[1:0] = PIN type (0 binary, 1 BCD, 2 ASCII); gpg/OpenSC
    // both send ASCII (0x82). Informational here — the pad only ever types ASCII
    // digits, so `assemble_verify` builds an ASCII body regardless.
    Some(SecurePinReq {
        operation,
        ascii: (format & 0x03) == 0x02,
        apdu_template,
    })
}

/// Build a plaintext VERIFY APDU from the secure-PIN `template` (its `CLA INS P1
/// P2`) and the ASCII digits the user typed on the panel. PIV (`P2 == 0x80`) is
/// `0xFF`-padded to 8 bytes; OpenPGP (`P2` in `0x81..=0x83`, and any other
/// reference) is variable-length. Returns the assembled APDU length in `out`, or
/// `None` for a non-VERIFY template, an over-length PIV PIN, or a short buffer.
pub fn assemble_verify(template: &[u8], pin: &[u8], out: &mut [u8]) -> Option<usize> {
    let cla = *template.first()?;
    let ins = *template.get(1)?;
    let p1 = *template.get(2)?;
    let p2 = *template.get(3)?;
    if ins != INS_VERIFY {
        return None;
    }
    let piv = p2 == PIV_PIN_P2;
    let body_len = if piv { PIV_PIN_LEN } else { pin.len() };
    if pin.len() > body_len || body_len > MAX_PIN || 5 + body_len > out.len() {
        return None;
    }
    out[0] = cla;
    out[1] = ins;
    out[2] = p1;
    out[3] = p2;
    out[4] = body_len as u8; // Lc
    out[5..5 + pin.len()].copy_from_slice(pin);
    if piv {
        out[5 + pin.len()..5 + body_len].fill(PIV_PAD);
    }
    Some(5 + body_len)
}

/// Kani proof harnesses (`cargo kani -p rsk-usb`): exhaustive over every input up
/// to the stated bound, where the unit tests only sample. The host bytes here are
/// attacker-controlled (a crafted `PC_to_RDR_Secure`), so totality + OOB-safety
/// matter: the PIN the user typed is written into `out` beside a host template.
#[cfg(kani)]
#[path = "secure_pin_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "secure_pin_tests.rs"]
mod tests;
