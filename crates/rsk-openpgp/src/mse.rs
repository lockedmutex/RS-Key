// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! MANAGE SECURITY ENVIRONMENT (INS 0x22): repoints the key slot the next
//! DECIPHER (`P2 = 0xA4`) or INTERNAL AUTHENTICATE (`P2 = 0xB8`) uses at the
//! DEC (ref 2) or AUT (ref 3) slot, until the next deselect ([`Session::reset`]).

use rsk_sdk::{Apdu, Sw};

use crate::consts::*;
use crate::pin::Session;

/// MANAGE SECURITY ENVIRONMENT (INS 0x22).
pub fn mse(sess: &mut Session, apdu: &Apdu) -> Sw {
    if apdu.p1 != 0x41 || (apdu.p2 != 0xA4 && apdu.p2 != 0xB8) {
        return Sw::WRONG_P1P2;
    }
    let d = apdu.data;
    // CRT `83 01 <02|03>` — a key-reference template; a short field is wrong data.
    if d.len() < 3 || d[0] != 0x83 || d[1] != 0x01 || (d[2] != 0x02 && d[2] != 0x03) {
        return Sw::INCORRECT_PARAMS; // 0x6A80 (wrong data)
    }
    let (algo, pk) = if d[2] == 0x02 {
        (EF_ALGO_PRIV2, EF_PK_DEC)
    } else {
        (EF_ALGO_PRIV3, EF_PK_AUT)
    };
    if apdu.p2 == 0xA4 {
        sess.algo_dec = algo;
        sess.pk_dec = pk;
    } else {
        sess.algo_aut = algo;
        sess.pk_aut = pk;
    }
    Sw::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apdu(p1: u8, p2: u8, data: &[u8]) -> Apdu<'_> {
        Apdu {
            cla: 0x00,
            ins: INS_MSE,
            p1,
            p2,
            nc: data.len(),
            ne: 0,
            data,
        }
    }

    #[test]
    fn mse_dec_template_repoints_dec_slot() {
        let mut s = Session::new();
        // Default DEC slot.
        assert_eq!(s.pk_dec, EF_PK_DEC);
        assert_eq!(s.algo_dec, EF_ALGO_PRIV2);
        // P2=0xA4 (DEC), ref 3 → point DEC at the AUT slot.
        assert_eq!(mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x03])), Sw::OK);
        assert_eq!(s.pk_dec, EF_PK_AUT);
        assert_eq!(s.algo_dec, EF_ALGO_PRIV3);
        // AUT slot untouched.
        assert_eq!(s.pk_aut, EF_PK_AUT);
    }

    #[test]
    fn mse_aut_template_repoints_aut_slot() {
        let mut s = Session::new();
        // P2=0xB8 (AUT), ref 2 → point AUT at the DEC slot.
        assert_eq!(mse(&mut s, &apdu(0x41, 0xB8, &[0x83, 0x01, 0x02])), Sw::OK);
        assert_eq!(s.pk_aut, EF_PK_DEC);
        assert_eq!(s.algo_aut, EF_ALGO_PRIV2);
        assert_eq!(s.pk_dec, EF_PK_DEC); // DEC untouched
    }

    #[test]
    fn uif_follows_the_repointed_slot() {
        // The core of #100: after MSE cross-wires DEC → the AUT key, a DECIPHER
        // must enforce the AUT slot's touch policy (EF_UIF_AUT), not DEC's.
        let mut s = Session::new();
        assert_eq!(slot_uif(s.pk_dec), EF_UIF_DEC);
        mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x03])); // DEC → AUT
        assert_eq!(slot_uif(s.pk_dec), EF_UIF_AUT);
        // Symmetrically for AUT → DEC, and SIG always maps to its own UIF.
        mse(&mut s, &apdu(0x41, 0xB8, &[0x83, 0x01, 0x02])); // AUT → DEC
        assert_eq!(slot_uif(s.pk_aut), EF_UIF_DEC);
        assert_eq!(slot_uif(EF_PK_SIG), EF_UIF_SIG);
    }

    #[test]
    fn mse_reset_restores_defaults() {
        let mut s = Session::new();
        mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x03]));
        s.reset();
        assert_eq!(s.pk_dec, EF_PK_DEC);
        assert_eq!(s.algo_dec, EF_ALGO_PRIV2);
        assert_eq!(s.pk_aut, EF_PK_AUT);
        assert_eq!(s.algo_aut, EF_ALGO_PRIV3);
    }

    #[test]
    fn mse_rejects_bad_p1p2_and_data() {
        let mut s = Session::new();
        assert_eq!(
            mse(&mut s, &apdu(0x00, 0xA4, &[0x83, 0x01, 0x02])),
            Sw::WRONG_P1P2
        );
        assert_eq!(
            mse(&mut s, &apdu(0x41, 0x00, &[0x83, 0x01, 0x02])),
            Sw::WRONG_P1P2
        );
        assert_eq!(
            mse(&mut s, &apdu(0x41, 0xA4, &[0x82, 0x01, 0x02])),
            Sw::INCORRECT_PARAMS
        );
        assert_eq!(
            mse(&mut s, &apdu(0x41, 0xA4, &[0x83, 0x01, 0x04])),
            Sw::INCORRECT_PARAMS
        );
        assert_eq!(
            mse(&mut s, &apdu(0x41, 0xA4, &[0x83])),
            Sw::INCORRECT_PARAMS
        );
    }
}
