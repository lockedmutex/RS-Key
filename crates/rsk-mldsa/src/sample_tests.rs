// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn coeff_from_three_bytes_vectors() {
    assert_eq!(
        coeff_from_three_bytes([0x12, 0x34, 0x56]),
        Some(0x0056_3412)
    );
    assert_eq!(
        coeff_from_three_bytes([0x12, 0x34, 0x80]),
        Some(0x0000_3412)
    ); // top bit cleared
    assert_eq!(
        coeff_from_three_bytes([0x01, 0xe0, 0x80]),
        Some(0x0000_e001)
    );
    assert_eq!(coeff_from_three_bytes([0x01, 0xe0, 0x7f]), None); // == q, rejected
}

#[test]
fn coeff_from_half_byte_vectors() {
    assert_eq!(coeff_from_half_byte(2, 3), Some(-1));
    assert_eq!(coeff_from_half_byte(4, 8), Some(-4));
    assert_eq!(coeff_from_half_byte(2, 15), None);
    assert_eq!(coeff_from_half_byte(4, 10), None);
    // The Barrett mod-5 must agree with a plain remainder over the whole domain.
    for b in 0..15u8 {
        assert_eq!(coeff_from_half_byte(2, b), Some(2 - (i32::from(b) % 5)));
    }
    for b in 0..9u8 {
        assert_eq!(coeff_from_half_byte(4, b), Some(4 - i32::from(b)));
    }
}

#[test]
fn sample_in_ball_weight_and_range() {
    for tau in [39, 49] {
        let mut c_tilde = vec![0u8; 64];
        c_tilde[0] = tau as u8;
        c_tilde[5] = 0xAB;
        c_tilde[30] = 0x5C;
        let c = sample_in_ball(tau, &c_tilde);
        let weight = c.0.iter().filter(|&&x| x != 0).count();
        assert_eq!(weight, tau as usize, "Hamming weight must be tau");
        assert!(
            c.0.iter().all(|&x| (-1..=1).contains(&x)),
            "coeffs in {{-1,0,1}}"
        );
    }
}
