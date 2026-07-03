// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn sample() -> LedConfig {
    LedConfig {
        steady: true,
        status: [
            StatusCfg {
                effect: 1,
                color: 2,
                brightness: 16,
                speed: 0,
            },
            StatusCfg {
                effect: 3,
                color: 2,
                brightness: 32,
                speed: 5,
            },
            StatusCfg {
                effect: 2,
                color: 4,
                brightness: 64,
                speed: 0,
            },
            StatusCfg {
                effect: 4,
                color: 1,
                brightness: 8,
                speed: 200,
            },
        ],
    }
}

#[test]
fn conf_len_matches_layout() {
    assert_eq!(CONF_LEN, 17);
    assert_eq!(CONF_LEN, 1 + 4 * N_STATUS);
}

#[test]
fn encode_decode_roundtrip() {
    let cfg = sample();
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}

#[test]
fn encode_layout_is_steady_then_quads() {
    let b = sample().encode();
    assert_eq!(b.len(), 17);
    assert_eq!(b[0], 1); // steady
    // touch (status index 2): effect, color, brightness, speed at 1+4*2 = 9..13
    assert_eq!(&b[9..13], &[2, 4, 64, 0]);
}

#[test]
fn color_is_masked_to_low_three_bits() {
    let mut cfg = LedConfig::default();
    let mut b = [0u8; CONF_LEN];
    b[2] = 0xFA; // idle color slot; 0xFA & 0x7 == 2
    cfg.apply_block(&b);
    assert_eq!(cfg.status[0].color, 0x2);
    // and encode re-masks rather than leaking high bits
    cfg.status[1].color = 0xFF;
    // status 1 (processing) color byte sits at index 2 + 4 = 6
    assert_eq!(cfg.encode()[6], 0x7);
}

#[test]
fn pre_speed_13_byte_block_keeps_current_speed() {
    let mut cfg = sample(); // speeds 0, 5, 0, 200
    let mut b = [0u8; 13]; // [steady, (effect, color, brightness) × 4]
    b[0] = 0;
    for i in 0..N_STATUS {
        b[1 + 3 * i] = 0; // effect legacy
        b[2 + 3 * i] = 1; // color red
        b[3 + 3 * i] = 100; // brightness
    }
    cfg.apply_block(&b);
    assert!(!cfg.steady);
    for s in &cfg.status {
        assert_eq!((s.effect, s.color, s.brightness), (0, 1, 100));
    }
    assert_eq!(cfg.status[1].speed, 5); // preserved
    assert_eq!(cfg.status[3].speed, 200); // preserved
}

#[test]
fn pre_effect_9_byte_block_keeps_current_effect_and_speed() {
    let mut cfg = sample(); // effects 1,3,2,4 ; speeds 0,5,0,200
    let mut b = [0u8; 9]; // [steady, (color, brightness) × 4]
    b[0] = 1;
    for i in 0..N_STATUS {
        b[1 + 2 * i] = 3; // color blue
        b[2 + 2 * i] = 50; // brightness
    }
    cfg.apply_block(&b);
    assert!(cfg.steady);
    for s in &cfg.status {
        assert_eq!((s.color, s.brightness), (3, 50));
    }
    assert_eq!(cfg.status[0].effect, 1); // preserved
    assert_eq!(cfg.status[3].effect, 4); // preserved
    assert_eq!(cfg.status[3].speed, 200); // preserved
}

#[test]
fn legacy_2_byte_block_maps_onto_idle_only() {
    let mut cfg = sample();
    let processing_before = cfg.status[1];
    cfg.apply_block(&[80, 0x0C]); // brightness 80, color 0x0C & 7 = 4 onto idle
    assert_eq!(cfg.status[0].brightness, 80);
    assert_eq!(cfg.status[0].color, 4);
    assert_eq!(cfg.status[1], processing_before); // others untouched
}

#[test]
fn legacy_3_byte_block_sets_steady() {
    let mut cfg = LedConfig::default();
    cfg.apply_block(&[10, 2, 1]);
    assert!(cfg.steady);
    assert_eq!((cfg.status[0].brightness, cfg.status[0].color), (10, 2));
}

#[test]
fn too_short_block_is_ignored() {
    let mut cfg = sample();
    let before = cfg;
    cfg.apply_block(&[]);
    cfg.apply_block(&[7]);
    assert_eq!(cfg, before);
}

#[test]
fn block_longer_than_conf_len_reads_the_known_prefix() {
    // A future, longer block still loads its first 17 bytes (the >= branch).
    let cfg = sample();
    let mut b = [0u8; 21];
    b[..CONF_LEN].copy_from_slice(&cfg.encode());
    let mut got = LedConfig::default();
    got.apply_block(&b);
    assert_eq!(got, cfg);
}

#[test]
fn clamp_leds_saturates_to_ceiling() {
    assert_eq!(clamp_leds(4, 8), 4);
    assert_eq!(clamp_leds(8, 8), 8);
    assert_eq!(clamp_leds(99, 8), 8); // the brick-fix invariant: no panic, saturate
    assert_eq!(clamp_leds(0, 8), 0);
}
