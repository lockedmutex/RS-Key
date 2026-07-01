// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `apply_block(encode()) == id` for every well-formed config (color is the
/// only constrained field: it is a 3-bit palette index by construction).
#[kani::proof]
fn encode_apply_block_roundtrip() {
    let any_status = || StatusCfg {
        effect: kani::any(),
        color: kani::any::<u8>() & 0x7,
        brightness: kani::any(),
        speed: kani::any(),
    };
    let cfg = LedConfig {
        steady: kani::any(),
        status: [any_status(), any_status(), any_status(), any_status()],
    };
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}
