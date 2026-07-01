// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn default_firmware_version_is_5_7_4() {
    // The default build must keep masquerading as a current YubiKey 5; an
    // override (FW_VERSION=…) is the only thing that changes this.
    assert_eq!(FIRMWARE_VERSION, (5, 7, 4));
    assert_eq!(FIRMWARE_VERSION_U32, 0x05_07_04);
}
