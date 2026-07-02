<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Changelog

All notable changes to RS-Key are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and **releases** are
versioned with [SemVer](https://semver.org/).

Two other version numbers live in the firmware and are deliberately **not** this
tag: the USB `bcdDevice` build counter (bumped on every behavior change), and
`FW_VERSION` — the YubiKey-compatibility version reported to host tools (5.7.4).

## [Unreleased]

### Added

- **Firmware flash-size budget in the gate.** `check.sh` fails if the shipping
  image exceeds a soft ceiling (1 MiB of the 2560K code region) — a runaway
  dependency trips it long before the linker's hard limit. Bump
  `FIRMWARE_FLASH_BUDGET_KIB` intentionally for a legitimate feature.
- **Host-crate coverage floor.** `deep-checks` gained an `llvm-cov` job that
  floors host-crate line coverage (a regression alarm; the embedded image is
  not host-measurable).
- **`scripts/metrics.sh`** — advisory refactor reconnaissance (function
  complexity, firmware size, generic monomorphization). Not a gate; the tools
  are pulled ad-hoc so they never join the pinned dev shell.

### Changed

- **`deep-checks` runs daily** rather than weekly (Miri, fuzz, Kani, repro,
  coverage).

## [0.3.0] — 2026-07-03

### Added

- **Trusted-display build (experimental, opt-in).** A screen-and-touch RS-Key
  variant for the Waveshare RP2350-Touch-LCD-2.8, behind the `display` cargo
  feature (`firmware-display` nix flavor). The screen turns the key into a
  *trusted display* — the operations that matter happen on the device's own glass,
  not on the host:
  - **Approve / Deny** paints the *real* relying party for every touch-gated
    operation, so a signature can't be produced without a physical tap on a screen
    showing the true `rpId` (refuse → `OPERATION_DENIED`); a registration shows a
    *Save new passkey?* card. A look-alike id too long for the box is clipped with
    a truncation marker so its prefix can't masquerade.
  - **On-screen PIN entry** — built-in user verification (getInfo `options.uv`; a
    `pinUvAuthToken` minted from the on-screen pad against the same `EF_PIN`), and
    a CCID **pinpad** (`bPINSupport` / `PC_to_RDR_Secure`) so GnuPG and OpenSC
    collect the OpenPGP / PIV PIN on the panel — the PIN never crosses USB. Every
    PIN screen names which credential it collects, an eye toggle reveals the
    digits, and "N tries remaining" is shown up front.
  - A dedicated **device PIN** (separate from the FIDO clientPIN) gating the
    on-device UI, with **lock / unlock**, display **sleep** (image-retention
    guard + wake button), and set / change PIN on the panel.
  - **Passkeys** — browse resident credentials, **rename** (a device-local
    nickname that never re-seals the box) and **delete** on-device.
  - **Apps** — a read-only browser of OpenPGP / PIV / OATH state (no PIN, no
    secret, no OATH code — the device has no clock), plus on-device **PIV key
    generation** (EC P-256/P-384, Ed25519, X25519, RSA 2048/3072/4096) into empty
    retired slots.
  - **Settings** — device & FIDO PINs; a PIV PIN / PUK / unblock / **protect
    management key** (ykman `--protect`) sub-menu; on-screen **BIP-39 / SLIP-39
    recovery** export (derived on-device, never over USB) and backup-window status;
    an **audit log**; **factory reset**; a **Firmware** screen that reboots to
    BOOTSEL for an over-USB update; and live brightness / display-sleep /
    touch-timeout that persist across reboots.
  - A standard **screenless key compiles none of it** — the whole UI stack
    (`rsk-ui`, `embedded-graphics`, `u8g2-fonts`) is `dep:`-gated and the build
    asserts it absent from the default image, so an ordinary build is
    byte-for-byte unaffected. The UI model, geometry and glyphs live in the
    host-tested + Kani-proved `rsk-ui` crate. See
    [`docs/guides/display.md`](docs/guides/display.md). Built up across bcdDevice
    `0x0784`–`0x07D5`.

- **PIV: RSA-3072 and RSA-4096 keys.** Generate, import, sign / decrypt,
  attestation and metadata gained RSA-3072/4096 (the applet buffers were lifted
  off their RSA-2048 ceiling); on a display build the on-device **Generate key**
  chooser offers RSA via a 2048 / 3072 / 4096 sub-picker. RSA-1024 stays disabled.
  bcdDevice `0x07C4` → `0x07C6`.

- **PIV: Ed25519 and X25519 keys** (algorithm ids `0xE0` / `0xE1`, Yubico 5.7
  PIV). Generate (Ed25519 with an RFC 8410 self-signed cert; X25519 is
  key-agreement-only), import (raw seed / scalar, yubikit tags `0x07` / `0x08`),
  sign / key-agree, metadata and attestation — interoperating with `ykman` /
  `yubico-piv-tool` (an imported X25519 scalar is byte-flipped to the little-endian
  form standard tooling sends, so the slot's public key matches). bcdDevice
  `0x07C3` → `0x07C4`.

- **Configurable multi-LED effects engine.** Boards with a chain of addressable
  WS2812 LEDs light the whole strip with per-status animated effects (`vapor`,
  `bounce`, `flow`, `sparkle`, `legacy`) via `rsk led --effect/--speed`; the
  connected count is a runtime phy setting (`rsk hw --led-num`, TLV tag `0x0E`)
  bounded by the `MAX_LEDS` build ceiling (a value over it saturates, never
  panics). `EF_LED_CONF` grows to 17 bytes; older blocks still load. Thanks to
  @Curious-r. bcdDevice `0x0780` → `0x0783`.

- **Configurable GPIO presence button (`PRESENCE_PIN`).** The user-presence input
  can move from BOOTSEL to a dedicated GPIO at compile time (`PRESENCE_PIN=<0..=29>`,
  active-low with a pull-up by default, or `PRESENCE_ACTIVE_HIGH=1` for a touch
  sensor / button-to-VCC); the pin is guarded against colliding with the LED and is
  rejected on a `display` build. One new documented `unsafe`. Thanks to @lpiob
  ([#17](https://github.com/TheMaxMur/RS-Key/pull/17)). bcdDevice `0x0791` → `0x0793`.

- **`rsk-tui` can export the seed as SLIP-39 shares** (tools/tui 0.2.4). The Backup
  section gains "Export seed (SLIP-39)" beside the BIP-39 export, revealing the seed
  as a 2-of-3 Shamir share set (via the in-tree `rsk-slip39` crate) that recombines
  with `rsk backup restore --scheme slip39`.

### Changed

- **Touch timeout is configurable; phy tag `0x08` now follows pico-fido.** Tag
  `0x08` (previously an unused presence-button GPIO) now means `PresenceTimeout` —
  the touch-wait in seconds — matching pico-fido / PicoForge, so a PicoForge config
  or `rsk hw --touch-timeout <secs>` sets it (absent / `0` keeps the 30 s default).
  bcdDevice `0x0783` → `0x0784`.

- **`rsk-tui` gets a curated colour theme** (tools/tui 0.2.3). On truecolor / 256-
  colour terminals the cockpit uses a fixed brand palette with rounded borders and
  an explicit selection bar; a 16-colour terminal keeps the adaptive named-ANSI
  colours. Override with `RSK_TUI_TRUECOLOR=1|0`. No `--once` / `--json` change.

- **`rsk-tui` status labels are single-sourced** (tools/tui 0.2.2). The `--once`
  printer and the cockpit now share the model's label mappings, which changes three
  `--once` labels (seed lock "… disabled until unlock", secure boot "ENABLED (not
  locked)", un-probed applets "not probed").

### Fixed

- **Maximal credential requests now fit the credential box.** A registration
  within every advertised limit (a 253-byte `rpId`, a 64-byte user.id, 64-byte
  name / displayName and a 127-byte credBlob) could overflow the sealed credential
  box or its resident bookkeeping and be rejected (`CTAP2_ERR_OTHER` /
  `KEY_STORE_FULL` / `REQUEST_TOO_LARGE`), and a large credential that did register
  could then never assert. The three ceilings are now **derived** from the field
  maxima so they can't drift below what the device advertises: `CRED_BOX_MAX` (748)
  sizes create / assert / reseal, `RP_REC_MAX` (314) the resident `EF_RP` record,
  and `MAX_RAW_SUBPARA` (384) a maximal `updateUserInformation`; getInfo's
  `maxCredentialIdLength` and the published metadata report the real 748, and
  over-maximum inputs are rejected explicitly with `INVALID_LENGTH`. Older records
  load unchanged. bcdDevice `0x07E7` → `0x07EC`.

### Security

- **Additional defense-in-depth hardening** (four items, none independently
  exploitable; bcdDevice `0x07DD` → `0x07DE`):
  - **credProtect is now range-checked.** makeCredential rejected nothing for a
    credProtect value outside `{1,2,3}` and stored it verbatim; `getAssertion`
    enforces protection by exact match, so an out-of-range value silently meant
    *no* protection. It now returns `CTAP2_ERR_INVALID_OPTION` (§12.1).
  - **hmac-secret-mc empty-salt parity.** makeCredential now rejects an
    hmac-secret-mc request with an empty salt up front (`MissingParameter`),
    matching the existing `getAssertion` hmac-secret guard (previously this was
    only caught later by the length check in `hmacsecret::eval`).
  - **credentialManagement enumeration counters widened to `u16`.** The `skip` /
    `total` / begin-next counters were `u8` and saturated at 255, so on a fully
    provisioned store (`MAX_RESIDENT_CREDENTIALS = 256`) the 256th RP/credential
    was invisible to (and undeletable via) enumeration. The wire encoding is
    unchanged for ≤255 (canonical CBOR).
  - **RSA-keygen fast path resets the incoming command chain.** The CCID keygen
    fast path already dropped a stale GET RESPONSE tail (`clear_pending`); it now
    also resets a half-accumulated CLA-`0x10` command chain (`clear_chaining`,
    scrubbing it) so an interrupted chain cannot prepend onto a later command.
- **Missing-authorization fixes in the Yubico-management and rescue applets**
  (two defects in never-before-audited utility applets; bcdDevice `0x07DC` →
  `0x07DD`):
  - **Rescue OTP-fuse writes now require an on-device user-presence confirmation.**
    The two irreversible fuse burns — page-58 access lock (`INS 0x1B` `P1=0x58`,
    `"LOCK58"`) and `ROLLBACK_REQUIRED` (`P1=0x48`, `"ROLLBK"`) — were the only
    privileged rescue commands without the `require_presence` gate every sibling
    op (attestation sign, cert/phy write, reboot-to-BOOTSEL) enforces. Their magic
    payload is a source-visible constant, not authentication, so an unauthenticated
    USB host could permanently burn a fuse with no operator consent. Both now
    prompt (`6985` if declined); idempotent no-ops still return `OK` without a
    prompt. (`crates/rsk-rescue/src/lib.rs`.)
  - **Management WRITE CONFIG (`INS 0x1C`) now requires user presence.** It was
    entirely unauthenticated and the `CONFIG_LOCK` byte it stores was never
    enforced, so a USB host could persistently spoof the reported DeviceInfo. The
    write now prompts for on-device confirmation (`6985` if declined), matching
    every sibling applet's write path. (`crates/rsk-mgmt/src/lib.rs`.)
- **PIV and CCID defense-in-depth hardening** (no exploitable vulnerability
  found; three items; bcdDevice `0x07DB` → `0x07DC`):
  - **PIV `GENERAL AUTHENTICATE` challenge is now bound to its issuing
    algorithm.** A 9B mutual/single-auth challenge issued under one algorithm
    (3DES `chal_len` 8 vs AES `chal_len` 16) could structurally be answered under
    the other; AES-192 and 3DES share a 24-byte key, so the key-length gate alone
    did not separate them. This was **not** exploitable (the witness always
    requires knowledge of the management key, and every replay failed closed with
    `has_mgm` staying false), but the `Session` now records `chal_algo` at issue
    and refuses a step-2 whose algorithm differs.
  - **PIV GET DATA / MOVE KEY clamp the stored object length.** `get_data` and
    `move_key` sliced a `MAX_OBJECT` (1900-byte) buffer by the full length
    `Storage::read` returns, which would panic on a stored value longer than the
    buffer. Every host writer already caps at `MAX_OBJECT` (so this was reachable
    only by a raw flash write — a stronger attacker than the USB host), but the
    readers now clamp with `n.min(MAX_OBJECT)`, returning the prefix instead of
    panicking. Matches the existing `EF_PIVMAN_DATA` clamp pattern.
  - **CCID RSA-keygen fast path clears the GET RESPONSE remainder.** The dual-core
    `try_rsa_keygen` / `try_piv_rsa_keygen` fast paths bypass
    `Dispatcher::process`, which is what normally drops a stale chained-response
    tail, so a host interleaving `chained-response → GENERATE → GET RESPONSE` was
    re-served its own prior tail. This crossed no trust boundary (same principal;
    a SELECT to another applet clears the buffer first), but the fast paths now
    call `Dispatcher::clear_pending()` to match ordinary dispatch.

- **PIV and OATH authentication fixes** (bcdDevice `0x07DA` → `0x07DB`):
  - **PIV management-key authentication bypass via an encryption oracle
    (critical).** `GENERAL AUTHENTICATE` had a symmetric-algorithm tag-`0x81`
    ("internal authenticate") branch for slot `9B` that returned
    `E(mgm_key, caller_bytes)` with no `has_mgm`, no PIN (`9B` is not a key slot,
    so the PIN gate was skipped) and no touch (default `9B` policy is
    `TOUCHPOLICY_NEVER`). Because the management-key cipher is deterministic ECB,
    an unauthenticated USB host could chain it with the applet's own single-auth
    challenge — request a plaintext challenge `R`, ask the oracle for `E(mgm,R)`,
    submit that as the response — and the card's `D(mgm,·)==R` check would pass,
    setting `has_mgm` with **zero knowledge of the management key**. That grants
    full, persistent PIV takeover (generate/import/overwrite slot keys, `PUT DATA`,
    rotate the management key, reset PIN/PUK counters). It is a distinct-mechanism
    sibling of the earlier mgmt-key bypass, whose `ChallengeKind` binding did not
    cover it. **Fix:** the symmetric tag-`0x81` branch (which has no legitimate PIV
    client) is removed, so the only sanctioned `9B` flows are mutual-witness
    (tag `0x80`) and single-auth (tag `0x81`-empty challenge → tag `0x82` verify).
    A class-invariant test asserts no `GENERAL AUTHENTICATE` path reachable without
    prior auth can set `has_mgm`.
  - **OATH `CHANGE PIN` unlimited OTP-PIN guessing at the retry floor (medium).**
    `cmd_change_otp_pin` decremented the OTP-PIN retry counter with a saturating
    subtraction but, unlike `cmd_verify_otp_pin`, did not refuse at the floor —
    once the counter reached 0 it stayed 0 and the PIN comparison kept running on
    every request, an unlimited online brute-force of the store-unlocking OTP-PIN
    (a residual sibling of the earlier `CHANGE PIN` finding). **Fix:** both `VERIFY`
    and `CHANGE` now go through a single `spend_and_match_otp_pin` chokepoint that
    refuses at `rec[0]==0`; legitimate recovery after lock-out is `RESET` (which
    wipes the store), not more guesses. **Behavior change:** a correct old-PIN no
    longer recovers a locked-out OTP-PIN via `CHANGE`; use `RESET`.
- **OTP, OpenPGP, U2F and audit-journal hardening** (bcdDevice `0x07D9` →
  `0x07DA`):
  - **OTP `SLOT_SWAP` access-code bypass (high).** `cmd_swap` was the only
    slot-mutating OTP command that did not check the per-slot access code that
    `cmd_configure`/`cmd_update` enforce: it unsealed both target slots (the seal
    read never compares the access code) and relocated/deleted them unconditionally.
    An unauthenticated USB host (CCID or the HID keyboard frame, no PIN/code/touch)
    could `SLOT_SWAP` a programmed, access-code-protected slot to **silently delete
    or relocate** it — persistently breaking a challenge-response credential used
    for LUKS / KeePassXC / pam_yubico. An unbounded swap offset could also orphan
    the slot at an FID outside the addressable 1..=4 range. `cmd_swap` now requires
    the access code of every non-empty slot it touches (an unprotected slot's code
    is all-zero, so a plain `ykman otp swap` of unprotected slots is unchanged) and
    rejects out-of-range offsets; the same offset bound is applied to
    `cmd_configure`/`cmd_update`/`cmd_calculate`. Integrity/availability only — the
    config stays GCM-sealed (no secret exfiltration).
  - **OpenPGP `read_public` unclamped stored length (hardening).** `read_public`
    returned the value's full `Fs::read` length without `n.min(out.len())` — the
    6th member of the OpenPGP stored-length family. Latent only (`EF_PB_*` is not
    host-writable beyond its bound), now clamped like every other reader.
  - **U2F attestation-chain read (hardening).** The org-attestation branch sliced
    `cert[..n]` on the full stored length with only a size margin; now clamps
    `n.min(cert.len())`, matching the sibling `EF_EE_DEV` branch.
  - **Audit-journal meta window (hardening).** `load_meta` now fails closed to
    genesis when a persisted `EF_AUDIT_META` claims a window wider than
    `AUDIT_RING_SLOTS`, so a flash-corrupted meta can't overrun the export buffer.
  - **`BACKUP_EXPORT` docstring corrected** to match behavior (only
    `BACKUP_FINALIZE` seals the window; repeat export before finalize is safe).
- **FIDO, OpenPGP and OATH fixes** (bcdDevice `0x07D8` → `0x07D9`):
  - **FIDO `getNextAssertion` user-presence bypass (high).** `getAssertion` armed
    the multi-credential `getNextAssertion` queue during resident discovery
    *before* its user-presence gate, and no path tore the queue down when that gate
    failed; `getNextAssertion` performs no presence check of its own. So on a
    device holding ≥2 discoverable credentials for one RP, after the user
    **declined or ignored** the touch, a host could still pull valid `UP=1`
    assertions for credentials #2..N with no touch — defeating the test of user
    presence. `get_assertion` now calls `gna.reset()` on any error return (CTAP 2.1
    §6.3: getNextAssertion only continues a *successful* getAssertion).
  - **OpenPGP `GENERATE` OOB panic on a short algorithm attribute (medium).** A
    PW3-written 1–2 byte `C1/C2/C3` DO (`PUT DATA` caps no minimum length) made
    `GENERATE ASYMMETRIC KEY PAIR` index the RSA modulus-size bytes past the slice
    → panic/reset on every `GENERATE` for that slot. The earlier clamp only bounded
    the *over*-long case; both `generate` and `rsa_generate_params` now reject an
    attribute shorter than 3 bytes, matching the guarded sibling `info::slot_algo`.
  - **OATH OTP-PIN counter glitch-hardening (defense-in-depth).** `VERIFY PIN` /
    `CHANGE PIN` now persist and read back the retry-counter decrement *before* the
    PIN compare (mirroring the FIDO clientPIN gate), so a fault-injected or failed
    flash program can't widen the 3-try OTP-PIN limiter.
  - **FIDO `verify_pin_hash` self-guards the retry decrement (defense-in-depth).**
    Added an in-function `retry == 0` check before `pin_data[0] -= 1` (matching
    `verify_pin_at`), so no future caller can underflow the PIN retry budget in a
    release build without overflow-checks.
- **OpenPGP, OATH and FIDO fixes; `rsk` receipt binding** (bcdDevice `0x07D8`;
  `rsk` 0.3.1; `rsk-tui` 0.2.1):
  - **OpenPGP `GET DATA` unclamped length → OOB brick (high, ×2 sites).** Both the
    generic top-level Flash DO (`login`/`url`/private DOs) and the `C1/C2/C3`
    algorithm-attribute path returned the value's full stored length, so an
    over-long PW3-written object panicked the device on every read (persistent
    DoS reached by `gpg --card-status`). `get_data` now clamps `data_len` to the
    scratch buffer at the single chokepoint, plus a defensive clamp at the extend.
  - **OATH access-code / OTP-PIN bypasses (high, ×2).** `SET PIN` now requires a
    validated session (an unauthenticated host could mint the unlock secret on a
    locked applet); `CHANGE PIN` now spends a retry on a wrong old-PIN (it was an
    unlimited brute-force oracle that recovered the OTP-PIN and unlocked the store).
  - **FIDO `setMinPINLength` truncation (medium).** A `newMinPINLength` above the
    max PIN length is now rejected before the `as u8` store, which otherwise
    truncated (e.g. 256 → 0) and silently defeated the monotonic enterprise floor.
  - **`rsk offboard` receipt binding (medium).** The signed wipe receipt is now
    bound to the journal window it presents (recompute + compare the head, hard-fail
    a missing RESET), matching `rsk audit`; the verify ceremonies also validate
    device-supplied checkpoint fields instead of raising a traceback.
  - **Defense-in-depth (low).** Clamped five remaining `Fs::read` readers
    (`phy`/`largeblobs`/vendor `unlock`/`makeCredential` att-chain/OpenPGP DEK) to
    their buffers; fixed the OpenPGP `GET DATA 0x7A` stale-scratch over-read;
    rejected the 2-byte TLV tag form in OATH `PUT`; hardened the `rsk-tui` audit
    view and `rsk led` against malformed device responses.

- **Full-tree audit fixes.** Found and fixed:
  - **PIV management-key authentication bypass (critical).** `GENERAL
    AUTHENTICATE` shared one session challenge field between the single-auth
    (plaintext challenge) and mutual-auth (encrypted witness) handshakes, so a
    host could read the plaintext single-auth challenge and replay it as the
    mutual-auth witness to authenticate as the card administrator with no
    knowledge of the management key — no PIN, no touch. The challenge is now
    tagged with the flow that issued it and can only be consumed by that same
    flow.
  - **OpenPGP `GET DATA` over-long-DO brick (two more sites).** The cardholder
    certificate (`7F21`) read-out and the generic `DoWriter` flash-DO builder
    sliced/advanced a fixed 1024-byte buffer by the value's *full* stored length;
    a PW3 host can `PUT DATA` an over-long cardholder cert/name, so a later `GET
    DATA 65/6E/7F21` (issued by `gpg --card-status`) panicked — a persistent
    brick. Both are now clamped to the buffer, matching the earlier `info.rs` fix.
  - **OATH `VERIFY CODE` (INS `0xB1`) now honours the access code.** It lacked the
    `validated` gate every other stored-data command has, so a locked applet
    answered it — a replayable oracle on the primary credential's current OTP
    across the access-code boundary. Now gated.
  - **Trusted-display delete-confirmation clips the identity.** The
    delete-passkey confirmation drew the untrusted rpId/account unclipped with no
    truncation marker, unlike the approve/add ceremonies; a padded look-alike
    rpId could overflow the card silently. Now ellipsized + marked to the card.
  - **OpenPGP private keys are AES-256-GCM-sealed with a fresh nonce.** The DEK
    seal used one fixed (key, IV) AES-CFB across every key slot, so the block-0
    keystream repeated and a flash-dump attacker could recover the XOR of two
    same-format scalars' first bytes; CFB was also unauthenticated. Sealing now
    uses AES-256-GCM under a synthetic per-record nonce (`HMAC(dek, fid ‖ key)`),
    adding authentication and eliminating the reuse. Keys in the old CFB format
    still load (trial-decrypt fallback) and are re-sealed to the new format the
    first time they are used — no reprovisioning needed.
  - **The release pipeline no longer ships the `no-touch` firmware.** The release
    workflow built and published four `no-touch` flavors (user-presence bypass,
    marked "never ship") as signed, SLSA-provenanced public assets. It now builds
    and publishes only the four touch-required flavors, with a guard that fails
    the release if any `no-touch` asset is present.

- **FIDO master seed sealed with authenticated ChaCha20-Poly1305.** The device
  master seed and the org attestation scalar (`EF_KEY_DEV` / `EF_ATT_KEY`) were
  sealed with AES-256-CBC under one fixed serial-hash IV shared across both
  slots, and carried no MAC — the same fixed-IV / no-authentication class as the
  OpenPGP DEK above, but at the root of the FIDO identity. They are now
  ChaCha20-Poly1305-sealed (new tags `0x02` pre-OTP / `0x12` OTP-arm) under a
  synthetic per-record nonce (`HMAC(HMAC(nonce_key, fid), value)`), so the seed
  and the attestation key never share a nonce and a flash fault or tamper is
  detected rather than silently decrypting to a corrupted seed. Records in the
  legacy CBC (`0x01`/`0x11`) and PIN-wrapped (`0x03`/`0x13`) formats still load
  and are re-sealed forward at boot / the first PIN verify — no reprovisioning,
  and every passkey survives the upgrade.

- **Pre-release cross-review hardening.** An adversarial re-review of the two
  unreleased hardening commits (the trusted-display arc and the pico-keys
  carry-over below) — the ones that had not yet been cross-reviewed before a
  release tag — found and fixed:
  - **OpenPGP over-long-DO brick, two remaining sites.** `GENERATE`,
    `rsa_generate_params` and key `IMPORT` read the algorithm-attribute DO into a
    fixed 16-byte buffer and sliced it by the value's *full* stored length; a
    PW3 host can `PUT DATA` an over-16-byte `C1/C2/C3`, so the slice panicked
    (device brick). Clamped to the buffer, matching the earlier `info.rs` fix.
  - **OTP slots and OATH credentials now survive a later OTP-MKEK burn.** Both
    seal under the device root key, which changes when the fuse MKEK is burned;
    neither had the pre-OTP recovery arm the FIDO seed / PIV / attestation key
    already use, so a secret provisioned *before* a burn became unreadable (OTP)
    or was double-encrypted and destroyed (OATH) on the first post-burn boot. The
    boot migrations now trial-decrypt under the pre-OTP arm and re-seal under the
    OTP arm.
  - **OATH OTP-PIN survives an OTP-MKEK burn.** The new OTP-rooted verifier gained
    the same `without_otp()` match-and-re-store fallback the PIV / OpenPGP / FIDO
    PINs use, so a PIN set before a burn still verifies afterwards — restoring the
    burn-immunity the legacy serial-only hash happened to have.
  - **The reboot-to-BOOTSEL user-presence gate can no longer be bypassed.** The
    vendor applet exposes the same reboot verb as the (gated) rescue applet, over
    both the CCID and CTAPHID transports; its `1F/01` (BOOTSEL) is now gated
    identically. A warm restart (`1F/00`) stays ungated.
  - **Trusted-display: the Add-passkey (enrollment) screen marks a truncated
    relying-party id.** The makeCredential screen dropped the truncation marker
    for a clamped look-alike id whose prefix fit the box — the phishing vector the
    Approve screen already closed. It now forces the marker like the Approve path.
  - **`rsk-wipe` rejects a degenerate `FLASH_SIZE`.** `FLASH_SIZE=0` passed the
    remaining build asserts and made the erase a silent no-op that still signalled
    success; a lower bound now rejects it.

  bcdDevice 0x07D3 → 0x07D4. Host CLI (`tools/rsk`) 0.2.0 → 0.3.0: `rsk hw` and
  `rsk reboot bootsel` now prompt for the on-device approval the firmware requires
  and explain a `6985` decline instead of failing cryptically.

- **Carry-over hardening from a pico-keys upstream audit.** A review of the upstream
  pico-keys C firmware surfaced design flaws; each was re-verified against the RS-Key
  Rust source. The overwhelming majority were already handled by the port (OATH gate,
  PIV key sealing + admin-auth gates, parser totality, HMAC-DRBG, constant-time
  compares), and this wave closes the remaining gaps:
  - **Yubico OTP slot secrets are now sealed at rest.** The 52-byte slot config —
    which carries the AES-128 key, private UID and the HMAC-SHA1 / OATH-HOTP secret —
    was the one applet still written to flash in the clear. It now goes through the same
    `KeyFid` AES-256-GCM chokepoint as FIDO / PIV / OpenPGP / OATH; a boot pass re-seals
    any pre-existing plaintext slot, so a flash-dump thief no longer recovers the token
    secrets.
  - **The OATH OTP-PIN verifier is OTP-rooted, not a fast serial-only hash.** The
    Nitrokey-style OTP PIN now stores `pin_derive_verifier` (rooted in the OTP MKEK,
    exactly like the OpenPGP / PIV PINs) instead of the legacy `double_hash_pin`; a
    legacy record still verifies and is upgraded on the next successful use.
  - **The device attestation key is AEAD-sealed.** `EF_DEVCERT_KEY` moved from raw
    AES-256-CBC under a public fixed IV with no MAC to AES-256-GCM (random nonce, auth
    tag); a bit-flip in the sealed scalar is now detected rather than silently accepted,
    and legacy CBC records are re-sealed at boot.
  - **Privileged rescue commands require user presence.** Attestation signing over a
    host-chosen digest, attestation-cert overwrite, phy/identity write and
    reboot-to-BOOTSEL now need an on-device confirmation (a touch, or an on-screen
    Approve on the trusted-display build), so a hostile USB host can no longer drive
    them silently. Read-only status and a plain restart stay ungated.
  - **OpenPGP MSE touch policy follows the repointed slot.** The UIF (touch) check for
    PSO:DECIPHER / INTERNAL AUTHENTICATE now follows an MSE key-reference repoint, so a
    cross-wired DEC↔AUT key can no longer be used under the wrong slot's touch policy.
  - **FIDO credMgmt `updateUserInformation` requires an exact userId match** (CTAP 2.1
    §6.8.3), closing a min-length-prefix compare where a prefix (or empty id) matched.
  - **`rsk-wipe` erases the whole target flash.** It reads the same `FLASH_SIZE` build
    knob as the firmware instead of assuming 4 MB, so a 16 MiB board is fully wiped.

  bcdDevice 0x07D2 → 0x07D3. (`rsk-wipe` is a separate binary and carries no bcdDevice.)

## [0.2.8] — 2026-06-21

### Changed

- **A WebAuthn login is a single touch by default.** RS-Key now honors the
  platform's silent pre-flight probe — a `getAssertion` with the `up` option set
  to `false` — by returning the credential-discovery assertion **without**
  polling the button and with the UP flag clear, as the CTAP2 spec and YubiKey
  do. Previously the `up` option was ignored and every assertion polled the
  button, so an `allowCredentials` (non-resident) login — the common security-key
  second-factor flow — cost **two** touches: one for the browser's silent
  pre-flight, one for the real assertion. Resident-credential / passkey logins
  were, and remain, a single touch. A new `strict-up` cargo feature (off by
  default) restores the touch-on-every-assertion behavior for anyone who wants an
  explicit gesture per assertion; `fido-conformance` enables it implicitly so the
  conformance image keeps its validated behavior. See
  [build.md](https://github.com/TheMaxMur/RS-Key/blob/main/docs/build.md).
  bcdDevice 0x077F → 0x0780.
- **Requiring a touch is the unconditional default, not a cargo feature.** The
  `up-button` feature (which was on by default) is gone — the shipped image
  demands a BOOTSEL touch for FIDO / OpenPGP-UIF operations with no flag. The
  no-touch test image, for the automated suites that cannot press a button, is
  now the explicit opt-in **`--features no-touch`** (previously
  `--no-default-features`). The secure default no longer depends on a feature
  being left enabled; the default firmware binary is unchanged.

## [0.2.7] — 2026-06-21

### Security

- **A pre-OTP seed remnant survived OTP provisioning, readable from a flash
  dump without the fused key — now physically scrubbed at the first OTP boot.**
  RS-Key seals the FIDO seed under the device root (`kbase`): chip-serial-only
  before OTP provisioning, the fused MKEK after. Burning OTP re-seals the seed
  from the weaker root to the fused one (`migrate_keydev_boot`), but the
  `sequential-storage` flash log is append-only — an overwrite leaves the prior
  value in place and `remove_item` only flips a header CRC, so the superseded
  *chip-serial-sealed* copy lingered in flash until natural compaction (rare on
  the cold credential partition). Because that root derives from the chip id
  alone — no fuse secret — an attacker with a flash dump plus the chip id could
  recover the seed, and with it every derived FIDO credential, **bypassing the
  OTP hardening entirely.** This is the same class of issue as the upstream
  pico-fido/pico-keys-sdk `flash_clear_file` finding (their "clear" zeroes only
  the length field, leaving the payload); here `sequential-storage`'s logical
  delete is the equivalent, and the device-root seal is the only thing that made
  the steady state safe. Fix: the first boot with the OTP key present now runs a
  one-shot `Fs::compact` — a full garbage-collection lap over the credential
  partition that migrates live records forward and sector-erases every page,
  physically destroying the superseded pre-OTP copies. It is gated by a new
  `EF_HARDENED` flash marker (runs once, before USB attach) and is crash-safe
  (an interrupted lap leaves the marker unset and re-runs next boot). A device
  provisioned OTP-first never creates the remnant and the pass finds nothing to
  scrub. A host-side proof on the real `sequential-storage` + mock-flash stack
  scans raw flash to confirm the remnant is present before the lap and gone
  after (`fuzz/tests/churn_compaction.rs`, mutation-checked). `production.md`
  now documents the pass and recommends burning OTP before enrolling; the
  threat-model/limitations caveats are corrected (the lingering record was
  described as "moot against anything but a fused-key compromise", true only for
  the already-fused soft-lock case, not this one). bcdDevice 0x077E → 0x077F.

## [0.2.6] — 2026-06-21

### Fixed

- **ML-DSA-44 (COSE `-48`) FIDO `getAssertion` hard-wedged the device — the
  post-quantum credential key is now heap-boxed off the worker stack.** The
  optional ML-DSA-44 signature scheme (negotiable from a request's
  `pubKeyCredParams`, unadvertised by default) held fips204's ~16.6 KiB of
  NTT-form keys *inline* on the worker stack, directly below the stack-heavy
  rejection-sampling `sign`. A `.bss` growth since v0.2.5 (the power-cut
  tri-state present-cache + the hybrid ML-KEM-768 seed-backup) had lowered the
  RP2350 worker-stack ceiling from ~238 KiB to ~222 KiB, so an ML-DSA-44
  `getAssertion` overflowed it → memory corruption → `panic-halt`, leaving FIDO
  dark until a USB replug. Reachable as a denial of service: an explicit `-48`
  `makeCredential` followed by `getAssertion` wedges the authenticator even
  though `-48` is unadvertised. `makeCredential` survived because key generation
  is a shallower frame than signing. The keypair is now `Box`-ed onto the
  firmware heap — idle during a FIDO request, since applet keys are reconstructed
  per-operation — freeing ~16.6 KiB at signing depth and restoring a measured
  32–64 KiB of stack margin (verified on hardware by flashing deliberately
  stack-starved builds: passes at −32 KiB, wedges at −64 KiB). The heap stays
  128 KiB, so there is no RSA impact, and a `size_of::<CredKey>()` guard fails
  the build if the key ever regresses back inline. HW-verified on RP2350
  (`tests/60` raw CTAPHID + `tests/61` python-fido2/OpenSSL, ML-DSA-44
  register+login). `bcdDevice` `0x077D` → `0x077E`.

- **`ssh-keygen -t ed25519-sk` (and any Ed25519 FIDO2 credential) failed on
  Windows — EdDSA is now advertised in `authenticatorGetInfo`.** The device has
  always *supported* EdDSA (COSE `-8`): `makeCredential` negotiates it from a
  request's `pubKeyCredParams` and signs with Ed25519. But `-8` was omitted from
  the advertised `algorithms` (0x0A) list, kept out alongside ES256K (`-47`) so
  the FIDO Conformance tool — whose `verifySignatureCOSE` only maps `-7/-35/-36` —
  wouldn't fail trying to verify an EdDSA self-attestation. The Windows WebAuthn
  API (the path Windows OpenSSH takes) **intersects the requested algorithms with
  the advertised list**, so it silently dropped `-8` and the credential create
  failed; macOS/Linux OpenSSH go through libfido2, which sends `-8` directly, so
  it worked there. The shipping/default build now advertises `-8`. The capability
  is unchanged — only the advertisement was added. ES256K (`-47`) stays
  unadvertised (still negotiable from a request). For the conformance run, the new
  `fido-conformance` build feature suppresses `-8` again and
  `metadata/rs-key.conformance.metadata.json` is the matching EdDSA-free Metadata
  Statement (verified by `tests/62` to be the shipping statement minus EdDSA).
  `bcdDevice` `0x077C` → `0x077D`.

- **Two power-cut data-durability bugs in the flash file system, both surfaced by
  the `power_cut` / `fs_ops` fuzz targets (deep-checks) and latent since the
  present-cache landed in v0.2.3.** Neither affects the shipped, verified v0.2.5
  artifacts — both are power-cut-edge, not artifact-integrity.
  - **`delete` orphaned metadata.** `Fs::delete` dropped a file's `EF_META`
    record only when the file's *own* data was present, so a file given metadata
    (`meta_add`) but never written (`put`) kept its metadata after deletion — the
    record read back alive across a reboot, diverging the live key set from the
    model. `delete` now drops metadata unconditionally (O(1) when there is none),
    and `meta_delete` skips the `EF_META` rewrite when the FID had no record, so
    the absent-slot reset sweep stays write-free.
  - **The present-cache could go false-absent after a torn migration.** The boot
    `scan` seeds its negative cache from a bulk `for_each_key`, which can silently
    under-count a key when a power-cut interrupts a `sequential-storage` page
    migration — while the per-key `fetch_item` still recovers it. A clear cache
    bit was trusted as "absent", so committed data/metadata read back lost, and a
    `meta_add` over a false-absent `EF_META` wiped every existing record. The
    cache is now tri-state (`present` + a `decided` authority bit): a clear bit is
    trusted only once a backend probe confirms it, otherwise the reliable
    `fetch_item` decides and the answer is memoised — a false-absent is now
    impossible. Cost: a one-time-per-boot first probe per absent FID (the PIV-tab
    lag returns once after a plug-in, then stays O(1)). `fetch_item` durability is
    pinned by a new `kv_durability` fuzz target (the storage layer in isolation);
    `power_cut` and `fs_ops` now run clean. `bcdDevice` `0x077B` → `0x077C`.

## [0.2.5] — 2026-06-20

### Added

- **Runtime LED hardware config — pin, driver, and wire order are now set at
  runtime via the `phy` record (`rsk hw` / PicoForge), no reflash.** The
  `LED_KIND` / `LED_PIN` / `LED_ORDER` build knobs (below) become *boot
  defaults*: a non-`none` build now compiles all three backends and, at boot,
  applies the data pin (`led_gpio`), driver (`led_driver` — 1=gpio / 2=pimoroni /
  3=ws2812, matching pico-fido / PicoForge), and an RS-Key vendor wire-order tag
  (`led_order`, `0x0D`) from `EF_PHY` — the same record that already drives the
  USB identity. The pin reaches the PIO state machine through a `match` over GPIO
  `0..=29` (embassy has no `PioPin for AnyPin`, but doesn't need one); the wire
  order is a runtime red/green swap, so one binary serves both RGB- and GRB-wired
  parts. New **`rsk hw`** command (`--led-pin` / `--led-driver` / `--led-order` /
  `--get`) does a read-modify-write of only the LED fields (any USB identity is
  preserved) and warm-reboots to apply. A `none` build stays headless and ignores
  the phy LED fields. `bcdDevice` `0x077A` → `0x077B`.

- **Selectable LED backend (`LED_KIND` build knob) — the indicator is no longer
  WS2812-only.** The status engine (boot/processing/touch/idle blink + the
  runtime-configurable colour/brightness in `EF_LED_CONF`) was already
  backend-agnostic; only the render half was hard-wired to the Waveshare's
  addressable WS2812. The render is now chosen at build time: `ws2812` (default —
  the addressable RGB on `LED_PIN`), `gpio` (a plain on/off LED on `LED_PIN`;
  hue/brightness collapse to lit/unlit, but the blink *pattern* still tells the
  statuses apart — so RS-Key now runs on boards with a simple LED, e.g. a bare
  RP2350 or Pico 2), `pimoroni` (a 3-pin PWM common-anode RGB, Pimoroni Tiny 2350)
  or `none` (headless). Only the selected driver and its PIO/PWM dependencies are
  compiled. `bcdDevice` `0x0778` → `0x0779`.

- **`LED_ORDER` build knob — the WS2812 wire byte order is now selectable.** The
  reference Waveshare RP2350-One is unusually **RGB**, the project default; but
  standard WS2812B parts (e.g. the TenStar RP2350-USB) are **GRB**, and driving
  one with the wrong order swaps red↔green (blue is unaffected). `LED_ORDER=grb`
  picks the standard order for such boards; `rgb` (default) keeps the Waveshare
  behaviour. Verified on a TenStar RP2350-USB (16 MB, WS2812 on GP22):
  `LED_KIND=ws2812 LED_ORDER=grb LED_PIN=22 FLASH_SIZE=16M`. `bcdDevice` `0x0779`
  → `0x077A`.

- **Hybrid post-quantum seed-backup channel — the vendor MSE key agreement is now
  P-256 + ML-KEM-768.** The seed-backup channel (`authenticatorVendor` `0x41`,
  `MSE`) is the one place the device hands out a normally non-exportable key — the
  32-byte master seed — so a recorded exchange is the prime harvest-now-decrypt-
  later target: break the ephemeral P-256 ECDH with a future quantum computer and
  the wrapped seed falls out. The handshake now accepts an optional ML-KEM-768
  (FIPS 203) encapsulation key in subCommandParams key 2; when present the device
  encapsulates to it and derives the channel key as
  `HKDF-SHA256("RSK-MSE-PQ-v1", z ‖ ss_mlkem, dev_pub ‖ ct)`, returning the
  ciphertext as response key 2. Both shared secrets feed the KDF, so the channel
  stays confidential unless *both* P-256 and ML-KEM-768 are broken (defense in
  depth — never PQC-only). Only the cheap `encapsulate` direction runs on-device;
  the host keeps the ML-KEM keypair and decapsulates. A host that sends no key 2
  gets the classical channel byte-for-byte, so existing hosts keep working.
  `bcdDevice` `0x0777` → `0x0778`.

- **`alwaysUv` (always require user verification) is supported.** `getInfo`
  advertises the `options.alwaysUv` flag (reflecting its state, `false` at reset)
  and the `toggleAlwaysUv` (`0x02`) `authenticatorConfig` subcommand. While enabled
  (flipped via `authenticatorConfig` toggleAlwaysUv, gated on a pinUvAuthToken with
  the `acfg` permission), every `makeCredential` / `getAssertion` requires a verified
  pinUvAuthToken — an up-only (touch) request is refused with
  `CTAP2_ERR_PUAT_REQUIRED`, even when no PIN is configured. The state persists until
  `authenticatorReset`, which clears it. Completes the FIDO conformance "featureful"
  CTAP2.3 profile's authenticatorConfig requirement. `bcdDevice` `0x0774` → `0x0775`.

- **`getInfo` advertises five optional informational members.** `transports`
  (0x09, `["usb"]`), `maxRPIDsForSetMinPINLength` (0x10, `8`),
  `remainingDiscoverableCredentials` (0x14, the live free resident-key-slot count),
  `attestationFormats` (0x16, `["packed"]`) and `maxPINLength` (0x1D, `63`). Purely
  informational — no behaviour change — and mirrored in the metadata statement (the
  FIDO conformance Authr-Generic test strict-compares each member to it).
  `bcdDevice` `0x0776` → `0x0777`.

### Fixed

- **CTAPHID: an init-type frame received mid-transaction is rejected as
  `ERR_INVALID_SEQ` regardless of its length field.** The `bcnt > maxMsgSize`
  check ran first, so a continuation frame whose sequence byte had the INIT bit
  set — the FIDO Conformance Tools' `HID-1 F-4` corrupts the last frame's seq to
  `CTAPHID_PING + 1` (0x82), leaving random payload bytes as the "bcnt" — usually
  tripped the length guard and returned `ERR_INVALID_LEN` (0x03) instead of the
  required `ERR_INVALID_SEQ` (0x04). The out-of-sequence check now precedes the
  length check. `bcdDevice` `0x0767` → `0x0768`.
- **U2F authenticate resolves the key handle before requesting a touch.** An
  unknown handle (wrong AppID / not minted by us) and a check-only (`P1=0x07`)
  request must be answered immediately — `0x6A80` and `0x6985` respectively —
  without user presence; we prompted for a touch first on `P1=0x03`, so a
  conformance negative test (`U2F-Authenticate F-2`) hung on the button and the
  stream of `UPNEEDED` keepalives desynced the tool's response reader (seen as
  "sequence out of order"). Shares the `0x0768` bump.
- **No `PROCESSING` keepalive before a fast U2F response.** U2F (CTAPHID_MSG) is
  quick apart from the touch wait, but the worker runs on a lower-priority
  executor, so the 100 ms keepalive timer could fire once before a near-instant
  reply (check-only, unknown handle) — and U2FHID hosts, including the FIDO
  Conformance Tool, read that stray `PROCESSING` frame as the response's first
  frame and desync (`U2F-Authenticate P-3`/`F-2`: "sequence out of order"). MSG
  now stays silent unless a touch is pending (`UPNEEDED`); CBOR keeps
  `PROCESSING` for its genuinely slow operations. `bcdDevice` `0x0768` →
  `0x0769`.
- **`CTAPHID_CANCEL` aborts an in-flight request's user-presence wait.** While
  the worker blocked on the touch wait the transport never read further frames,
  so a `CANCEL` sat unread until the (up to 30 s) wait ended — the FIDO
  Conformance Tool's `HID-1 P-10` (cancel during `makeCredential`) and `P-15`
  (cancel during `authenticatorSelection`) timed out. The transport now watches
  for a `CANCEL` on the active channel concurrently with the worker and signals a
  cross-executor abort; the cancelled command returns `CTAP2_ERR_KEEPALIVE_CANCEL`
  (0x2D). A `CANCEL` is also no longer acknowledged with its own frame (per the
  CTAPHID spec).
- **`authenticatorMakeCredential` input validation.** A non-text `rp.name`
  (`Req-2 F-2`) and a `pubKeyCredParams` entry missing its `alg` (`Req-4 F-4`)
  are now rejected instead of accepted.
- **`authenticatorMakeCredential` accepts `options.up=true`.** An explicit
  `up=true` is the default and now succeeds (`Req-6 P-3`); only `up=false`
  remains an `INVALID_OPTION` (`F-1`).
- **getAssertion withholds user name/displayName without user verification.** On
  a multi-credential discovery the response `user` map now carries only `id`
  unless `uv` is set (CTAP §6.2.2 privacy rule, `Discoverable P-2`); the full
  identity is returned once the user is verified. Applies to
  `authenticatorGetNextAssertion` too.
- **credentialManagement enumerateCredentials always reports `credProtect`.** The
  `0x0A` field was emitted only when a non-default level was set; it now always
  appears, defaulting to level 1 (`userVerificationOptional`)
  (`CredMgmt-EnumerateCredentials P-1`).
- **largeBlobs accepts `get=0`.** A read of zero bytes is valid and returns an
  empty fragment instead of `CTAP2_ERR_INVALID_PARAMETER` (`LargeBlobs-1 P-2`).
- **credentialManagement updateUserInformation keeps the credentialId stable.**
  Resealing a credential draws a fresh IV (nonce reuse is forbidden), so the box —
  and the resident id previously re-derived from it — changed, staling the
  platform's stored credentialId; a later `deleteCredential` with that id then
  returned `CTAP2_ERR_NO_CREDENTIALS` (`CredMgmt-UpdateAndDelete P-2`). The update
  now rewrites the credential in place, preserving its stored 42-byte resident id,
  and `getAssertion` returns that stored id instead of re-deriving it (CTAP2.1
  §6.8.5). The signing key / hmac-secret / largeBlobKey are still box-derived, so
  they rotate on an update — full stability needs a per-credential nonce and is
  deferred. `bcdDevice` `0x076F` → `0x0770`.
- **A `pinUvAuthToken` request while a forced PIN change is pending now returns the
  correct per-subcommand error.** With `forcePINChange` set (via `setMinPINLength`
  subcommand param `0x03`), both `getPinToken` (0x05) and
  `getPinUvAuthTokenUsingPinWithPermissions` (0x09) refuse to issue a token until the
  PIN is changed. The FIDO conformance ClientPin forcePINChange tests assert a
  *different* code for each: legacy `getPinToken` (0x05) → `CTAP2_ERR_PIN_INVALID`
  (0x31) (`ClientPin1-NewPin F-1`, `ClientPin2-GetPinToken F-5`); the
  permissions-based `getPinUvAuthTokenUsingPinWithPermissions` (0x09) →
  `CTAP2_ERR_PIN_POLICY_VIOLATION` (0x37)
  (`ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions F-1`). Previously both
  returned `PIN_POLICY_VIOLATION`. The PIN verify itself still succeeds first, so the
  retry counter is untouched. `bcdDevice` `0x0773` → `0x0774` (0x05 fix); the 0x09
  branch followed at `0x0776`.

### Changed

- **Enterprise attestation: `ep` advertised + reflects state, type-1 eligibility
  enforced.** `getInfo` and the metadata statement carry the `ep` option (`false`
  until `authenticatorConfig` enableEnterpriseAttestation flips it `true`), so
  platforms and the conformance tool exercise the enterprise profile. EA is now
  performed only when warranted — platform-managed (type 2) for any RP,
  vendor-facilitated (type 1) only for an RP on a built-in list (empty in shipping
  firmware). Any enterpriseAttestation request now yields a basic_full (x5c)
  attestation: the org/EP cert + `epAtt` when EA is performed, or a non-enterprise
  basic_full with the device's own cert and no `epAtt` for a non-listed type-1 RP
  (CTAP2.1 §6.1.3, conformance Enterprise-Attestation F-6, which requires x5c). A
  request without enterpriseAttestation keeps the default self-attestation. The FIDO
  conformance test RPID is added to the type-1 list **only** under the
  conformance-only `ea-conformance-rpid` build feature, never in a shipped image.
  The metadata `upv` gains `{1,2}` and `{1,3}` and drops the non-MDS3
  `legalHeader`. `bcdDevice` `0x0770` → `0x0772`.
- **EdDSA (-8) and ES256K (-47) are no longer advertised in `getInfo.algorithms`
  or the metadata.** The FIDO conformance tool's shared `verifySignatureCOSE` maps
  only `-7`/`-35`/`-36` for elliptic curves, so it throws "hashFunction missing"
  verifying a packed self-attestation over an EdDSA or secp256k1 credential
  (`MakeCred-Resp P-06`). Both stay fully implemented — makeCredential negotiates
  `-8`/`-47` from a request's `pubKeyCredParams` — only the advertisement is dropped
  (the same approach as ML-DSA-44), leaving the advertised set at the
  tool-verifiable NIST curves ES256/ES384/ES512. getInfo, `authenticationAlgorithms`
  and `authenticatorGetInfo.algorithms` kept in sync (`tests/62`). `bcdDevice`
  `0x0772` → `0x0773`.
- **`getInfo` advertises the `authenticatorConfigCommands` member (`0x1F`).** It
  lists the supported `authenticatorConfig` (0x0D) subcommands —
  `enableEnterpriseAttestation` (0x01), `toggleAlwaysUv` (0x02) and `setMinPINLength`
  (0x03). The FIDO conformance AuthenticatorConfig suite requires it (the
  enable-enterprise-attestation test asserts the array contains `0x01`, the
  "featureful" CTAP2.3 profile requires `0x02`, and the suite's `before` hook reads
  it). Mirrored in the metadata statement. Shares the `0x0774` bump (`0x02` arrived
  with alwaysUv at `0x0775`, below).

## [0.2.4] — 2026-06-19

### Added

- **The `rsk` CLI can run without Nix.** A `tools/pyproject.toml` packages the
  CLI so it installs from any Python ≥ 3.9 toolchain —
  `uvx --from ./tools rsk …`, `uv tool install ./tools`, `pipx install ./tools`,
  or plain `pip`. The Nix dev shell stays the primary, pinned path; this mirrors
  its CLI runtime deps (`hidapi`, `cryptography`, `pyscard`, `fido2`,
  `mnemonic`, `shamir-mnemonic`) for hosts without Nix. See
  [tools/README.md](tools/README.md). Host-tool only; no `bcdDevice` bump.

### Changed

- **FIDO2 PIN entry is now uniform across the CLI.** Commands disagreed on how
  to take a PIN: most accepted only `--pin` (and aborted on a PIN-protected
  device when it was omitted), while `fido list-passkeys` and `fido set-pin`
  prompted interactively with no flag at all. Every PIN-gated command (`backup
  export`/`restore`, `audit log`/`verify`, `lock enable`/`disable`, `inventory
  verify`, `fido list-passkeys`/`set-pin`/`attestation import`/`clear`) now
  accepts the PIN **either** way — `--pin` flag **or** an interactive prompt —
  through one chokepoint (`rsk.common.resolve_pin`) that only prompts when the
  device actually has a PIN, so touch-only devices are never asked. Host-tool
  only; no `bcdDevice` bump.
- **The `rsk-tui` cockpit now routes PIN entry through one chokepoint too.** Its
  four per-action PIN steps collapsed into a single `App::gate_pin` +
  `Step::PinThenRun`, so "prompt for the FIDO2 PIN iff the device has one, else
  run" lives in exactly one place (mirroring the CLI's `resolve_pin`). PIN-vs-
  phrase collection in the modal flow is now explicit instead of a catch-all (a
  stray text input can no longer land in the PIN buffer), and the four
  `device requires a PIN` strings were unified. No behaviour change for users;
  host-tool only, no `bcdDevice` bump.

### Fixed

- **`rsk secure-boot` no longer refuses provisioning on a chip with a benign
  `LOCK_NS`.** `pages_locked()` read the whole OTP lock row, so a pre-set
  non-secure-page lock (`LOCK_NS=1`, `0x040404`) looked like a bootloader lock
  and wrongly blocked `load-key`; it now masks `LOCK_BL` specifically. Host-tool
  only; a mutation-proven regression test was added.

### Security

- **Transparency-log monitoring for our release signing identity.** A scheduled
  GitHub Action (`sigstore/rekor-monitor`) watches the Rekor log for entries
  signed under our release workflow's OIDC identity, so illegitimate use of it —
  a signature we did not produce — becomes detectable, complementing the SLSA
  Build L3 provenance. CI only; see `docs/supply-chain.md`.
- **OATH credential secrets are now sealed at rest.** Every other applet
  (FIDO, PIV, OpenPGP, rescue) AES-encrypts its keys before they reach flash;
  OATH alone stored its TOTP/HOTP shared secrets — and the SET CODE key — as
  plaintext TLV. They are now AES-256-GCM-sealed under the device `kbase`
  (`HKDF(serial_hash, kbase, "OATH/KEYS")`), the same device-seal the PIV slot
  keys use. A one-time boot migration re-seals any credential enrolled before
  this release, so existing accounts keep working. With the OTP MKEK burned, an
  extracted flash image no longer reveals OATH secrets. `bcdDevice` `0x0765` →
  `0x0766`.
- **The at-rest seal path is now enforced by types, not convention.** A slot
  that holds a sealed secret is a `KeyFid`, distinct from a plaintext `u16` file
  id, and the only writer that accepts one is `Fs::put_key(KeyFid, Sealed)` —
  where `Sealed` is produced only by a seal routine. A stray
  `fs.put(key_fid, raw_secret)` no longer compiles (asserted by a `compile_fail`
  doctest). This is the chokepoint whose absence let OATH ship its secrets in
  the clear; every applet's key FIDs were moved onto it.
- **Resident-credential RP domains are now boxed at rest.** A discoverable
  credential's `EF_RP` record stored the relying-party id (the site's domain)
  in cleartext, so a flash dump revealed the *list of sites you hold passkeys
  for* — a privacy leak, even though the keys themselves were sealed. The domain
  is now ChaCha20-Poly1305-boxed under the device seed (the same seal the
  credential body uses), with the rpId **hash** kept in cleartext as the O(1)
  lookup key. A boot migration re-boxes records enrolled before this release.
  Honest residual: the rpId hash remains, so a dump can still *dictionary-attack*
  guessable domains — but the plaintext site list is gone. `bcdDevice` `0x0766`
  → `0x0767`.

## [0.2.3] — 2026-06-18

### Changed

- **LED turns green (idle) as soon as the host configures the device**, instead
  of staying on the red boot status until the first applet command arrives. A
  healthy, enumerated key that nothing is talking to yet — e.g. a Linux host with
  no PC/SC daemon running — used to look dead (red) even though it was ready. A
  device-level USB `Handler::configured` callback now flips the status on
  configuration. `bcdDevice` `0x0764` → `0x0765`.

### Fixed

- **~90 s boot stall (LED stuck on the red BOOT status) on some RP2350 boards.**
  `FidoRng::new` seeds the HMAC-DRBG with 48 bytes from the hardware TRNG, and
  the embassy driver runs an autocorrelation health-check on every generated
  block — on a failed check it soft-resets and re-samples in a loop. At the
  default `sample_count` of 25, consecutive ROSC samples on a marginal unit are
  too correlated, so the check failed almost every time and seeding blocked a
  variable 30–105 s on **every** boot (init runs before the USB pull-up, so the
  device was simply absent from the bus that whole time — looked dead, worst on
  strict hosts). Raising `sample_count` to 1000 decorrelates the samples so the
  check passes first try: **~1.5 s boot, HW-verified** on the affected board.
  Entropy quality is unchanged — the NIST health checks stay enabled and the
  source is the same; the seed is just gathered reliably. `bcdDevice` `0x0763`
  → `0x0764`.

- **PIV tab *still* slow after the present-cache fix below: `GET METADATA` over
  empty key slots.** That bitmap guarded `read` and `size`, but `has_data` — a
  third absent-probe method — still called the backend directly, so a missing
  FID scanned the whole partition. PIV `GET METADATA` checks `has_data(slot)`
  first, and `ykman piv info` / Yubico Authenticator's PIV tab read metadata for
  ~24 mostly-empty slots (`9A/9C/9D/9E` + 20 retired), so each tab switch paid
  ~24 full scans ≈ 4 s of green-blinking even though every individual APDU
  answered in ~30 ms. `has_data` now consults the same bitmap → `O(1)` for an
  absent slot; measured `ykman piv info` **4.16 s → 0.26 s** (~16×) on hardware.
  `bcdDevice` `0x0762` → `0x0763`.

- **Slow applet listing (PIV especially), seen as long green-blinking when
  switching tabs in Yubico Authenticator.** A backend `read`/`size` of an
  *absent* file scanned the entire ~1.4 MB KV partition to confirm absence, so
  enumerating a sparse object range was `O(slots · flash)` — opening the
  Certificates tab probes ~25 mostly-empty PIV certificate slots, each a full
  scan. (OATH had the same class of bug, fixed earlier; PIV/others did not.) The
  filesystem now keeps a fixed present/absent bitmap of all FIDs (rebuilt on
  boot, maintained on every write/remove), so an absent `read`/`size` returns
  without touching the backend — `O(1)` instead of a full scan. `bcdDevice`
  `0x0761` → `0x0762`.

- **USB enumeration race at boot (first field report).** On a Waveshare RP2350
  the device would "blink red and not be recognised," recovering only after
  several replugs. `builder.build()` asserts the bus pull-up, so the host begins
  enumerating the moment the device attaches — but the task that answers control
  transfers (`usb_task`) was spawned only after a block of per-boot init (seed +
  attestation cert + OpenPGP DEK + flash writes, heaviest on a fresh device). The
  host enumerated into an attached-but-mute device and timed out the first
  descriptor request; a lenient host (macOS) usually won, a strict one often did
  not. Boot now completes all that init **before** attaching, and spawns
  `usb_task` immediately after `build()`, so enumeration is serviced with no
  blocking gap. `bcdDevice` `0x0760` → `0x0761`.

## [0.2.2] — 2026-06-15

No firmware change — `bcdDevice` stays `0x0760` and the eight `.uf2` images are
bit-identical to 0.2.0. This release ships the fixed, hardened release pipeline:
0.2.0 published its GitHub Release without provenance, because the SLSA
generator's "append the provenance to the release" model is incompatible with
GitHub's immutable releases (the late asset upload is rejected — even on a draft).

### Changed

- Build provenance now uses GitHub's native `attest-build-provenance`, generated
  from inside a **reusable workflow** (`release-build.yml`). Running the build
  and the attestation in an isolated, identity-bound reusable workflow raises the
  release to **SLSA v1 Build Level 3** (an inline attestation step alone is only
  Build L2). Each `.uf2` is attested keyless (Sigstore/Fulcio + the Rekor log)
  into the **attestation API** instead of being uploaded as a release asset, so
  it stays compatible with immutable releases. Verify with
  `gh attestation verify --signer-workflow …` (`docs/supply-chain.md`).
- All GitHub Actions bumped to their current major versions (off the deprecated
  Node 20 runtime).

## [0.2.0] — 2026-06-15

The cycle since 0.1.0. USB `bcdDevice` is now `0x0760` (incremented once per
firmware change along the way).

### Added

- **Own AAGUID + FIDO Metadata Statement.** The authenticator reports its own
  model identity (`2479c7bf-6b30-5683-9ec8-0e8171a918b7`, a reproducible UUIDv5)
  instead of the inherited pico-fido one, and ships a self-published FIDO
  Metadata Statement (`metadata/rs-key.metadata.json`) with a drift guard.
- **Supply-chain provenance.** Releases now carry SLSA build provenance
  (slsa-github-generator, keyless) and pass a release-time reproducibility gate
  that rebuilds all eight flavors bit-identical before anything is published.
- **Dependency review.** A `cargo-vet` gate (Mozilla / Google / ISRG / Zcash
  audits + recorded exemptions) blocks new unreviewed crates; a new
  `docs/supply-chain.md` documents the whole chain.
- **Versioned documentation site** — `main`, `develop` and tagged versions are
  published side by side with a switcher.
- **Kani proofs** that the OpenPGP import (BER) parser is panic-free and
  terminating, plus a CI guard that `flake.lock` stays in sync with `flake.nix`.

### Changed

- Every GitHub Action is pinned to a commit SHA, kept fresh by Dependabot.
- The physical-attack posture docs are reframed around the published RP2350
  hacking challenges (threat model / OTP fuses / limitations).

### Fixed

- **U2F routing.** A vendor-AID SELECT over CTAPHID_MSG no longer leaves a sticky
  applet selection that routed later U2F REGISTER / AUTHENTICATE / VERSION into
  `0x6D00`; the MSG selection is dropped on every CTAPHID_INIT.
- **OATH performance.** RESET / LIST / CALCULATE-ALL / lookup probed all 255
  credential slots, and each absent slot rescanned flash; they now touch only
  present credentials — OATH RESET dropped from ~39 s to ~0.5 s.
- **USB transport wedge.** Bounding the CTAPHID/CCID IN-endpoint writes stops an
  abandoned transaction from wedging the interface until a replug.
- The OpenPGP card-status self-test now follows GET DATA response chaining.

### Security

- **Constant-time audit fixes** — RSA base blinding on the raw path and
  constant-time OTP access-code comparisons (`docs/ct-audit.md`).
- **Fault-injection fences** on the PIN and secure-boot gates, so a glitched
  single comparison can't skip the check.

## [0.1.0] — 2026-06-13

First public release — an open-source security-key firmware for the Raspberry Pi
RP2350 (Cortex-M33), a behavioral reimplementation of the AGPL-3.0 pico-keys
family that keeps the "enterprise" features in the open tree.

### Security keys / protocols

- **FIDO2 / WebAuthn / U2F** — passkeys (discoverable credentials), second-factor,
  `ssh -t ed25519-sk`, hmac-secret and largeBlobs; user presence gated on the
  BOOTSEL button (the default touch build).
- **OpenPGP card 3.4** — sign / decrypt / authenticate; EC (Ed25519, NIST, brainpool)
  and on-card RSA keygen (2048/3072/4096) accelerated across both cores.
- **PIV** — X.509 slots, attestation, the Yubico management extensions; works
  through PKCS#11 / OpenSC and the OS-native stacks.
- **OATH (YKOATH)** — TOTP / HOTP credential store.
- **Yubico OTP** — slot programming and challenge-response over CCID, plus the
  HID-keyboard typing path.

### Enterprise features, in the open tree

- forceChangePin enforcement, a SHA-256-chained signed audit trail, an opt-in
  `fips-profile`, organizational attestation (import key + chain), and host-side
  fleet inventory / verification / offboarding tooling.

### Hardening

- Secure boot + anti-rollback (RP2350 OTP), keys sealed under an OTP-burned
  device root, and an at-rest soft-lock of the FIDO seed.

### Tooling

- The `rsk` CLI and the `rsk-tui` ratatui dashboard; guided primary + backup
  device pairing; secure-boot key-rotation tooling. Run without the dev shell via
  `nix run .#rsk`, `.#rsk-tui`, and a one-command flasher `.#flash`.

### USB identity

- The default build presents this project's **own** pid.codes identity
  (`0x1209:0x0001`, "RS-Key Security Key") — not a YubiKey masquerade. An opt-in
  `VIDPID=Yubikey5` flavor borrows the YubiKey identity for `ykman` / Yubico
  Authenticator interop.

### Assurance

- 39 fuzz targets, Kani proofs, a Miri pass, power-cut torture, bit-reproducible
  `nix build` images (per platform, per `flake.lock`), and a hardware-verified
  interop matrix ([docs/interop.md](docs/interop.md)).

### Release artifacts

- Eight firmware flavors (`up-button` × `advertise-pqc` × `fips-profile`), each a
  reproducible **unsigned** `.uf2` — on a secure-boot device, seal it with your
  own key before flashing (`nix run .#flash`, or see
  [docs/production.md](docs/production.md)).
- `SHA256SUMS` over every artifact, a keyless [cosign](https://docs.sigstore.dev/)
  signature of it, and a CycloneDX SBOM. See
  [docs/releases.md](docs/releases.md) to verify a download.

[Unreleased]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/TheMaxMur/RS-Key/compare/v0.2.8...v0.3.0
[0.1.0]: https://github.com/TheMaxMur/RS-Key/releases/tag/v0.1.0
