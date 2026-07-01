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

### Security

- **Security-audit run-2 + run-3 hardening.** Fixed the outstanding findings from
  two further agentic audits (bcdDevice `0x07D8`; `rsk` 0.3.1; `rsk-tui` 0.2.1):
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

- **Security-audit hardening (six-phase agentic audit).** A fresh full-tree audit
  found and fixed:
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

### Added

- **Documentation: a trusted-display guide.** The screen-and-touch build now has its own page
  ([`docs/guides/display.md`](docs/guides/display.md)) covering the build and flashing, the
  Approve / Deny anti-phishing prompt, on-screen PIN entry (built-in UV + CCID pinpad), the
  Passkeys and Apps browsers, Settings, and the security model.

- **Trusted-display: every PIN screen names which credential it's asking for, and a fresh
  device offers to set a PIN.** The on-screen PIN pad now titles each entry with the
  credential it collects — **Device PIN**, **FIDO PIN**, **PIV PIN** / **PIV PUK**, or the
  OpenPGP PINs — so the four independent PINs can no longer be confused (the New / Confirm /
  current step moves to the caption line beneath, keeping the scope label fixed at the top).
  And on a fresh, PIN-less device the panel shows a one-time **Set a PIN?** prompt at first run
  (*Set a PIN* / *Continue without PIN*); choosing to continue without one is remembered (a
  flag in the `EF_DISPLAY` record, forward-compatibly extended), so the offer isn't repeated
  until a factory reset. bcdDevice 0x07CB → 0x07CC.

- **Trusted-display + PIV: set a PIN-protected random management key on the panel (ykman
  `--protect`).** Settings → Security → PIV PIN gains a **Protect mgmt key** action: the device
  generates a fresh random AES-256 management key, seals it, and marks it PIN-protected, so a
  host (`ykman piv …`) can then use it with just the PIV PIN — you never have to carry the
  24-byte key. The applet now serves the YubiKey ADMIN-DATA (`5FFF00`) and PRINTED (`5FC109`)
  objects: the management key is read back from PRINTED only after a PIN VERIFY **and** only once
  protected (a default/plain key is never PIN-readable), and it is synthesized from the sealed
  auth slot — there is no second copy at rest. `ykman piv access change-management-key --generate
  --protect` now works over USB too. **Security:** once protected, the PIV PIN alone grants PIV
  admin (it unlocks the random key) — the panel states this plainly and gates the action behind
  the device PIN and a deliberate hold. bcdDevice 0x07CA → 0x07CB.

- **Trusted-display: change the PIV PIN and PUK, and unblock a blocked PIN, on the panel.**
  Settings → Security gains a **PIV PIN** entry that opens a sub-menu — *Change PIN*,
  *Change PUK*, and *Unblock PIN* (reset a PIN blocked by too many wrong tries, using the PUK),
  so PIV PIN management no longer needs a host. Each op is gated by the current PIN/PUK exactly
  like the host CHANGE REFERENCE DATA / RESET RETRY APDUs (no management key); the PIV applet's
  own retry counter is shown and enforced, and a blocked PIN/PUK shows the lockout notice. The
  PIN/PUK are stored padded to the 8-byte `0xFF` PIV wire form, so a host VERIFY (ykman /
  yubico-piv-tool, which always pad) accepts a panel-set value — a host-tested round-trip locks
  this in. The change / unblock logic moved into host-tested `rsk-piv` functions shared with the
  APDU handlers. The PIV *management key* stays host-only for now (a 24-byte AES key can't be
  typed on a numeric pad). bcdDevice 0x07C9 → 0x07CA.

- **Trusted-display: the brightness, display-sleep and touch-timeout settings persist across
  reboots.** Edits made in Settings → Display used to reset to their defaults on the next power
  cycle; they now survive it. Brightness and the display-sleep timeout are stored in a new
  `EF_DISPLAY` flash record (a 3-byte block — `[brightness, sleep_secs]` — with a pure,
  host-tested + Kani-proved codec in `rsk-ui`, read at boot so the panel comes up at the saved
  brightness with no full-bright flash). The touch timeout is written back to `EF_PHY`'s
  existing `PresenceTimeout` tag — the same field `rsk hw --touch-timeout` and the boot path
  already read and write — so there is one source of truth (last writer wins; an on-panel edit
  snaps to the menu's choices). The record is rewritten once when you leave Settings (not per −/+
  tap, and only when a value actually changed), and an older/newer record loads
  forward-compatibly. bcdDevice 0x07C8 → 0x07C9.

- **Trusted-display: the on-device keygen spinner animates during the RSA prime search.** The
  *Generating…* screen's indicator arc now spins while an on-device RSA key is generated, so it
  reads as actively working rather than hung — important for RSA-4096, whose search can take a
  minute-plus. The search is a blocking dual-core busy-loop that owns the core, so the panel
  can't repaint from a loop; instead a new `run_rsa_search_progress` hook (invoked once per prime
  candidate, off the keygen state) drives the arc, throttled to ~100 ms so the SPI repaints don't
  slow the search. bcdDevice 0x07C6 → 0x07C7.

- **PIV: RSA-3072 and RSA-4096 keys, including on-device generation (display builds).** PIV gained
  RSA-3072/4096 across generate, import, sign/decrypt, attestation and metadata — the applet's
  buffers were lifted off their long-standing RSA-2048 ceiling (the at-rest seal, the on-card
  X.509 builder, the GENERAL AUTHENTICATE and metadata paths). On the trusted display, the
  on-device **Generate key** chooser (PIV → Retired & F9) now offers RSA via a size sub-picker
  (**2048 / 3072 / 4096**) alongside the four curves. RSA runs the firmware's **dual-core** prime
  search (the same one the USB GENERATE uses) behind a *Generating…* screen — the panel freezes
  while it runs (a few seconds for 2048, up to a minute-plus for 4096) with USB / CCID keepalives
  still flowing on interrupts. Same authorisation and fence as the curve path: device PIN (when
  set) + a deliberate hold, empty retired slots only (add a key, never overwrite), self-signed
  cert + sealed key written exactly as a host GENERATE. RSA-1024 (weak / FIPS-disabled) is still
  not offered on-device. bcdDevice 0x07C4 → 0x07C6.

- **PIV: Ed25519 and X25519 keys (algorithm ids `0xE0` / `0xE1`, Yubico 5.7 PIV).** The PIV
  applet now generates, imports and uses Curve25519 keys alongside RSA and the NIST curves.
  **GENERATE** mints an Ed25519 key with an RFC 8410 self-signed certificate (id-Ed25519 SPKI,
  PureEdDSA over the TBS); X25519 is key-agreement-only and cannot self-sign, so it is stored
  with no auto-certificate (a host/CA provisions one later via PUT DATA). **GENERAL
  AUTHENTICATE** signs with Ed25519 (the raw message, bare 64-byte signature) and performs
  X25519 key agreement (`ykman piv calculate-secret`); **IMPORT** accepts the raw 32-byte
  seed / scalar (yubikit tags `0x07` / `0x08`); **GET METADATA** and attestation cover both.
  Interoperates with `ykman`. The same curves are offered by the on-device **Generate key**
  chooser on display builds (four rows now: P-256 / P-384 / Ed25519 / X25519). EdDSA is FIPS
  186-5-approved and X25519 is widely deployed, so the `fips-profile` does not restrict either.
  No proprietary wire change (standard NIST SP 800-73 / Yubico PIV). bcdDevice 0x07C3 → 0x07C4.

- **Trusted-display applet detail screens — OATH / OpenPGP / PIV, plus on-device PIV key
  generation (display builds).** The applet hub gained the detail screens that the overviews
  only hinted at. **OATH:** each credential row now drills into a detail showing its type
  (TOTP / HOTP), HMAC algorithm, digit count, TOTP step (the `<period>/` name prefix, default
  30 s) and touch gate — still no code (the device has no clock). **OpenPGP:** the overview
  gained a **Card holder** row opening a detail card with the public cardholder name, login,
  URL and language (all plaintext, no PIN). **PIV:** the overview gained a **Retired & F9** row
  opening a paged list of the populated retired key-management slots (82–95) and the F9
  attestation slot, each drilling into the shared slot-detail. From that screen a **Generate
  key** action creates an EC key (P-256 / P-384) on-device into the next free retired slot —
  gated on the device PIN (when set) and a deliberate hold, EC only (RSA's prime search would
  block the panel), and restricted to *empty* retired slots so it can only add a key, never
  overwrite one (the four primary slots and F9 stay USB-managed; there is no management-key auth
  — physical presence at the panel is the authorisation). The read paths are plaintext / device
  metadata; no PIN, DEK or host session. No protocol or wire-format change. bcdDevice 0x07C1 →
  0x07C3 (the **Card holder** row carries a new person `User` glyph; the generate-confirm screen
  is a chrome-less modal so its cancel chevron no longer overlaps the status bar).

- **Trusted-display Settings regrouped by domain (display builds).** The Settings root was a
  flat list of five unrelated rows; it is now three domains — **Display** (Brightness, Display
  sleep, Touch timeout), **Security** (the existing PIN / Audit / Backup / Factory-reset
  sub-page), and **Firmware** last (a rarely-touched maintenance action). The three panel knobs
  moved under a new Display sub-page, each still drilling into its −/+ adjust page (which now
  backs out to Display, not the root). No protocol or wire-format change. bcdDevice 0x07C0 →
  0x07C1.

- **Trusted-display polish wave 2 — grouped cards, Settings nav, service icons, motion
  (display builds).** Every list now reads as one grouped surface with hairline dividers — the
  Home status card (USB / device PIN / passkey count), the Passkeys and service-detail lists,
  the Apps / OpenPGP / PIV / OATH lists, the audit log, and the Backup fact rows — instead of a
  stack of separate pills (the design's grouped-card look). **Settings** is now a full peer of
  the other tabs: its root screen carries the four-tab bottom nav (Settings active) so you can
  switch tabs from it, rather than only backing out to Home. Service rows gain the design's icon
  chip behind each glyph, and an SSH relying party shows a new terminal (`>_`) glyph instead of
  the generic globe; the boot splash gains a shield brand mark. The screens the design animates
  now move: the **"Working…"** spinner arc rotates, the locked **"Touch to unlock"** hint
  breathes, and the rename caret blinks (each a small in-place repaint on the display loop, so
  the idle hot path and its flicker-free guarantees are untouched). No protocol or wire-format
  change. bcdDevice 0x07BF → 0x07C0.

- **Trusted-display UI polish (display builds).** A fit-and-finish pass over the on-device
  screens. Over-long labels and titles now end in an ellipsis ("Authenticat…") instead of being
  cut mid-glyph — fixing a text-measurement bug where a label that "fit" by a pixel had its last
  glyph's right edge clipped (a `d` rendered as a `c`): proportional width is now measured to the
  rightmost ink (left bearing + ink width), not the ink width alone, so a clip is correct across
  every screen. The applet item counts read grammatically ("1 slot", not "1 slots"). The busy
  **"Working…"** status screen is a blue ring-and-arc spinner on a dim track instead of a flat
  filled disc. The brightness / touch-timeout / display-sleep adjust pages back out via the
  standard title-bar chevron like every other screen, dropping the odd full-width grey "Back"
  slab. No protocol or wire-format change. bcdDevice 0x07BE → 0x07BF.

- **On-device OpenPGP / PIV / OATH screens behind a unified "Apps" hub (display builds).**
  The bottom navigation gains a fourth tab — **Apps** (a 2×2 grid glyph) — between Passkeys and
  Settings, and every tab now carries a caption under its icon (the four tabs are tighter at
  60px each). The Apps tab opens an **applet chooser** (OpenPGP / PIV / OATH, each with a live
  item count) that drills into a read-only screen per applet. **OpenPGP** lists the three key
  slots (Signature / Encryption / Authentication) with each one's algorithm (Ed25519, Cv25519,
  NIST P-256, RSA 2048, …), the signature counter, and the remaining PW1/PW3 attempts; a present
  slot drills into a detail card showing the algorithm, touch policy, whether a generation time
  is recorded, and the full 40-hex SHA-1 fingerprint. **PIV** lists the four primary slots
  (9A/9C/9D/9E) with each one's algorithm (or "cert" when only a certificate is stored) and the
  remaining PIN/PUK attempts; a populated slot drills into a detail card with the PIN policy,
  touch policy, key origin (Generated / Imported), and certificate presence. **OATH** lists the
  stored credentials (label, TOTP/HOTP, and a padlock when touch-gated); no code is shown — the
  device has no clock for time-correct TOTP, so codes are still read in the host app. Every fact
  is read **plaintext / device-sealed without a PIN** (new host-tested `read_info` readers in
  `rsk-openpgp` / `rsk-piv` and a `for_each_cred` enumerator in `rsk-oath`); no key material,
  PIN, or public point is ever surfaced (the OpenPGP public key isn't reconstructable without a
  PIN, by design). All screens are read-only — no on-device mutation, so no PIN gate. **Every
  OpenPGP / PIV slot row is tappable** and drills into its own detail, even when empty — an
  unprovisioned slot's screen names the slot's role (e.g. "Signs data and commits",
  "Authentication / login") and how to set it up over USB, rather than being an inert row. No
  protocol or wire-format change. bcdDevice 0x07BC → 0x07BE.

- **Design-fidelity polish of the trusted-display UI (display builds).** A visual pass that
  brings the on-screen widgets closer to the handoff and reads more finished. The
  hold-to-confirm buttons are now a **solid fill** (primary blue / danger red) with a lighter
  progress wash growing over them, instead of a dark outline that filled in. Every list /
  settings row is a **bordered card** (1px hairline + 11px corners) rather than a borderless
  tile, and a destructive row is red-tinted. The idle **Home** screen shows a calm white
  "Ready" beside the status check and a **three-row status card** backed by live data — USB,
  whether a **device PIN** is set, and the **resident-passkey count** (read from a cache
  refreshed only at modal boundaries — boot, wake, a closed tab — never per idle frame, so it
  never triggers a per-paint flash scan). The **Factory reset** confirm is a proper destructive
  ceremony — a red warning disc, a danger-red triangle (not amber), an "Erase RS-Key?" headline,
  and a red-dot list of what gets wiped. The muted/caption text tiers are tightened (audit
  timestamps and row glyphs sit one shade dimmer, matching the design hierarchy). No protocol or
  flag change. bcdDevice 0x07BA → 0x07BB.

- **Redrawn icon set for the trusted-display UI (display builds).** The vector glyphs are cleaner
  and instantly readable at the small list-row (14px) and nav (20px) sizes they are used at, not
  just the large headline sizes. The previous "mirror the buffer" symmetry pass was the root of
  the breakage — its union fill turned a ring (clock, gear) into a solid blob and erased centred
  axis strokes on an even box (the USB cable, the globe meridian, the sun's rays). It is replaced
  by symmetry **by construction** plus two guarantees in the renderer: a non-destructive symmetry
  pass (mirror the canonical half, restore the centre band) that makes a claimed axis exact
  without filling, and an **auto-centre** step that shifts each glyph's ink to equal margins on
  every side. Several glyphs were redrawn so they read at a glance — USB (plug + cable), globe
  (disc + equator + meridian), gear (open bore vs the sun's solid core), eye, lifebuoy, shield,
  house, clock. No protocol or flag change. bcdDevice 0x07BB → 0x07BC.

- **On-device PIN entry for OpenPGP & PIV over CCID (secure pinpad, experimental; display builds).**
  The trusted-display build now advertises itself as a **CCID pinpad reader** (`bPINSupport` =
  VERIFY) and handles `PC_to_RDR_Secure` (`0x69`): when the host driver asks for a secure PIN
  verify, the **PIN is typed on the device's own touchscreen** and the device assembles and runs
  the VERIFY APDU itself, so the secret is never placed in a USB transfer. Works with **GnuPG**
  scdaemon (OpenPGP PW1/PW2/PW3) and **OpenSC** (PIV application PIN). The pad shows which PIN it
  is collecting; a wrong PIN returns the card's real status word (`63 Cx` tries left / `69 83`
  blocked), and a cancel/timeout on the pad maps to the CCID `bError` the host surfaces as
  cancelled/timed-out. The CCID transport streams time-extensions for the whole on-screen entry,
  so the host transaction doesn't time out. Honest scope: this keeps the PIN off the wire **when
  the host uses pinpad mode** — it does not, on its own, prevent a host that chooses to send a
  plaintext VERIFY; an opt-in device-enforced mode is a planned follow-up. Host-tested
  structure-parse + APDU-assembly logic lives in the new `rsk-usb` `secure_pin` module; the
  firmware is the glue that collects the PIN and dispatches. The PIN pad's title now names
  which PIN it is collecting ("OpenPGP Sign PIN" / "PIV PIN" …); a title too wide for the
  header band **scrolls as a marquee** so it never collides with the back chevron (composited
  into a 1-bit off-screen mask and blitted in one transaction, so the scroll is flicker-free).
  The Settings list also drops its row below the title-bar back chevron (a clear gap so a reach
  for back can't hit the first item) and removes the redundant **Lock now** row (the UI
  auto-locks on sleep). bcdDevice 0x07B6 → 0x07BA.
- **On-device Firmware screen with reboot-to-update over USB (experimental).** The trusted
  display's Settings list now opens a **Firmware** screen (replacing the read-only device-info
  page): the installed `bcdDevice` build shown inline on the row and as a headline, the chip
  serial, and an honest update story. This authenticator can't discover firmware updates on its
  own, so the screen does not fabricate a "newer version available" — it states the real
  mechanism: the RS-Key host app delivers an image **over USB**, and — **when secure boot is
  fused** — the RP2350 boot ROM **verifies its signature before it runs**. The screen reads the
  device's real OTP secure-boot state and only claims that check when it is on, otherwise
  warning that updates are unverified (the trusted display never vouches for a check the
  silicon isn't doing). A deliberate (blue) **Hold to update** queues a
  secure reboot into the BOOTSEL bootloader so the host can flash; the reboot routes through the
  worker (not a raw ROM call from the display task) so the live RAM secrets — the FIDO auth
  state and the DRBG — are scrubbed before the device drops to BOOTSEL, and the worker services
  the request on its idle button-poll tick so it lands without waiting on a host command. New
  `Glyph::Cpu`, `render_firmware`/`render_rebooting`, and a `run_firmware` hold sub-flow.
  bcdDevice 0x07B5 → 0x07B6.
- **On-device SLIP-39 Shamir share display — split the seed on the screen (experimental).**
  The trusted-display recovery reveal now offers a **format chooser**: a single BIP-39 phrase
  (as before), or **`T`-of-`N` SLIP-39 Shamir shares** rendered **on the device** so no share
  ever crosses USB. After the one device-PIN re-auth, **Shamir shares** opens a `T`/`N` picker
  (default **2-of-3**, configurable on-panel), then a deliberate hold over the warning, then
  each 33-word share page-by-page with a "Share i/N" title and a global pager. The shares are
  split from the device DRBG and are **bit-for-bit recombinable by `rsk backup restore
  --scheme slip39`** (single group, non-extendable, iteration exponent 1, empty passphrase —
  matching the host `shamir_mnemonic`), so any `T` of the `N` written-down shares reconstruct
  the FIDO seed. The seed is wiped the instant the shares are derived; the share words on exit.
  The SLIP-39 encode lives in a new host-tested `rsk-slip39` crate whose 1024-word wordlist is
  checksum-pinned and whose output is verified against the host library bit-for-bit (golden
  vectors), with a Kani proof bounding the word indices. Display flavor only; disabled on a
  `fips-profile` device (non-exportable seed). bcdDevice 0x07B4 → 0x07B5.
- **On-device recovery-phrase display — the seed never crosses USB (experimental).** The
  trusted display can now show the device's **24-word BIP-39 recovery phrase on its own
  screen**, derived **on the device** from the master seed, so the seed is never exported to
  a host to be backed up. From Settings → Security → Backup (while the backup window is open
  and **a device PIN is set** — the master secret is never surrendered on a bare gesture),
  **Show recovery phrase** re-enters the device PIN, takes a deliberate hold over a "no one
  watching?" warning, then paints the 24 words (two numbered pages). The seed is
  zeroized the instant the words are derived; the word indices are zeroized on exit and the
  screen auto-clears on idle (walked-away guard). A **Seal backup** action closes the one-time
  window on-device (hold-gated) so the phrase can no longer be shown or exported until a
  factory reset — mirroring the host `BACKUP_FINALIZE`. The existing USB seed-export path is
  unchanged (it coexists). The on-device BIP-39 encode lives in a new host-tested `rsk-bip39`
  crate whose embedded English wordlist is checksum-pinned to the canonical BIP-39 list and
  whose output is verified against the host `mnemonic` library bit-for-bit (so on-device
  encode == host `rsk backup restore`); a Kani proof bounds the word indices. Display flavor
  only; disabled on a `fips-profile` device (non-exportable seed). bcdDevice 0x07B3 → 0x07B4.
- **Seed-backup status screen on the trusted display (experimental).** Settings → Security
  now has a read-only **Backup** page showing the seed-backup state the device genuinely
  tracks: whether a recovery seed is present and whether the one-time export window has been
  **sealed**. A colour-coded status plate reads **Review needed** (export window still open),
  **Export sealed** (window closed), **No recovery seed**, or **Restore-only** (a
  `fips-profile` device, where the seed is non-exportable), over two fact rows and a hint that
  the host app drives the backup over USB. It is honest about the real backend — there is
  **no** fictional "N of M recovery shares" state, and the screen states only the export
  **window** state, never claiming a recovery copy exists (the device cannot verify an export
  happened): backup is a one-time seed export over the host MSE channel, then sealed.
  Read-only (no on-device action, shows no secret). The Security row reflects the window state
  as "Sealed" / "Review". Display flavor only. bcdDevice 0x07B2 → 0x07B3.
- **Dedicated device PIN, separate from the FIDO clientPIN (experimental, display flavor).**
  The trusted display now has its own **device PIN** (`EF_DEVICE_PIN`, device-sealed, its
  own retry counter) that gates **local control** — unlocking the on-device UI, deleting a
  passkey on-device, and factory reset — independent of the FIDO clientPIN. Settings →
  Security now offers **two** set/change flows: **device PIN** and **FIDO PIN** (each
  verifies its own current PIN first). The built-in-UV WebAuthn pad stays the FIDO clientPIN
  (CTAP requires it). The device boot-locks when a device PIN is set. A forgotten device PIN
  is recoverable by a host `authenticatorReset` (touch-only), which now also clears
  `EF_DEVICE_PIN` — mirroring how the FIDO PIN is recovered, since the lock gates on-device
  Settings. The FIDO clientPIN storage/verify path is byte-unchanged (the verify/store cores
  were parameterized by record FID; the standard screenless key is unaffected). bcdDevice
  0x07B0 → 0x07B2 (0x07B2 fixes a RefCell double-borrow panic when opening the Settings
  page — the two PIN-set flags are now read under one borrow).
- **PIN-entry reveal (eye) toggle on the trusted-display pad (experimental).** The
  on-screen PIN pad now carries an **eye toggle** beside the masked entry: tapping it shows
  the digits you have typed (and tapping again re-hides them), so you can check the PIN
  before committing — on **every** PIN screen, since the pad is shared by built-in UV, the
  unlock / delete / factory-reset gates, and set/change PIN. A revealed PIN **auto re-masks
  after a short idle** so a device left mid-entry doesn't keep the digits lit, and a PIN
  longer than the field shows a "+" overflow marker. The digits are only ever held in the
  firmware's buffer and painted transiently while revealed — never stored in the UI crate,
  never sent to the host. Display flavor only. bcdDevice 0x07AD → 0x07B0.
- **Add-passkey registration screen on the trusted display (experimental).** A WebAuthn
  **registration** (`makeCredential`) now shows the design's **"Save new passkey?"** card
  — a placeholder tile, the relying party + account being enrolled, and **Cancel** / **Save**
  (a tap; the deliberate hold stays reserved for sign-in) — instead of a bare Approve/Deny.
  The untrusted rp / account are clipped to the panel (centred when they fit, else
  left-clipped) so a long rp id can never overrun the trusted display. The **approve**
  screen (FIDO sign-in plus the generic OpenPGP/PIV/OATH/OTP touch prompts) is re-skinned to
  the status/title chrome — shield + operation title + relying-party header + amber caution —
  and the hold button is widened so "Hold to approve" sits fully inside it. Routed by a typed
  `ConfirmKind` (`Generic` / `Register`) on the shared `Confirm` context — a screenless key
  ignores it and is byte-unaffected. The small **back / cancel** affordances (title bar,
  the chrome-less modals, the PIN pad) are now drawn as **outlined buttons** with a larger
  chevron, so the tappable bounds are visible rather than a lone glyph (the PIN pad's title
  is re-centred between that button and the lock so a wide "Confirm PIN" can't slide under
  either). Display flavor only. bcdDevice 0x07A9 → 0x07AD.
- **PIN-entry indicator + "tries remaining" on the trusted display (experimental).** The
  on-device PIN pad now matches the design's `enterpin` / `createpin` / `confirmpin`
  screens: the entry row shows a row of **dim placeholder dots for the minimum length**
  that fill with the accent colour as digits are typed (a longer PIN grows past them),
  instead of a bare growing run. The on-device PIN gates — unlock, and the delete /
  factory-reset / change-current-PIN prompts — open with a muted **"N tries remaining"**
  line so the remaining attempts before lockout are visible up front (read from the same
  `EF_PIN` counter without spending a try); a wrong entry still swaps it for the
  danger-coloured "Wrong PIN, N left". The on-device **Set / Change PIN** steps gain
  matching muted hints — **"Choose a PIN"** then **"Re-enter to confirm"**. Pure on-panel
  feedback — no auth logic changed. Display flavor only. bcdDevice 0x07A8 → 0x07A9.
- **Rename a passkey on the trusted display (experimental).** A relying party's detail
  screen gains a pencil affordance (top-right of the title bar) that opens a character-wheel
  editor to set a short **device-local nickname**, shown in place of the rpId on both the
  detail screen and the Passkeys list. The nickname is a display-only label, **sealed at
  rest** (ChaCha20-Poly1305 under the device seed, rpIdHash as AAD) in a new EF_RPNICK
  region parallel to EF_RP; it is wiped by `authenticatorReset` and on-device factory reset,
  and dropped automatically when its RP loses its last credential. Crucially it **never
  touches the credential box**, so — unlike CTAP `updateUserInformation`, which reseals the
  box and rotates the signing key — renaming a passkey here leaves it fully working. Because
  it is device-local, the nickname is **not** reflected in host credential managers. Display
  flavor only. bcdDevice 0x07A7 → 0x07A8.
- **List paging on the trusted display (experimental).** The Passkeys list, a relying
  party's accounts, and the audit log now **page** through long sets instead of silently
  showing only the first few rows: a `‹` Prev / `›` Next bar with a "page / pages"
  indicator appears whenever a list spans more than one page (the end arrow dims when
  there is no further page). One reusable pager drives all three screens; the single-page
  case is unchanged (the item-count footer). Display flavor only. bcdDevice 0x07A6 →
  0x07A7.
- **On-device audit log (trusted display, experimental).** A new **Settings → Security →
  Audit log** screen shows the most recent device journal events — sign-ins, passkeys
  added, PIN changes, lockouts, lock changes, config changes, backups, factory resets and
  power cycles — newest first, each with a colour-coded status dot and, for events in the
  current power cycle, a compact "time ago" (the device has no wall clock, so entries from
  earlier boots show no time). Read-only: the full tamper-evident journal, with
  attestation, is still exported and verified host-side over `authenticatorVendor`. The
  reader is a lean visitor over the journal ring (no alloc, no CBOR), mirroring the
  passkeys browser. Display flavor only. bcdDevice 0x07A5 → 0x07A6.
- **On-device success screens (trusted display, experimental).** The three device-driven
  ceremonies that previously snapped straight back to the prior screen now end on a
  brief confirmation, matching the design's "pop" moments: a granted **Approve** shows
  a green-check **"Approved"** for ~0.4 s before the host ceremony resumes (auto-dismissing,
  so it barely delays the host); an on-device **passkey delete** shows **"Passkey deleted"**
  with a **Done** button; and a completed **factory reset** shows a grey rotate
  **"RS-Key erased / Restarting…"** before the device reboots into its fresh state. The
  success circle animates the design's scale-up "pop". Pure on-panel feedback — no auth
  logic changed. Display flavor only. bcdDevice 0x07A4 → 0x07A5.
- **On-device Set / Change PIN (trusted display, experimental).** The device PIN can now
  be set and changed entirely on the panel — no host. A new **Settings → Security**
  sub-page offers **Set PIN** (when none is set) or **Change PIN** (which first verifies
  the current PIN on the on-screen pad), then prompts for the new PIN twice; the two
  entries must match before it is stored. The PIN never leaves the device, and it is
  written as the **same `EF_PIN` verifier** (device-sealed, fresh retry budget) the host
  clientPIN setPIN/changePIN path stores — so afterwards the host sees a clientPIN exactly
  as if it had been set over USB, and a satisfied `minPINLength` policy (the pad enforces
  the floor and shows it) clears any pending forced-change marker. To make room without
  shrinking the touch targets, the destructive **Factory reset** moved from the Settings
  root into this Security sub-page (one tap deeper), matching the design's settings →
  security flow. A wrong entry on any on-device PIN pad (unlock, delete, factory reset,
  and the set/change current-PIN step) now shows a "Wrong PIN, N left" caption with the
  remaining attempts before lockout instead of a silent re-prompt, and a New ≠ Confirm
  mismatch shows "PINs don't match". When the retry budget is spent, a dedicated "PIN
  blocked" screen explains the lockout and that recovery is a host-side reset (every
  on-device action shares the one blocked `EF_PIN` counter). Display flavor only.
  bcdDevice 0x07A1 → 0x07A4.
- **Trusted-display lock / unlock (on-device UI lock, experimental).** The panel can
  now be **locked** so the on-device UI — the passkeys browser and Settings — needs the
  device PIN to reopen, showing a "Locked / Touch to unlock" screen; a tap opens the
  on-screen PIN pad and a correct PIN (verified against the same `EF_PIN` retry ladder
  as every other on-device gate) unlocks it. It locks **at boot**, on a new **Settings →
  Lock now** action, and automatically when the display sleeps on inactivity — all when a
  PIN is set, so a security key comes up requiring the PIN to reach its on-device UI. This
  gates **only** the on-device UI: host CTAP / WebAuthn ceremonies are unaffected (they
  paint their own trusted Approve / built-in-UV prompts and have their own verification),
  so a locked key still works as a security key. Display flavor only; no-op when no device
  PIN is set (nothing to unlock with). bcdDevice 0x079E → 0x07A1.
- **Trusted-display sleep (image-retention guard, experimental).** The panel now
  blanks itself — backlight off and the glass cleared — after an inactivity timeout,
  so a static screen can't burn a ghost into the IPS panel. A touch anywhere or the
  **sleep/wake button** restores it (the first touch/press only wakes; it isn't read
  as a tap), and an incoming host ceremony wakes it so the trusted prompt is always
  visible. The button is a power-button-style toggle — pressing it while the screen is
  on blanks it immediately, and it works from **any** on-device screen (Home, Passkeys,
  Settings, the per-RP detail, and the Locked screen), not just Home. The timeout is set
  on-device under **Settings → Display
  sleep** (15 s … 5 min, or Off; runtime, reseeds to 1 min on reboot). The button is
  the board's **BAT_PWR** button (GPIO25) by default and is build-configurable —
  `WAKE_PIN=<gpio>` picks another, `WAKE_PIN=none` makes it touch-only, and
  `WAKE_ACTIVE_HIGH=1` flips the polarity; a `WAKE_PIN` that collides with an
  LCD/touch GPIO is rejected at compile time. Display flavor only. bcdDevice 0x079A →
  0x079C.
- **Configurable multi-LED effects engine.** Boards with a chain of addressable
  WS2812 LEDs now light the whole strip with per-status animated effects —
  `vapor` (breathing), `bounce`, `flow`, `sparkle`, or `legacy` (the classic
  on/off blink) — each with its own color, brightness, and speed via `rsk led
  --effect/--speed`. The number of connected LEDs is a **runtime** setting in the
  phy record (`rsk hw --led-num <n>`, new PicoForge-compatible TLV tag `0x0E`),
  bounded by a compile-time `MAX_LEDS` buffer ceiling (`MAX_LEDS` build flag,
  default 1 — a single onboard LED; a chain sets `MAX_LEDS=N`). A phy count above
  that ceiling is **saturated, not asserted**, so a
  stray value can never panic the boot path (the phy record survives factory
  resets, so a boot panic there would be an unrecoverable loop). `EF_LED_CONF`
  grows to 17 bytes — `steady, (effect, color, brightness, speed) × 4` — and
  older 13/9/2-byte blocks still load forward-compatibly. Single-LED boards are
  unaffected (effects reduce to a static color or the legacy blink). Thanks to
  @Curious-r for the contribution. bcdDevice 0x0780 → 0x0783.
- **Trusted-display variant — panel bringup (experimental, opt-in).** A screen +
  touch variant for the Waveshare RP2350-Touch-LCD-2.8, behind the `display` cargo
  feature / `firmware-display` nix flavor. The panel is now driven: on the display
  build the ST7789 (over SPI1) shows a boot splash and then mirrors the device
  status the onboard LED would otherwise show (idle / working / touch), and the
  CST328 touch controller (over I2C1) is read and each raw touch is marked on
  screen — the hardware bringup. The *what to draw* and the *touch-report parse*
  live in `rsk-ui`, a pure host-tested crate (the on-screen UI model + renderer,
  the untrusted relying-party-string sanitizer, the Allow/Deny button geometry,
  with Kani proofs and a recording-target render test). Still to come in later
  phases: the trusted on-screen Approve/Deny showing the relying party, on-device
  PIN entry, lock, and settings. A standard key **without** a screen compiles
  **none** of this — the whole stack (`rsk-ui`, `mipidsi`, `embedded-graphics`) is
  `dep:`-gated and the gate asserts it is absent from the default firmware
  dependency tree, so there is no size cost; only the shared `bcdDevice` build
  counter advances. bcdDevice 0x0784 → 0x0785.
- **Trusted-display variant — on-screen Approve/Deny (experimental, opt-in).** On
  the `display` build the panel now gates user presence: when an applet asks for a
  touch, the screen shows a trusted Approve/Deny prompt that names the operation
  ("Sign in?", "Register key?", …) and, for FIDO make/getAssertion, the **real**
  relying-party id and account. A tap on **Allow** confirms; a tap on **Deny** is a
  genuine refusal (`CTAP2_ERR_OPERATION_DENIED`). This is the anti-phishing payoff:
  even driven over WebUSB, a signature can't be produced without a physical tap on
  a screen showing the true rp ("what you see is what you sign"). The Allow/Deny
  buttons are rounded floating targets with muted (not vivid) colors, inset from
  the edges with a centre gap — a tap in a margin or the gap approves nothing.
  Relying-party text is sanitized to bounded printable ASCII before it can reach
  the framebuffer (terminal-escape / homoglyph / overlong tricks can't survive).
  The confirmation context is threaded through every applet's `UserPresence` via a
  new dependency-free `rsk_sdk::Confirm`; the standard (button) key ignores it and
  is byte-for-byte unchanged. CTAPHID_CANCEL and the configurable touch timeout are
  honored during the wait, and USB keepalives keep flowing (the on-screen wait is a
  busy-wait on the thread executor, preempted by USB on the interrupt executor).
  bcdDevice 0x0785 → 0x0786.
- **Trusted-display variant — on-device PIN / built-in user verification
  (experimental, opt-in).** On the `display` build the device can now verify the
  user with a PIN typed on its **own** screen, so the PIN never crosses the host —
  defeating a host-side keylogger, the user-verification counterpart to Phase 2's
  "what you see is what you sign". getInfo advertises `options.uv`, and clientPIN
  gains the standard built-in-UV subcommands `getPinUvAuthTokenUsingUvWithPermissions`
  (0x06) and `getUVRetries` (0x07): the platform asks the device to verify, the
  on-screen numeric pad collects the PIN (masked — only dot-per-digit is drawn,
  each key debounced to release, OK gated at `minPINLength`), it is checked against
  the same `EF_PIN` clientPIN already uses, and a `pinUvAuthToken` is minted — so
  makeCredential / getAssertion are unchanged (a token is a token however it was
  earned, and the Phase 2 Approve/Deny still names the relying party afterwards).
  Built-in UV shares the clientPIN retry budget, so a wrong on-screen PIN is
  `UV_INVALID` and spends one retry; an exhausted budget is `UV_BLOCKED`; tapping
  Cancel declines without spending one. A standard key **without** a screen compiles
  none of this and is byte-for-byte unchanged — the new `UserPresence` methods
  default to "no built-in UV", so getInfo omits `uv` and 0x06/0x07 answer
  `UnsupportedOption`. The pad geometry + hit-test live in `rsk-ui` (host-tested +
  Kani-proved disjoint). NB the display build's getInfo therefore advertises `uv`,
  a deliberate divergence from the shared metadata statement, which describes the
  standard (screenless) key. The pad repaints only its masked-entry row per
  keystroke — a tiny partial update, not a full-frame redraw — so typing a digit
  does not flash the whole screen; and the ambient status screen is held back
  briefly between the pad and the Approve/Deny prompt so it does not blip the
  idle/working screen in the hand-off. bcdDevice 0x0786 → 0x0789.
- **Trusted-display variant — on-device settings menu (experimental, opt-in).** On
  the `display` build the idle screen is now interactive: a **MENU** button (shown
  only while idle) opens an on-device settings menu — no host involved. It offers
  **Brightness** (five live backlight levels; GPIO16 is now driven as PWM instead of
  a plain on/off output), **Touch timeout** (step the presence-wait between
  10/20/30/60/120 s live), and a read-only **Device info** page (firmware
  `bcdDevice` + chip serial). The menu is a synchronous on-panel interaction that
  shares the confirm/PIN modals' executor, so while it is open the worker is parked
  (a host command waits behind it); it auto-closes after 15 s without a tap so a
  walked-away user can't wedge the host. These settings are **runtime-only** for now
  — a reboot re-seeds the touch timeout from the phy record and brightness returns to
  full; persisting them across boots is a later, deliberate flash-format change. The
  menu geometry, hit-tests and value steppers live in `rsk-ui` (host-tested +
  Kani-proved disjoint); a standard key **without** a screen compiles none of it and
  is byte-for-byte unchanged. bcdDevice 0x0789 → 0x078A.
- **Trusted-display variant — redesigned UI + hold-to-approve (experimental,
  opt-in).** The `display` build moves to a consistent on-device design language: a
  bottom **navigation bar** (Home / Passkeys / Settings) replaces the single corner
  menu button, a shared list-row / header / card system, vector icon glyphs drawn
  from primitives (no bitmap assets — and, since the device only knows a relying
  party's id string, a generic globe + the rpId rather than a brand logo), and a
  true-black palette with a cyan accent. The Home tab shows the device status; the
  Approve prompt is restyled with a shield, the relying-party card and a plain
  "approve only if you started this" caution. Most importantly, **approve is now a
  deliberate hold, not a tap**: the approve button fills as you hold it (~0.8 s) and
  an accidental brush — or sliding off — resets it, so a signature needs a sustained,
  intentional press on the trusted screen. Deny stays a single tap. The Passkeys tab
  is a stub (the resident-credential list lands in a later wave). The UI model,
  geometry, hit-tests and glyphs all live in `rsk-ui` (host-tested + Kani-proved
  disjoint); a standard key without a screen compiles none of it. bcdDevice 0x078A →
  0x078B.
- **Trusted-display variant — PIN pad in the new design language (experimental,
  opt-in).** The on-screen PIN pad — the one screen the redesign hadn't yet reached
  — now matches the rest of the `display` UI: a lock-marked header, a cyan-accent
  masked entry, and a 3×4 grid of dark neutral key cards with a subtle edge (the
  affirmative OK a solid green check glyph, Del a backspace glyph, and the decline a
  low-emphasis outlined Cancel, mirroring the Approve prompt's Deny). This is a
  re-skin only — the
  pad geometry, the masked-dots-only display and the per-keystroke partial repaint
  are unchanged. The now-unused idle "menu button" hit-test (`MENU_BTN_RECT` /
  `hit_menu`), superseded by the bottom navigation bar, is removed from `rsk-ui`.
  bcdDevice 0x078B → 0x078D.
- **Trusted-display variant — hold-to-approve button: no flicker, no fill artifact
  (experimental, opt-in).** The Approve screen's hold button now paints a static base
  once and grows the fill **in place** as you hold, instead of repainting the whole
  button from a dark base every poll — so the build-up no longer flickers. The
  progress fill is the button's own rounded shape revealed left-to-right through a
  clip, so its corners exactly match the card — no square corner pokes past it — and
  the advancing edge is flat. bcdDevice
  0x078D → 0x078F.
- **Trusted-display variant — on-device Passkeys browser (read-only, experimental,
  opt-in).** The Passkeys tab is no longer a stub: it lists the resident (discoverable)
  credentials stored on the device — one row per relying party (generic globe + the
  real rpId + account count), drilling into a per-RP detail that lists each account
  (user name / display name, with a "UV" tag for credProtect-gated credentials). It is
  strictly **read-only** — no rename or delete yet (a later wave) — and the data is
  decrypted on the device, never on the host: a small additive `rsk-fido::passkeys`
  walk loads the device seed from `EF_KEY_DEV`, unboxes the `EF_RP` / `EF_CRED` records
  the worker already seals at rest, and zeroizes the seed before returning, so the
  display task never holds it. No CTAP / wire change — the FIDO-conformance
  `authenticatorCredentialManagement` path is untouched. The brand of a relying party
  can't be shown (the device only has the rpId string, not a logo or trademark), and
  there is no "last used" time (no per-credential timestamps are stored). Navigation
  switches tab→tab **directly** — tapping Settings (or Home) from inside the Passkeys
  tab now goes straight there instead of dropping back to Home first — and each tab
  repaints the moment it is tapped rather than after the finger lifts, so switching
  feels immediate. bcdDevice 0x078F → 0x0791.
- **Trusted-display variant — on-device factory reset (experimental, opt-in).** A
  new danger row in the Settings menu erases the device from the trusted panel: tap
  **Factory reset**, enter the device PIN if one is set (verified locally, like the
  delete flow), then **hold** the confirm button. The back chevron, a slid-off
  finger, or the inactivity timeout all abandon it without erasing anything. A
  completed hold wipes **every applet's data** — FIDO passkeys and PIN, PIV,
  OpenPGP, and OATH — physically scrubbing the flash (no superseded secret survives
  a raw dump), then reboots; the next boot re-provisions a fresh seed, so the device
  returns blank. Only the org-provisioned batch attestation (device identity, not
  user data) and the fused OTP / secure-boot state survive — matching what the host
  `authenticatorReset` keeps. Unlike that host command, this clears all applets, not
  just FIDO. Implemented as a generic `Fs::factory_wipe` (host-tested) plus a reboot,
  so the display task needs no rng or session state. bcdDevice 0x0797 → 0x0798.
- **Trusted-display variant — on-device passkey deletion (experimental, opt-in).**
  The Passkeys tab moves from read-only to its first **write** action: tapping an
  account on a relying party's detail opens a trusted Confirm-Delete screen naming
  exactly what will be removed, and — if a clientPIN is set — asks for it on the
  on-screen pad (the same built-in-UV input, verified **locally** against the same
  `EF_PIN` and retry counter the host PIN path uses, so it never crosses the host and
  shares the anti-bruteforce budget), then requires a deliberate **hold** on the
  delete button before the credential is removed. A brush, a slid-off finger, the back
  chevron, or the inactivity timeout all abandon it without a write. The delete mirrors
  CTAP `deleteCredential` (0x06) on flash — the `EF_CRED` record is removed and its
  `EF_RP` count decremented (the RP row disappears with its last credential) — keyed by
  slot rather than the host's resident id, with `decrement_rp` now shared between the
  two paths. No CTAP / wire change. bcdDevice 0x0793 → 0x0794.
- **Trusted-display variant — on-device tabs no longer time out mid-browse.** The
  Passkeys / Settings tabs (and the Confirm-Delete screen) used a short 15 s inactivity
  auto-close that dropped you back to the Home screen even when you were just reading.
  That timeout existed only so a walked-away open tab couldn't park the worker and make
  a host command wait behind it — so the guard is now **precise**: the browse loops poll
  whether a host request is actually queued and yield to the worker the instant one
  arrives. With host-starvation handled exactly, the blind timeout is relaxed to 60 s —
  comfortable for reading a passkey list — while still returning to the idle "Ready"
  screen when the device is genuinely left unattended (so the credential list isn't left
  on screen indefinitely). Closing a tab is also snappier: returning to Home (e.g.
  Settings → Close, or the Home nav button from Passkeys) used to wait out a ~400 ms
  ambient-repaint hold — a window meant only for the PIN-pad → confirm hand-off — before
  the Home screen came back; the dispatcher now repaints Home the moment the tab returns,
  so the transition is immediate. The panel SPI clock is also raised from 40 MHz to the
  ST7789's 62.5 MHz maximum, cutting each full-frame repaint by ~35%. bcdDevice 0x0794 →
  0x0797.
- **Configurable GPIO presence button (`PRESENCE_PIN`).** The user-presence input can
  be remapped from BOOTSEL to a dedicated GPIO at compile time: `PRESENCE_PIN=<0..=29>`
  selects an active-low button with an internal pull-up (e.g. a touch sensor to ground),
  while the default (`bootsel`) keeps the BOOTSEL path byte-for-byte. The chosen pin is
  guarded — it must not collide with the active LED pin (boot panic) and is rejected on
  a `display` build (where the touchscreen is the presence source). The button's
  polarity is configurable: active-low by default (button to ground, internal pull-up),
  or active-high with `PRESENCE_ACTIVE_HIGH=1` (internal pull-down) for a capacitive
  touch sensor or a button to VCC. One new `unsafe` (`AnyPin::steal` for the
  runtime-selected pin) documented in `docs/unsafe.md`. Thanks to @lpiob for the
  original contribution ([#17](https://github.com/TheMaxMur/RS-Key/pull/17)).
  bcdDevice 0x0791 → 0x0793.

### Changed

- **Trusted-display: per-size icon bitmaps for crisp small-size rendering.** The glyph
  renderer no longer scales one 16×16 vector contour to every size — the root cause of the
  rounding artefacts that detailed icons (key, globe, gear, lifebuoy, microchip, sun, clock)
  still showed at 14–20px, where features fell off-axis and the icon collapsed into a blob.
  Each glyph is now a hand-authored 1-bit bitmap at the canonical sizes the UI paints
  (14 / 16 / 18 / 20 / 36 / 44 px), blitted 1:1 with a centre-sampled nearest-neighbour
  fallback for the few off-canonical sizes; the round / detailed icons were redrawn cleanly
  at the small sizes via a distance-field rasteriser, while the large 36 / 44 px sizes were
  re-authored from the prior renders to stay visually close. No new glyphs, no behaviour
  change. bcdDevice 0x07D0 → 0x07D1.

- **Trusted-display: redraw the icon set for crisp, centred rendering at small sizes.** A
  pass over the vector glyphs to fix the rough edges that showed at 14–20px: diagonals
  (chevron / back / the check marks / the terminal caret) now step at a clean 45°, on-axis
  features that sat a pixel off-centre (the sun and gear central rays, the clock hands, the
  lock shackle and home roof peaks, the apps tile gap) are re-centred, the warning sign's
  exclamation no longer merges into the triangle edge, the eye is re-proportioned with a
  small pupil, the shield tapers to a clean point, and the USB indicator is redrawn as the
  familiar trident instead of an unclear plug box. No new glyphs, no behaviour change.
  bcdDevice 0x07CF → 0x07D0.

- **Trusted-display: design-token fidelity polish pass.** A pass over the on-device
  screens to close residual drift from the high-fidelity handoff: the PIN keypad keys
  tighten to the design's 7px grid gap (re-centred so the pad stays balanced) and 9px
  key radius, the backspace key takes its darker `#101317` shade, outline buttons
  (Deny / Cancel) gain the design's faint tinted fill behind a 1px border (was a bare
  2px stroke), buttons settle to the 11px card radius, the Home "Ready" check icon to
  38px, list rows align to the 13px content gutter, and three screen labels match the
  spec wording (*Verify & install*, *Hold to wipe*, *RECOVERY SHARES*). No behaviour or
  wire change. bcdDevice 0x07CE → 0x07CF.

- **Trusted-display visual redesign — typography and palette (experimental).** The
  on-device screens move to the high-fidelity design language: proportional 1-bit
  text (Helvetica-style `helvR`/`helvB` and `profont` for mono labels, via the new
  `u8g2-fonts` dependency) in place of the monospace built-in fonts, and a blue
  accent over a near-black blue-grey background with calm danger / warning / success
  tiers. This is the design-system foundation; individual screen layouts are
  re-skinned onto it wave by wave. Display-flavor only — the new dependency never
  reaches a standard (screenless) key (the build still asserts `rsk-ui` absent from
  the default image). The proportional faces also harden two layout spots against
  the wider, variable text: the PIN screen's cancel is a back chevron (not a "Cancel"
  word that overran its box into the title), and list-row labels are clipped clear of
  their trailing value (a long rp name no longer touches its account count).
  bcdDevice 0x0798 → 0x079A.
- **Trusted-display redesign — status/title-bar chrome (experimental).** The tab
  screens (Home, Passkeys, Settings, and per-RP detail) now wear the design's two-tier
  chrome: a persistent top **status bar** (a mono "RS-Key" wordmark at the left and the
  USB power indicator at the right — this is a bus-powered device, so always USB, never
  a battery) and, below it, a **title bar** carrying the screen title and, on a pushed
  screen, a back chevron. Content shifts down to clear both strips. The geometry is the
  single source of truth shared by paint and hit-test (a new `hit_title_back`, proven
  disjoint from the rows and nav under Kani). Display-flavor only. bcdDevice 0x079D →
  0x079E.
- **Touch timeout is configurable; phy tag `0x08` now follows pico-fido.** RS-Key
  read tag `0x08` as a user-presence button GPIO, but the button is always BOOTSEL
  so the field was never used. It now means `PresenceTimeout` — the touch-wait
  timeout in **seconds** — matching pico-fido / PicoForge, so a PicoForge config
  (or `rsk hw --touch-timeout <secs>`) sets how long the device waits for a touch.
  Absent / `0` keeps the built-in 30 s default; existing phy records never carried
  a meaningful `0x08`, so the realignment is safe. bcdDevice 0x0783 → 0x0784.

### Fixed

- **Trusted display: the "Protect mgmt key" row label is no longer clipped to nothing on
  the PIV PIN menu.** Its long right-aligned hint ("random, PIN-unlocked", 159 px) crowded
  the 128 px label down to 1 px, so the row showed only the hint and not its name. The hint
  is dropped (the random / PIN-unlocked consequence is stated in full on the confirm screen),
  so the label shows like the other rows; a regression test now asserts every menu label fits
  beside its caption. Display flavor only.

- **Trusted display: the device now locks from the audit-log screen.** The power/wake
  button now sleeps and locks the on-device UI from inside the audit log too — previously
  it was ignored there, so a PIN-set device could not be locked from that screen — and the
  settings menu unwinds cleanly afterwards without repainting over the blanked panel.
  Display flavor only.

- **OpenPGP / trusted display: an over-long fingerprint, timestamp or algorithm object can no
  longer crash the Apps screen.** `read_info` sliced fixed stack buffers by the *full* stored
  length that `Storage::read` reports, so a fingerprint (`C7`), timestamp (`CE`) or algorithm
  attribute stored longer than its buffer — PUT DATA caps nothing, so a PW3 host or flash
  corruption can leave one — indexed out of bounds and panicked (a device brick) every time the
  OpenPGP screen was opened. The read length is now clamped before slicing, and a host test
  exercises an over-long record. Found by a pre-release cross-wave review.

- **PIV: imported X25519 keys now match their real public identity (ykman / yubico-piv-tool
  interop).** An imported X25519 scalar was stored verbatim, but the curve op treats the stored
  scalar as a big-endian MPI while `ykman` / `yubico-piv-tool` send it little-endian (RFC 8410 /
  RFC 7748) — so the slot's public key (and every ECDH) disagreed with the key's established
  public key, and ciphertext or certificates already bound to it could not be decrypted by the
  slot. The import now flips the byte order for X25519 (Ed25519 seeds are unaffected), and a host
  test asserts the reported public point equals the one standard tooling derives from the same
  bytes. On-device *generated* X25519 keys were always self-consistent and are unchanged.

- **Trusted display: a look-alike relying-party id can no longer hide its tail on the Approve
  screen.** The sign-in / approve screen hard-clipped a too-wide rp id with no marker, and the
  "was truncated" flag on a sanitized label was never rendered — so a padded look-alike id could
  be silently cut to a trustworthy-looking prefix on the very screen meant to expose it. The rp
  id is now ellipsized (`…`) on overflow and always marked when the label was clamped. Display
  flavor only.

- **Trusted display: a long OpenPGP cardholder name no longer overruns the overview row.** The
  host-set cardholder name is drawn right-anchored on the "Card holder" overview row; without a
  clip a long name spilled left across the icon and off the panel edge. The trailing value is now
  clipped to the row (short values are unaffected), with a regression test that renders a
  max-length name on-panel. Display flavor only.

- **Hardening: property sweeps now pin the `EF_DISPLAY`, `EF_RPNICK` (passkey nickname) and PIV
  ADMIN-DATA / PRINTED codecs against regression.** No new defect was found in these, but the
  load-bearing read-length clamps and the fail-closed protection-flag parse are locked in by
  deterministic host sweeps over adversarial bytes. bcdDevice 0x07D1 → 0x07D2.

- **Trusted display + PIV: on-panel "Protect mgmt key" now preserves a host's `PivmanData`.**
  Setting a PIN-protected management key from the panel rebuilt the YubiKey ADMIN-DATA object
  from scratch, discarding any PIN-change timestamp and unrelated flag bits a host (`ykman`)
  had written. It now carries those forward and drops only the derived-key salt — which a
  PIN-protected (device-stored, no longer PIN-*derived*) key makes obsolete, exactly as
  ykman's `--protect` does. The rebuild moved into a pure codec pinned by a Kani proof and a
  host property sweep: for any prior bytes it always emits a well-formed protected object that
  carries no salt. bcdDevice 0x07D4 → 0x07D5.

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

[Unreleased]: https://github.com/TheMaxMur/RS-Key/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TheMaxMur/RS-Key/releases/tag/v0.1.0
