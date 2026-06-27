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
