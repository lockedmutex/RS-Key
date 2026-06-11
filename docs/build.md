# Build options

Every knob is compile-time: set environment variables and cargo features at
`cargo build` and they are baked into the image. Nothing here can be changed
at runtime (except where noted for the phy record).

```sh
# the general shape
nix develop -c env KNOB=value cargo build --release -p firmware [--features ...] [--no-default-features]
picotool uf2 convert target/thumbv8m.main-none-eabihf/release/firmware -t elf firmware.uf2
```

## Cargo features

| Feature | Default | Effect |
|---|---|---|
| `up-button` | **on** | FIDO operations (makeCredential, getAssertion, U2F, reset, selection) and OpenPGP UIF data objects require a press of the BOOTSEL button. Build with `--no-default-features` to get the **no-touch test build** — the automated suites (`tests/`, python-fido2, OpenPGP card tests) cannot press a button and will hang on a touch build. |
| `advertise-pqc` | off | Prepends ML-DSA-44 (COSE −48) to the getInfo `algorithms` list. Off by default because released Firefox versions abort the *entire* getInfo parse on an unknown COSE id and report the authenticator broken. **PQC capability is on regardless of this flag** — makeCredential negotiates −48 from the request's `pubKeyCredParams`; the flag only controls advertising. |

## Environment variables

| Variable | Default | Values | Effect |
|---|---|---|---|
| `VIDPID` | `Yubikey5` | `Yubikey5`, `YubikeyNeo`, `YubiHSM`, `NitroHSM`, `NitroFIDO2`, `NitroStart`, `NitroPro`, `Nitro3`, `Gnuk`, `GnuPG`, `Pico`, `Dev` | USB VID/PID preset. The default `Yubikey5` (`0x1050:0x0407`) is what makes `ykman`, Yubico Authenticator and the stock udev rules work. `Pico` = the Raspberry Pi generic id (`0x2E8A:0x10FD`); `Dev` = a placeholder (`0xFEFF:0xFCFD`). An unknown preset fails the build. **Masquerade ids are for local interop only — never distribute hardware carrying them.** |
| `USB_VID` / `USB_PID` | from preset | `0xHHHH` | Raw override, applied on top of the preset (you can override either half alone). |
| `FW_VERSION` | `5.7.4` | `X.Y.Z` or `X.Y` | The firmware version reported everywhere a tool looks: management DeviceInfo (`ykman info`), FIDO getInfo, CTAPHID INIT, OATH/OTP/PIV version fields. Yubico tools gate features on it; 5.7.4 mimics a current YubiKey 5. Does **not** change the OpenPGP card version (3.4) or the USB `bcdDevice` (an internal build counter). |
| `XOSC_DELAY_MULT` | `128` | `1..=1024` | Crystal-oscillator startup-delay multiplier ("delayed boot"). A longer settle wait hardens the early-boot clock-switch window against glitch/fault injection. 128 is the embassy default. |
| `FAKE_MKEK` / `FAKE_DEVK` | unset | 64 hex chars | **Test builds only.** Bakes a fake OTP master key / device key into the image instead of reading the OTP fuses, so the whole OTP migration path can be exercised with zero fuse writes. The build prints a loud warning and the key is greppable in the binary. Flashing a FAKE build onto a provisioned device migrates its data under the fake key — going back orphans that data (recovery = per-applet resets). Never flash one on a device you care about. |

Verify what got baked without flashing:

```sh
rg PK_USB_VID  target/thumbv8m.main-none-eabihf/release/build/firmware-*/output   # decimal: 4176 = 0x1050
rg PK_FW_VERSION target/thumbv8m.main-none-eabihf/release/build/rsk-sdk-*/output
rg PK_XOSC_DELAY_MULT target/thumbv8m.main-none-eabihf/release/build/firmware-*/output
```

## Examples

```sh
# default: touch build, YubiKey-5 identity, fw 5.7.4
cargo build --release -p firmware

# no-touch test build (for the automated suites)
cargo build --release -p firmware --no-default-features

# Nitrokey FIDO2 identity with its own version number
env VIDPID=NitroFIDO2 FW_VERSION=1.4.0 cargo build --release -p firmware

# advertise PQC in getInfo (breaks released Firefox — see above)
cargo build --release -p firmware --features advertise-pqc
```

## Runtime overrides (phy record)

The rescue applet can store a small config record in flash (`rsk` /
`rsk-tui` expose the safe fields). At boot, a stored **VID/PID** and **product
string** override the compile-time defaults — useful to re-identify a device
without rebuilding. A bad value can make the device enumerate strangely;
recovery is a BOOTSEL reflash (which never reads the record) or rewriting the
record over CCID.

## Notes

- The PC/SC **reader name** comes from the USB strings
  (`Yubico YubiKey RSK OTP+FIDO+CCID`). `ykman` derives the device's PID from
  that name — it needs the `Yubico YubiKey` words and the `OTP`/`FIDO`/`CCID`
  tokens. If you change the product string, YubiKey tools stop recognizing the
  CCID half; the project's own tools match the `RSK` token.
- `bcdDevice` (USB device release) is an internal build counter, not the
  firmware version.
- The two UF2 flavors on a release build of this repo:
  `firmware.uf2` (touch) and `firmware-test.uf2` (no-touch) — `scripts/check.sh`
  builds both.
