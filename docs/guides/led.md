# LED

The status LED is the device's only display. On the reference board — the
**Waveshare RP2350-One** — it's a WS2812 addressable RGB on GPIO16.

Three properties of the indicator are **runtime-configurable**, like the USB
identity: they live in the device's `phy` record and change with `rsk hw` (or
PicoForge) **without reflashing**, because a non-`none` build compiles all
three backends. The `LED_KIND` / `LED_PIN` / `LED_ORDER` build knobs set the
*boot defaults* used when the phy record doesn't override them
([build.md](../build.md), [hardware.md](../hardware.md)):

- **backend** — `LED_KIND` / `rsk hw --led-driver`: `ws2812` (addressable RGB,
  the default), `gpio` (a plain on/off LED — can't show the colours below, but
  the blink *pattern* still tells the four states apart), `pimoroni` (a 3-pin
  PWM RGB, Pimoroni Tiny 2350), or the build-only `none`.
- **pin** — `LED_PIN` / `rsk hw --led-pin`: the `ws2812`/`gpio` data GPIO
  (`0..=29`), for a board that wires its LED off GPIO16.
- **wire order** — `LED_ORDER` / `rsk hw --led-order`: a `ws2812` board whose
  **red and green come out swapped** (blue unaffected) has the other byte
  order — the Waveshare RP2350-One is `rgb` (the default), most other WS2812B
  parts are `grb`.

A `none` build is the exception: it renders nothing and ignores the phy LED
fields (there is no backend compiled to switch to).

The LED runs on its own high-priority task, so it keeps animating even while
the firmware blocks waiting for a touch or grinds through a long RSA keygen —
a frozen LED means the firmware itself is wedged, not just busy.

## What the states mean

There are four states. Each has a **fixed blink timing** baked into the
firmware (`firmware/src/led.rs`); only the **color and brightness** are
configurable.

| State | Default color | Blink (on/off) | Means |
|---|---|---|---|
| idle | green | 500 / 500 ms — slow, even | ready, nothing in flight |
| processing | green | 50 / 50 ms — fast flicker | handling an APDU / crypto op |
| **waiting for touch** | yellow | 1000 / 100 ms — long on, brief blink | press the button to confirm |
| boot | red | 500 / 500 ms | the brief power-up state |

The **touch** state is the one to learn. WebAuthn dialogs, `ssh`, and `gpg`
look hung at exactly the moment the device is waiting for your press — a
near-solid yellow that ticks off once a second is the cue to tap the button.

A few honest details:

- **No dedicated error color.** The firmware does not light a distinct "error"
  state; a failed operation just drops back to idle. Read the host tool's exit
  code, not the LED, for success or failure.
- **The touch state needs the touch build.** It is only ever shown on a build
  with the `up-button` feature (the default touch build). A no-touch build
  never enters it. The processing state still flashes during the operation
  either way ([build.md](../build.md)).
- **Default brightness is gentle** — 16 of 255 per channel, so the indicator
  is visible without being a flashlight. Turn it up if you want.
- **Boot is brief.** You normally see it only for the moment between power-up
  and the first idle, so don't tune your eye to it.

This is *not* the BOOTSEL / `picotool` state. Holding the button while
plugging in puts the RP2350 in its ROM bootloader, where this firmware — and
therefore this LED engine — isn't running, so the LED is dark or shows
whatever the ROM does. That mode is for flashing firmware and OTP, covered in
[build.md](../build.md) and [otp-fuses.md](../otp-fuses.md).

## Customize

Color and per-channel brightness are configurable **per state**; the values
persist in flash (`EF_LED_CONF`) and apply live — no reboot. The host command
is `rsk led`:

```sh
rsk led --get                                  # print the current config
rsk led --status idle --color blue             # recolor a state
rsk led --status idle --brightness 64          # 0–255; 0 = that state goes dark
rsk led --status idle --color blue --brightness 64
```

Selectors and values:

| Flag | Values |
|---|---|
| `--status` | `idle`, `processing`, `touch`, `boot` (default `idle`) |
| `--color` | `off`, `red`, `green`, `blue`, `yellow`, `magenta`, `cyan`, `white` |
| `--brightness` | `0`–`255` per channel (`0` = off) |
| `--steady` | solid color, no blinking — **global**, affects every state |
| `--blink` | the opposite: restore blinking |

`--steady` and `--blink` are global, not per-state: the firmware keeps each
state's timing internally, but a single flag decides whether *any* of them
blink. So `--steady` makes the whole indicator a solid lamp whose color tracks
the current state, and `--blink` brings the blink patterns back.

```sh
rsk led --status idle --color cyan --steady    # solid cyan at idle, no pulse
rsk led --blink                                # back to the blink patterns
```

`rsk-tui` has a "Cycle idle color" action that steps the idle state through
the palette, plus "Read LED state" — for per-state color, brightness, or the
steady toggle, use `rsk led`.

## Hardware wiring (`rsk hw`)

The **look** (`rsk led`, above) is one layer; the **wiring** — which pin, which
driver, which wire order — is the other. The wiring lives in the `phy` record
(the same device-config blob PicoForge writes) and is applied at **boot**, so a
change needs a reboot — `rsk hw` issues a warm one for you unless `--no-reboot`:

```sh
rsk hw                                  # show the current phy LED config
rsk hw --led-pin 22                     # move the WS2812/gpio data pin to GPIO22
rsk hw --led-driver gpio                # switch to a plain on/off LED
rsk hw --led-order grb                  # fix a red/green swap on a GRB part
rsk hw --led-pin 22 --led-order grb     # e.g. the TenStar RP2350-USB
rsk hw --led-driver ws2812 --no-reboot  # stage a change; reboot later
```

| Flag | Values |
|---|---|
| `--led-pin` | `0`–`29` (RP2350A GPIOs) — the `ws2812`/`gpio` data pin |
| `--led-driver` | `gpio`, `pimoroni`, `ws2812` |
| `--led-order` | `rgb`, `grb` (the `ws2812` backend only) |
| `--get` | print the current phy LED config and exit |
| `--no-reboot` | write but don't reboot (the change applies on the next boot) |

A field you never set stays at the firmware build default (`rsk hw` with no
setters, or `--get`, prints which are overridden). `rsk hw` does a
read-modify-write of *only* the LED fields, so a USB identity or other phy
option set elsewhere (PicoForge) is preserved. A `none` build ignores these —
there is no backend compiled to render the LED.

### Reset to defaults

There's no single "reset LED" verb; set the values back yourself. The factory
defaults are the table above at brightness 16, blinking:

```sh
rsk led --status idle       --color green  --brightness 16
rsk led --status processing --color green  --brightness 16
rsk led --status touch      --color yellow --brightness 16
rsk led --status boot       --color red    --brightness 16
rsk led --blink
```

## Under the hood

`rsk led` talks to the firmware's vendor applet over CCID
(`tools/rsk/led.py`, `firmware/src/vendor.rs`): **SET LED** (`INS 0x10`) packs
brightness into `P1` and color + the steady bit + the target state into `P2`;
**GET LED** (`INS 0x11`) returns the whole `[steady, (color, brightness) × 4]`
block that `--get` prints. The firmware writes it to `EF_LED_CONF` and reloads
it on every boot, so your colors survive a power cycle but not an OpenPGP/FIDO
factory reset of other applets (those don't touch this file).

`rsk hw` instead writes the **wiring** to the `phy` record (`EF_PHY`) via the
rescue applet (`tools/rsk/hw.py`, `crates/rsk-rescue/src/phy.rs`): **READ**
(`INS 0x1E`, P1=01) and **WRITE** (`INS 0x1C`, P1=01) the same TLV blob
PicoForge uses — `led_gpio` (tag `0x04`), `led_driver` (`0x0C`), plus the
RS-Key vendor `led_order` tag (`0x0D`, which PicoForge skips as unknown). At
boot `firmware/src/main.rs` reads those fields and selects the pin (a `match`
over GPIO `0..=29`) and the driver; the wire order is a runtime red/green swap
in the render task, so one binary serves both RGB- and GRB-wired parts.
`EF_PHY` survives every applet factory reset.

One board quirk worth knowing: the Waveshare RP2350-One's WS2812 takes bytes in
**RGB** wire order, not the WS2812B-standard GRB — the `rgb` default matches it,
and a `grb` board just flips `LED_ORDER` (build) or `rsk hw --led-order grb`
(runtime); the swap touches red/green only (blue is unaffected).

## Troubleshooting

- **LED is dark and stays dark.** Either the board has no addressable LED, or
  the data pin / driver is wrong for your wiring — fix it live with `rsk hw
  --led-pin N` / `--led-driver …` (or rebuild with the right `LED_PIN` /
  `LED_KIND`, [build.md](../build.md)). If a known-good board goes dark
  mid-session, the firmware task is likely wedged, not the LED.
- **Red and green look swapped.** Wrong wire order for your LED part — flip it
  with `rsk hw --led-order grb` (or build with `LED_ORDER=grb`); see the
  RGB-vs-GRB note above.
- **`rsk led` can't reach the device.** It needs the CCID interface up
  (`pcscd` on Linux); if `gpg --card-status` / `rsk status` also fail, fix that
  first ([linux.md](../linux.md)).
- **An app looks frozen.** Check for the long-on yellow touch state and tap the
  button. If the LED is idle-green and the app is still stuck, it isn't waiting
  on the device.
