# LED

The WS2812 RGB LED (GPIO16 on the Waveshare RP2350-One) is the device's only
display. Boards without one just run dark.

## What the colors mean

| State | Default |
|---|---|
| idle | dim blue breathing |
| processing | white pulse |
| **waiting for touch** | green blink — press the button |
| boot | a short white flash |

The touch blink is the one to learn: WebAuthn dialogs and `ssh` look hung
precisely when the device is waiting for your press.

## Customize

```sh
rsk led                       # show current config
rsk led <status> <color> [brightness]
rsk led 2 green               # e.g. set status 2's color
```

Color and brightness are configurable per status; the values persist in
flash. `rsk-tui` can cycle the idle color interactively.
