## What

<!-- What changes, and why. A couple of sentences is fine; link the issue if there is one. -->

## How it was tested

<!-- Keep what applies, delete the rest. -->

- [ ] `nix develop -c ./scripts/check.sh` passes locally
- [ ] On hardware: board = …, what was exercised = …
- [ ] Host-only change (CLI / docs / CI) — no device behavior touched

## Checklist

- [ ] Firmware behavior changed → `config.device_release` (bcdDevice) bumped in `firmware/src/main.rs`
- [ ] New or changed `unsafe` → justified in `docs/unsafe.md`
- [ ] User-visible behavior → the matching guide under `docs/` updated
- [ ] New files carry the SPDX header (`AGPL-3.0-only`)
- [ ] Commit messages use the zone prefix style (`fido:`, `piv:`, `rsk:`, `docs:`, …)
