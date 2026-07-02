<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# docs/images

Illustrations for the documentation. Referenced from the `docs/*.md` pages with
**relative** paths (`![…](images/foo.svg)`) so they render both on GitHub and in
the mdBook site.

- Prefer **SVG** for diagrams (crisp, tiny, no theme baked in), **PNG** for
  screenshots, **GIF/APNG** for motion. Keep binaries small — the versioned site
  duplicates `docs/` per build.
- Diagrams are hand-authored and self-contained (their own light card, so they
  read on both the light `rust` and dark `ayu` themes — mdBook embeds SVG as an
  `<img>`, which does not inherit page CSS). Palette: two ramps only — rust for
  the firmware/code, teal for the KV store.
- Third-party screenshots (browser dialogs, `ykman`, GnuPG, …) keep their
  origin noted here.

| File | What | Source |
|---|---|---|
| `flash-map.svg` | RP2350-One 4 MB flash address map | original — from `firmware/memory.x` / `flash_storage.rs` |
| `flash-map-sizes.svg` | 4 MB vs 16 MB layout (how `FLASH_SIZE` scales it) | original — from `firmware/build.rs` |
