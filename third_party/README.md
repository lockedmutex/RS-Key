# third_party — vendored upstream test suites

Two external conformance suites, vendored so the firmware can be validated
without checking out the upstream repos. They are **not** part of RS-Key's
own test suite (`tests/`, `cargo test`) — they are the upstream ecosystems'
own tests, kept runnable against this implementation.

Both directories carry their own licenses (each `LICENSE` file), distinct
from the repository's own AGPL-3.0-only:

| Directory | Origin | License |
|---|---|---|
| `pico-fido-tests/` | [polhenarejos/pico-fido](https://github.com/polhenarejos/pico-fido) `tests/` | AGPL-3.0 (their LICENSE) |
| `openpgp-card-tests/` | [polhenarejos/pico-openpgp](https://github.com/polhenarejos/pico-openpgp) `tests/`, derived from [Gnuk](https://www.fsij.org/gnuk/) (NIIBE Yutaka / g10 Code GmbH) | GPL (see file headers + their LICENSE) |

Local modifications are minimal and marked in-place; the notable one:
`pico-fido-tests/conftest.py` filters the relying-party's allowed algorithms
to those the installed python-fido2 can actually verify (the firmware can
lead with ML-DSA-44, which older fido2 libraries parse but cannot check).

## Running them

Flash the **no-touch test build** first (the suites cannot press the
button); if your board enforces secure boot, sign it
([docs/production.md](../docs/production.md)).

```sh
# FIDO suite (pytest + python-fido2):
nix develop -c python -m pytest third_party/pico-fido-tests/pico-fido -v

# OpenPGP card suite (pytest + pyscard) — DESTRUCTIVE: resets the card,
# exercises factory PINs/KDF setup. Run section by section:
nix develop -c python -m pytest third_party/openpgp-card-tests/020_kdffull -v
```

Read a suite's conftest before running it: parts are destructive
(authenticator resets, card terminate/activate cycles) and assume factory
default PINs.
