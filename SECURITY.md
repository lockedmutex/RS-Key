# Security policy

RS-Key is a hobby project and says so on the tin — but it is still an
authenticator, and bugs that break its promises are treated accordingly.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/TheMaxMur/RS-Key/security/advisories/new).
Do not open a public issue for anything exploitable.

Worth reporting privately: PIN or touch-gate bypasses, secret or seed
extraction (beyond what the [threat model](docs/threat-model.md) already
concedes), attestation or audit-checkpoint forgery, secure-boot escapes,
crypto misuse, parser memory corruption reachable over USB.

Not a vulnerability here: attacks the threat model explicitly does not cover
(physical extraction from a board without the OTP lock, glitching the RP2350
itself, malware on the host with an unlocked session). Read
[docs/threat-model.md](docs/threat-model.md) first if unsure — and when still
unsure, report privately anyway; worst case it becomes a public issue with
your name on the find.

A good report includes the firmware build (`rsk inventory list` prints
version and bcdDevice), the board, and steps or a PoC. A suggested fix is
welcome but absolutely not required.

## What to expect

One maintainer, best effort: an acknowledgment usually within a few days, a
fix on `main` as fast as severity warrants. Since there are no releases yet,
"the fix" means a commit on `main` plus a note in the advisory; bcdDevice
bumps on every change, so affected builds are easy to name precisely.

## Supported versions

The tip of `main`. There are no maintained release branches.
