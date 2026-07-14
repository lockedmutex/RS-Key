# SSH with FIDO keys (`ed25519-sk` / `ecdsa-sk`)

Hardware-backed SSH keys. The private key is generated on the device and never
leaves it. The file on disk is only a *handle* that points at it. Logging in
takes one touch (and a PIN, if you ask for one). This is the OpenSSH "security
key" (`-sk`) feature. The device is a FIDO2 authenticator, and RS-Key supports
both key types it can use:

| Key type | Algorithm | Use it when |
|---|---|---|
| `ed25519-sk` | Ed25519 (EdDSA) | the default: smallest, fastest |
| `ecdsa-sk` | NIST P-256 (ES256) | a server or old client rejects `ed25519-sk` |

## Requirements

- **OpenSSH 8.2+** for `-sk` keys (8.3+ to download resident keys with `-K`).
- A FIDO **middleware**: distro OpenSSH links `libfido2`; check with
  `ssh -Q key | grep sk`.
- **macOS:** Apple's `/usr/bin/ssh` ships **without** FIDO support and fails
  with `Permission denied` before touching the device. Use Homebrew OpenSSH:
  ```sh
  brew install openssh
  export PATH="/opt/homebrew/opt/openssh/bin:$PATH"   # ahead of /usr/bin
  ```
- **Linux:** OpenSSH links `libfido2` almost everywhere; you only need the FIDO
  udev rules (see [linux.md](../linux.md)). FIDO is local to wherever `ssh`
  runs, so logging in *to* a remote box needs nothing special there.
- **Windows:** OpenSSH for Windows routes `-sk` keys through the Windows WebAuthn
  API (`webauthn.dll`), which only offers algorithms the device *advertises* in
  its FIDO `getInfo`. `ed25519-sk` needs firmware that advertises EdDSA:
  RS-Key `bcdDevice 0x077D` or newer (see `rsk status`). On older firmware
  `ed25519-sk` fails at create with a generic error while `ecdsa-sk` still works,
  so either reflash or use `ecdsa-sk`. macOS and Linux talk to `libfido2`
  directly and send the algorithm regardless, so they are unaffected.

## Enroll

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk -C "you@laptop"
# → enter the FIDO PIN if one is set, then touch the button
```

The `-C` comment is free text that ends up in the `.pub` and on the server. It
is handy for telling keys apart. Two files appear:

- `id_ed25519_sk`: the **handle**. Not a private key; useless without the
  physical device. Copy it (and the `.pub`) to every machine you ssh *from*.
  The device is the second factor, the file is just a pointer.
- `id_ed25519_sk.pub`: the public key, for `authorized_keys`.

Then install it on a server:

```sh
ssh-copy-id -i ~/.ssh/id_ed25519_sk.pub you@server
ssh -i ~/.ssh/id_ed25519_sk you@server      # one touch
```

## Enrollment options (`-O`)

Pass `-O` flags at `ssh-keygen` time to shape the credential:

| `-O` option | Effect |
|---|---|
| `resident` | store the key *on the device* so it can be downloaded later (see below) |
| `verify-required` | demand the **FIDO PIN** on every login, not just a touch |
| `application=ssh:NAME` | tag the credential (default `ssh:`); a distinct string is a distinct key |
| `user=NAME` | user handle stored with a resident key (for listing/telling them apart) |
| `no-touch-required` | mark the key as not needing a touch; **see the note below** |
| `write-attestation=FILE` | save the enrollment attestation for later verification |
| `challenge=FILE` | use a fixed challenge (for reproducible attestation) |

```sh
# PIN on every login, and store the key on the device:
ssh-keygen -t ed25519-sk -O resident -O verify-required \
    -O application=ssh:work -f ~/.ssh/id_work_sk
```

> **`no-touch-required` does nothing useful on RS-Key.** The default (touch)
> build always polls the button on every assertion. The firmware does not honor
> `up:false`. The flag still marks the credential, but you will be asked to touch
> regardless. The touch is the point; enroll without it.

## PIN and touch: what to expect

RS-Key follows the standard FIDO2 flow, the same as a YubiKey: the **PIN unlocks
a session token silently (no touch for the PIN itself)**, and then each
operation takes **one touch**.

| Action | PIN | Touch |
|---|---|---|
| Enroll (`ssh-keygen -t …-sk`) | once | once* |
| Log in, normal key | — | once |
| Log in, `verify-required` key | once | once |

\* You only touch *twice* at enrollment when **several FIDO devices are plugged
in at once**: the first touch is a CTAP "selection" gesture (which key did you
mean?), the second authorizes the key creation. With one device connected it is a
single touch.

So a single login asks for the PIN **at most once**. If you ever see the PIN
prompt *twice* in one action, two separate operations are running. Usually the
key is offered by both `ssh-agent` and an `IdentityFile` (add `IdentitiesOnly
yes`), or `git push` opened two SSH channels (use `ControlMaster` /
`ControlPersist`, see the [git guide](git.md#authenticating-push-pull-and-2fa)).
A real YubiKey behaves identically in those setups. It is the client, not the
device.

## Resident (discoverable) keys

`-O resident` stores the key handle on the device itself, so you can recover it
onto any machine later instead of carrying the file:

```sh
ssh-keygen -K                      # download handles into the current dir (PIN)
# → writes id_ed25519_sk_rk[...]  and the matching .pub
ssh-add -K                         # load resident keys straight into the agent
rsk fido list-passkeys             # see what's stored on the device
```

Resident keys cost one of the device's **256** discoverable-credential slots.
For most people the **non-resident default plus a [seed backup](seed-backup.md)
is better**: non-resident keys are re-derivable from the seed, so a restored
board logs in with the same handle files. No slot used, nothing to download.
Reach for resident keys when you want to walk up to a fresh machine with only the
device in your pocket.

## ssh-agent and `~/.ssh/config`

Add the key to the agent so you are not retyping `-i`:

```sh
ssh-add ~/.ssh/id_ed25519_sk       # non-resident: add the handle file
ssh-add -K                         # resident: pull from the device
ssh-add -l                         # list loaded keys
```

A config block makes plain `ssh host` use the right key (and the Homebrew binary
on macOS):

```
# ~/.ssh/config
Host server
    HostName server.example.com
    User you
    IdentityFile ~/.ssh/id_ed25519_sk
    IdentitiesOnly yes
```

`IdentitiesOnly yes` stops the agent from offering every other key first. Worth
it so each connection prompts for exactly one touch.

## Server side

The `.pub` goes in `~/.ssh/authorized_keys` like any key. You can also pin
requirements there, independent of how the key was enrolled:

```
# authorized_keys — require the FIDO PIN for this key (touch is omitted = required)
verify-required sk-ssh-ed25519@openssh.com AAAA... you@laptop
```

`sshd` enforces `verify-required` from **OpenSSH 8.4+**; older servers accept the
key but skip the check. A key enrolled `verify-required` always asks for the PIN
on the client regardless of the server. (Adding `no-touch-required` here would
*relax* the touch requirement, but RS-Key touches anyway, as above.)

## Signing git commits

The same key signs git commits and tags (no GPG needed). See the
[git guide](git.md#ssh-signing). The short version:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519_sk.pub
git config commit.gpgsign true     # one touch per commit
```

## Using the OpenPGP AUT slot instead

If you already run an OpenPGP key on the card, its authentication subkey doubles
as an SSH key via `gpg-agent`, a different path that needs no `-sk` support in
the client. See [openpgp.md](openpgp.md) (`gpg --export-ssh-key`,
`enable-ssh-support`).

## Troubleshooting

- **`Permission denied` instantly on macOS** → you are on `/usr/bin/ssh`; use the
  Homebrew binary (above).
- **`Key enrollment failed: requested feature not supported`** → the client lacks
  `ed25519-sk` middleware; install `libfido2` / Homebrew OpenSSH, or fall back to
  `-t ecdsa-sk`.
- **`device not found` / no prompt** → FIDO udev rules missing
  ([linux.md](../linux.md)), or a browser / `gpg-agent` is holding the device;
  close it and retry.
- **Asks for a PIN you never set** → some client builds require a PIN to enroll;
  set one with `rsk fido set-pin` and retry.
- **`sign_and_send_pubkey: signing failed`** on login → the wrong device is
  plugged in, or the key is resident on a device you reset. Re-plug the right key,
  or `ssh-add -K` again.
- **After a factory FIDO reset, old `id_*_sk` files stop working.** The seed
  they derive from is gone. Re-enroll, or [restore the seed](seed-backup.md)
  first so the same handles work again.
