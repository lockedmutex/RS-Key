# Git with the device

Two jobs you do with git and a hardware key: **sign** your commits and tags, and
**authenticate** — push, pull, and clear the forge's 2FA / "confirm access"
challenges. The same RS-Key handles both; they are just different credentials on
it. Signing comes first; [authentication and 2FA](#authenticating-push-pull-and-2fa)
are at the end.

Signing keeps the key off the disk and takes a touch per signature. It has two
flavours, and RS-Key supports both:

| | SSH signing | OpenPGP signing |
|---|---|---|
| Key | your `-sk` SSH key ([ssh.md](ssh.md)) | a key on the OpenPGP card ([openpgp.md](openpgp.md)) |
| Needs | git 2.34+, nothing else | `gpg` + `scdaemon` |
| Trust model | an `allowed_signers` file you curate | the OpenPGP web of trust |
| Touch / PIN | touch per signature | PIN once, then touch per signature (UIF) |
| Best when | you only want commit signing, no GPG | you already use GPG, or want WoT |

If you have no GPG setup and just want verified commits, use **SSH signing** — it
is the smaller path. If you already keep a GPG identity, use **OpenPGP**.

## SSH signing

Point git at your `-sk` public key and turn signing on:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git config --global commit.gpgsign true     # sign every commit
git config --global tag.gpgsign true        # sign every tag
```

Now `git commit` asks for one touch. Drop `--global` to scope it to a single
repo (handy if only some repos should be signed by the device).

```sh
git commit -m "…"          # touch the device when the LED blinks
git log --show-signature   # see the signature on each commit
```

### Verify locally

Verification needs an `allowed_signers` file mapping identities to public keys:

```sh
mkdir -p ~/.config/git
echo "you@example.com namespaces=\"git\" $(cat ~/.ssh/id_ed25519_sk.pub)" \
    >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

git verify-commit HEAD              # "Good \"git\" signature for you@example.com"
git log --show-signature -1
```

Without that file git can *make* signatures but reports every commit as
"No signature" on verify — that is the file missing, not a bad signature.

### On GitHub / GitLab

Add the **same `.pub`** as a **Signing key** (this is a separate entry from an
authentication key — GitHub: *Settings → SSH and GPG keys → New SSH key → Key
type: Signing Key*). Commits then show as **Verified**. Turn on **vigilant mode**
(GitHub) to flag any *unsigned* commit on your account as Unverified.

## OpenPGP signing

First put a signing-capable key on the card and learn its key id — see
[openpgp.md](openpgp.md). Then:

```sh
git config --global gpg.format openpgp        # the git default; set it explicitly
git config --global user.signingkey 0xLONGKEYID
git config --global commit.gpgsign true
git config --global tag.gpgsign true
# if gpg isn't found by name on your platform:
git config --global gpg.program $(command -v gpg)
```

`git commit` now goes through `gpg` → `scdaemon` → the card: the **User PIN**
once per session, then a **touch** per signature if the SIG slot's UIF touch
policy is on ([openpgp.md](openpgp.md)).

```sh
git commit -m "…"
git log --show-signature        # "Good signature from …" via your gpg keyring
git verify-tag v1.0
```

### On GitHub / GitLab

Export the public key and add it as a **GPG key** (*Settings → SSH and GPG keys →
New GPG key*):

```sh
gpg --armor --export 0xLONGKEYID    # paste the block into the forge
```

The email on a signing UID must match your commit email for the forge to mark it
Verified.

## Authenticating: push, pull, and 2FA

Signing proves *who wrote* a commit. **Authenticating** is how you push, pull, and
get past the forge's security-key prompts. The device does this too — with
*separate* credentials from the signing key.

### Push / pull over SSH

The cleanest path: use the device's `-sk` SSH key (or the OpenPGP **AUT** subkey
via gpg-agent) as your transport. Add the **public** key to the forge as an
**Authentication** key — on GitHub this is a *separate* entry from the signing
key (*Settings → SSH and GPG keys → New SSH key → Key type: Authentication*) —
point the remote at SSH, and each connection is a challenge the key answers with
a touch:

```sh
git remote set-url origin git@github.com:you/repo.git
git push                     # touch when the LED blinks
```

That is one touch per *connection*, not per command. To keep a burst of pushes
under a single touch, reuse the SSH channel:

```
# ~/.ssh/config
Host github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_sk
    IdentitiesOnly yes
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m         # one touch covers everything in the window
```

The key setup itself is the [SSH guide](ssh.md); here it just doubles as the git
transport.

### Push / pull over HTTPS

Over HTTPS git authenticates with a **token**, not the key — the device isn't in
that path. But it protects the *account* the token comes from: `gh auth login`,
or signing in to mint a token, triggers the 2FA challenge below, which a tap
clears.

### Account 2FA and "confirm access" challenges

The forges require 2FA and re-challenge for sensitive actions — signing in on a
new machine, changing keys, deleting a repo (GitHub calls this *sudo mode*).
Register the device once and a tap answers every such prompt:

- **GitHub:** *Settings → Password and authentication →* add a **Passkey** (one
  tap, no password) or a **Security key** (second factor).
- **GitLab:** *Settings → Account →* enable a **WebAuthn Device**.

A **passkey** is a resident credential — it costs one of the device's 256
discoverable slots ([ssh.md](ssh.md#resident-discoverable-keys)); a **security
key** 2FA credential is non-resident. Either way the browser shows "use your
security key", you touch, and the challenge clears.

> One device, three jobs: a **signing** key for commits, an **SSH auth** key for
> push/pull, and a **passkey / 2FA** credential for the account — three
> independent credentials on the same RS-Key, each its own touch.

## Living with the touch

Every signature is one touch — that is the security benefit (malware can't sign
in the background), but it adds up on a rebase that re-signs many commits.

- **SSH signing** always touches; there is no caching. For a big rebase, sign the
  final result rather than every intermediate commit, or temporarily set
  `commit.gpgsign false` for the rebase and re-sign at the end.
- **OpenPGP** caches the *PIN* (via `gpg-agent`, `default-cache-ttl`), but the
  **touch** still happens per signature when UIF is on. Turn UIF off on the SIG
  slot if you want PIN-only signing (weaker — any process with the cached PIN can
  then sign).
- `git commit --no-gpg-sign` skips signing for a one-off commit.

## Troubleshooting

- **`error: gpg failed to sign the data`** (SSH mode) → `gpg.format` isn't `ssh`,
  or `user.signingkey` points at a missing file. Re-check both.
- **`git verify-commit` says "No signature"** but the commit *is* signed → the
  `allowed_signers` file isn't configured (above).
- **OpenPGP: `No secret key` / `selecting card failed`** → `scdaemon` lost the
  reader (often after `ykman`/another tool grabbed it): `gpgconf --kill scdaemon`
  and retry; on Linux apply the [linux.md](../linux.md) scdaemon settings.
- **Commits show Unverified on the forge** → the signing key/GPG key isn't added
  to your account, or the commit email doesn't match the key's identity.
- **`git push` says `Permission denied (publickey)`** → the **authentication** key
  isn't on the forge (it is a separate entry from the signing key), or the remote
  is HTTPS not SSH — check with `git remote -v` and `ssh -T git@github.com`.
- **The device never prompts for a touch** → another process is holding it (a
  browser, `gpg-agent`, the [TUI](tui.md)); close it and retry.
