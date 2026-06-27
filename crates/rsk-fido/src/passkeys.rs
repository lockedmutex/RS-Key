// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Read-only enumeration of resident (discoverable) credentials for the
//! trusted-display Passkeys view. It walks the same `EF_RP` / `EF_CRED` records as
//! the CTAP `authenticatorCredentialManagement` path but yields decrypted Rust
//! values for the on-device UI instead of a CBOR response, and never mutates flash.
//! The device seed is loaded from `EF_KEY_DEV`, used, and zeroized within each call,
//! so the display task never has to hold it.
//!
//! It deliberately does not reuse `credmgmt`'s `enumerate_rps` / `enumerate_creds`:
//! those are stateful (the begin/next cursor lives in `FidoState`), permission-gated
//! and FIDO-conformance-tested. A separate additive walk leaves that path untouched.

use zeroize::Zeroize;

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};

use crate::consts::{EF_CRED, EF_RP, EF_RPNICK, MAX_RESIDENT_CREDENTIALS};
use crate::credential::{
    NICK_BOX_MAX, RECORD_PREFIX, RP_PREFIX, credential_load, seal_nick, slot_map, unseal_nick,
    unseal_rp_id,
};

/// The device-local PIN seam for a display-initiated action, re-exported here so the
/// trusted display reaches the whole on-device Passkeys/PIN seam — read walks,
/// [`delete_cred`], the PIN check ([`verify_local_pin`]) and the on-device set/change
/// ([`store_local_pin`]) — through one module. Defined next to the canonical
/// `verify_pin_hash` in `clientpin`. [`min_pin_length`] is the floor the set flow shows
/// on the pad and enforces.
pub use crate::clientpin::{
    LocalPin, MAX_PIN_LENGTH, SetPinError, min_pin_length, pin_is_set, store_local_pin,
    verify_local_pin,
};
/// The on-device nickname length cap, re-exported here so the display sizes its rename
/// buffer from the same constant the store enforces.
pub use crate::consts::RP_NICK_MAX_LEN;

/// Largest EF_RP record (count + rpIdHash + boxed domain); domains are short.
const RP_REC_MAX: usize = 256;
/// Largest EF_CRED record — up to ~1 KiB with a large credBlob.
const CRED_REC_MAX: usize = 1024;

/// A resident relying party as shown on-device.
pub struct RpView<'a> {
    /// Decrypted rpId domain (e.g. `"github.com"`), borrowed from internal scratch —
    /// copy it (sanitized) before the visitor returns.
    pub rp_id: &'a str,
    /// The rpIdHash — the stable key the per-RP credential walk takes.
    pub rp_id_hash: [u8; 32],
    /// How many resident credentials this RP holds.
    pub count: u8,
    /// The device-local display nickname ([`set_rp_nickname`]), if one is set —
    /// borrowed from internal scratch like `rp_id`. `None` falls back to the rpId.
    pub nickname: Option<&'a str>,
}

/// One resident credential's account identity, for the per-RP detail screen.
pub struct AccountView<'a> {
    /// `user.name` (e.g. `"alex@example.com"`), or empty if the RP stored none.
    pub user_name: &'a str,
    /// `user.displayName`, or empty.
    pub user_display_name: &'a str,
    /// `user.id` — the binary handle, a last-resort label when no name was stored.
    pub user_id: &'a [u8],
    /// credProtect level (0..=3); ≥2 marks a UV-gated credential.
    pub cred_protect: u64,
    /// The `EF_CRED` slot fid this credential occupies — the key
    /// [`delete_cred`] takes to remove it from the on-device Passkeys view.
    pub ef_cred_fid: u16,
}

/// Visit each resident RP (those with ≥1 credential), decrypting its rpId domain,
/// in slot order. The seed is loaded from `EF_KEY_DEV`, used, and zeroized before
/// returning; with no seed (unprovisioned) or no resident RPs the visitor is never
/// called. Returns the true total of RPs visited — even if the visitor keeps only
/// the first few (so a screen can show "N items" while listing a subset). Records
/// whose domain fails to unseal are skipped.
pub fn for_each_rp<S, F>(dev: &Device, fs: &mut Fs<S>, mut f: F) -> usize
where
    S: Storage,
    F: FnMut(RpView<'_>),
{
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return 0;
    };
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    // Which slots carry a nickname, mapped in one pass so absent nickname slots are
    // never `fs.read`-probed (each such probe would rescan the whole partition).
    let mut nick_present = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RPNICK, &mut nick_present);
    let mut buf = [0u8; RP_REC_MAX];
    let mut plain = [0u8; RP_REC_MAX];
    let mut nick_buf = [0u8; NICK_BOX_MAX];
    let mut nick_plain = [0u8; RP_NICK_MAX_LEN];
    let mut total = 0usize;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = fs.read(EF_RP + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n < RP_PREFIX || buf[0] == 0 {
            continue;
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&buf[1..RP_PREFIX]);
        let Some((rp_id, _)) = unseal_rp_id(&seed, &rp_id_hash, &buf[RP_PREFIX..n], &mut plain)
        else {
            continue;
        };
        // A nickname lives in the parallel EF_RPNICK slot; it opens only under this
        // rpIdHash (the AEAD's AAD), so a stale slot-reuse leftover reads as `None`.
        let nickname = if nick_present[i as usize] {
            fs.read(EF_RPNICK + i, &mut nick_buf).and_then(|m| {
                unseal_nick(
                    &seed,
                    &rp_id_hash,
                    &nick_buf[..m.min(NICK_BOX_MAX)],
                    &mut nick_plain,
                )
            })
        } else {
            None
        };
        total += 1;
        f(RpView {
            rp_id,
            rp_id_hash,
            count: buf[0],
            nickname,
        });
    }
    seed.zeroize();
    plain.zeroize(); // held the cleartext rp domains
    nick_plain.zeroize(); // held the cleartext nicknames
    total
}

/// Set (or clear) the device-local display nickname for a resident RP. An empty `nick`
/// deletes any existing nickname (the RP reverts to showing its rpId); a non-empty one
/// (≤ [`RP_NICK_MAX_LEN`] bytes) is sealed at rest under the device seed and stored in
/// the EF_RPNICK slot parallel to the RP's EF_RP record. Returns whether the change was
/// persisted; `false` if the RP has no resident credentials (nothing to name), the
/// nickname is too long, or the seed is unavailable. The credential box — and so the
/// signing key — is never touched, so the passkey keeps working across a rename.
pub fn set_rp_nickname<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rp_id_hash: &[u8; 32],
    nick: &str,
) -> bool {
    if nick.len() > RP_NICK_MAX_LEN {
        return false;
    }
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    let mut rp = [0u8; RP_REC_MAX];
    let mut slot: Option<u16> = None;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        if let Some(m) = fs.read(EF_RP + i, &mut rp)
            && m.min(rp.len()) >= RP_PREFIX
            && rp[1..RP_PREFIX] == *rp_id_hash
        {
            slot = Some(i);
            break;
        }
    }
    let Some(slot) = slot else {
        return false; // no such resident RP
    };
    if nick.is_empty() {
        let _ = fs.delete(EF_RPNICK + slot); // absent is fine — the RP ends up unnamed
        return true;
    }
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return false;
    };
    let mut rec = [0u8; NICK_BOX_MAX];
    let ok = match seal_nick(&seed, rp_id_hash, nick, &mut rec) {
        Ok(len) => fs.put(EF_RPNICK + slot, &rec[..len]).is_ok(),
        Err(_) => false,
    };
    seed.zeroize();
    ok
}

/// Visit each resident credential under `rp_id_hash` (slot order), decrypting its
/// account identity. Seed loaded + zeroized internally. Returns the true total
/// visited; credentials whose box fails to open are skipped.
pub fn for_each_cred<S, F>(dev: &Device, fs: &mut Fs<S>, rp_id_hash: &[u8; 32], mut f: F) -> usize
where
    S: Storage,
    F: FnMut(AccountView<'_>),
{
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return 0;
    };
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    let mut buf = [0u8; CRED_REC_MAX];
    let mut scratch = [0u8; CRED_REC_MAX];
    let mut total = 0usize;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = fs.read(EF_CRED + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n < RECORD_PREFIX || buf[..32] != *rp_id_hash {
            continue;
        }
        let Some(cred) = credential_load(&seed, &buf[RECORD_PREFIX..n], rp_id_hash, &mut scratch)
        else {
            continue;
        };
        total += 1;
        f(AccountView {
            user_name: cred.user_name,
            user_display_name: cred.user_display_name,
            user_id: cred.user_id,
            cred_protect: cred.ext.cred_protect,
            ef_cred_fid: EF_CRED + i,
        });
    }
    seed.zeroize();
    scratch.zeroize(); // held the decrypted account names
    total
}

/// Delete the resident credential stored at `ef_cred_fid` (an `EF_CRED` slot fid,
/// as surfaced by [`AccountView::ef_cred_fid`]), then decrement — or remove — its
/// `EF_RP` record. The rpIdHash is the cleartext record prefix, so unlike the read
/// walks this needs no seed. Returns whether a credential was removed; an
/// out-of-range fid or an empty/short slot is a no-op returning `false`.
///
/// This is the on-device counterpart of CTAP `deleteCredential` (0x06): the same
/// flash effect, but keyed by slot (what the on-device walk holds) instead of by
/// the host's resident id. Cred-first then RP-decrement matches that path's order.
pub fn delete_cred<S: Storage>(fs: &mut Fs<S>, ef_cred_fid: u16) -> bool {
    if !(EF_CRED..EF_CRED + MAX_RESIDENT_CREDENTIALS).contains(&ef_cred_fid) {
        return false;
    }
    let mut buf = [0u8; CRED_REC_MAX];
    let Some(n) = fs.read(ef_cred_fid, &mut buf) else {
        return false;
    };
    if n.min(buf.len()) < RECORD_PREFIX {
        return false;
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&buf[..32]);
    if fs.delete(ef_cred_fid).is_err() {
        return false;
    }
    let _ = crate::credmgmt::decrement_rp(fs, &rp_id_hash);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rng;
    use crate::consts::{ALG_ES256, CURVE_P256};
    use crate::credential::{CredExt, CredInput, credential_create, credential_store};
    use crate::seed::{ensure_seed, load_keydev};
    use rsk_crypto::sha256;
    use rsk_fs::Fs;
    use rsk_fs::storage::ram::RamStorage;

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    fn dev() -> Device<'static> {
        Device {
            serial_hash: &[0xAB; 32],
            serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            otp_key: None,
        }
    }

    fn provisioned() -> (Fs<RamStorage>, [u8; 32]) {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let seed = load_keydev(&dev(), &mut fs).unwrap();
        (fs, seed)
    }

    // Register a resident credential the way makeCredential's storage primitive does
    // (a sealed box + an EF_CRED record + the boxed EF_RP domain).
    #[allow(clippy::too_many_arguments)]
    fn add(
        fs: &mut Fs<RamStorage>,
        seed: &[u8; 32],
        iv_byte: u8,
        rp_id: &str,
        uid: &[u8],
        name: &str,
        dname: &str,
        cred_protect: u64,
    ) {
        let rp_hash = sha256(rp_id.as_bytes());
        let iv = [iv_byte; 12];
        let inp = CredInput {
            rp_id,
            user_id: uid,
            user_name: name,
            user_display_name: dname,
            use_sign_count: false,
            rk: true,
            created_ms: 1,
            alg: ALG_ES256,
            curve: CURVE_P256 as i64,
            ext: CredExt {
                cred_protect,
                ..CredExt::default()
            },
        };
        let mut boxbuf = [0u8; 512];
        let len = credential_create(seed, &dev(), &inp, &rp_hash, &iv, &mut boxbuf).unwrap();
        credential_store(seed, &dev(), fs, &boxbuf[..len], &rp_hash, rp_id, uid).unwrap();
    }

    #[test]
    fn lists_rps_with_credential_counts() {
        let (mut fs, seed) = provisioned();
        add(
            &mut fs,
            &seed,
            1,
            "github.com",
            b"u-alice",
            "alice",
            "Alice",
            0,
        );
        add(&mut fs, &seed, 2, "github.com", b"u-bob", "bob", "Bob", 0);
        add(
            &mut fs,
            &seed,
            3,
            "google.com",
            b"u-carol",
            "carol",
            "Carol",
            0,
        );

        let mut seen = std::vec::Vec::new();
        let total = for_each_rp(&dev(), &mut fs, |rp| {
            seen.push((rp.rp_id.to_string(), rp.count));
        });
        assert_eq!(total, 2);
        seen.sort();
        assert_eq!(
            seen,
            std::vec![("github.com".to_string(), 2), ("google.com".to_string(), 1)]
        );
    }

    #[test]
    fn lists_accounts_under_one_rp() {
        let (mut fs, seed) = provisioned();
        add(
            &mut fs,
            &seed,
            1,
            "github.com",
            b"u-alice",
            "alice",
            "Alice",
            0,
        );
        add(&mut fs, &seed, 2, "github.com", b"u-bob", "bob", "Bob", 2);
        add(
            &mut fs,
            &seed,
            3,
            "google.com",
            b"u-carol",
            "carol",
            "Carol",
            0,
        );

        let gh = sha256(b"github.com");
        let mut names = std::vec::Vec::new();
        let total = for_each_cred(&dev(), &mut fs, &gh, |a| {
            names.push(a.user_name.to_string());
        });
        assert_eq!(total, 2);
        names.sort();
        assert_eq!(names, std::vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn surfaces_cred_protect_level() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "bank.example", b"u1", "neo", "Neo", 3);
        let h = sha256(b"bank.example");
        let mut levels = std::vec::Vec::new();
        for_each_cred(&dev(), &mut fs, &h, |a| levels.push(a.cred_protect));
        assert_eq!(levels, std::vec![3]);
    }

    #[test]
    fn true_total_even_when_visitor_keeps_fewer() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "a.example", b"u", "n", "N", 0);
        add(&mut fs, &seed, 2, "b.example", b"u", "n", "N", 0);
        add(&mut fs, &seed, 3, "c.example", b"u", "n", "N", 0);

        let mut kept = 0;
        let total = for_each_rp(&dev(), &mut fs, |_| {
            if kept < 1 {
                kept += 1;
            }
        });
        assert_eq!(total, 3, "return is the true total");
        assert_eq!(kept, 1, "visitor may keep a subset");
    }

    #[test]
    fn empty_when_unprovisioned() {
        let mut fs = Fs::new(RamStorage::new(), &[]);
        let mut calls = 0;
        let total = for_each_rp(&dev(), &mut fs, |_| calls += 1);
        assert_eq!(total, 0);
        assert_eq!(calls, 0);
    }

    #[test]
    fn empty_for_rp_with_no_credentials() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        let unknown = sha256(b"nope.example");
        let mut calls = 0;
        let total = for_each_cred(&dev(), &mut fs, &unknown, |_| calls += 1);
        assert_eq!(total, 0);
        assert_eq!(calls, 0);
    }

    fn fids_under(fs: &mut Fs<RamStorage>, rp_id: &str) -> std::vec::Vec<u16> {
        let h = sha256(rp_id.as_bytes());
        let mut fids = std::vec::Vec::new();
        for_each_cred(&dev(), fs, &h, |a| fids.push(a.ef_cred_fid));
        fids
    }

    #[test]
    fn delete_drops_cred_and_decrements_rp() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u-a", "a", "A", 0);
        add(&mut fs, &seed, 2, "github.com", b"u-b", "b", "B", 0);
        add(&mut fs, &seed, 3, "google.com", b"u-c", "c", "C", 0);

        let gh = fids_under(&mut fs, "github.com");
        assert_eq!(gh.len(), 2);
        assert!(delete_cred(&mut fs, gh[0]));

        // The other github account survives, google is untouched.
        assert_eq!(fids_under(&mut fs, "github.com").len(), 1);
        assert_eq!(fids_under(&mut fs, "google.com").len(), 1);
        // The EF_RP count was decremented (2 → 1), so the RP still lists once.
        let mut counts = std::vec::Vec::new();
        for_each_rp(&dev(), &mut fs, |rp| {
            counts.push((rp.rp_id.to_string(), rp.count));
        });
        counts.sort();
        assert_eq!(
            counts,
            std::vec![("github.com".to_string(), 1), ("google.com".to_string(), 1)]
        );
    }

    #[test]
    fn delete_last_cred_removes_rp() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "solo.example", b"u", "n", "N", 0);
        add(&mut fs, &seed, 2, "keep.example", b"u", "n", "N", 0);

        let solo = fids_under(&mut fs, "solo.example");
        assert_eq!(solo.len(), 1);
        assert!(delete_cred(&mut fs, solo[0]));

        // The RP record is gone with its last credential, so the walk no longer
        // surfaces it — only the untouched RP remains.
        let mut seen = std::vec::Vec::new();
        let total = for_each_rp(&dev(), &mut fs, |rp| seen.push(rp.rp_id.to_string()));
        assert_eq!(total, 1);
        assert_eq!(seen, std::vec!["keep.example".to_string()]);
    }

    #[test]
    fn delete_bad_fid_is_noop() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        // Out of range below / at the EF_RP boundary, and an in-range but empty slot.
        assert!(!delete_cred(&mut fs, EF_CRED - 1));
        assert!(!delete_cred(&mut fs, EF_CRED + MAX_RESIDENT_CREDENTIALS));
        assert!(!delete_cred(&mut fs, EF_CRED + 200));
        // The real credential is still there — nothing was removed.
        assert_eq!(fids_under(&mut fs, "github.com").len(), 1);
    }

    // --- Device-local RP nicknames -----------------------------------------

    /// The nickname as `for_each_rp` surfaces it for `rp_id`.
    fn nick_of(fs: &mut Fs<RamStorage>, rp_id: &str) -> Option<std::string::String> {
        let want = sha256(rp_id.as_bytes());
        let mut out = None;
        for_each_rp(&dev(), fs, |rp| {
            if rp.rp_id_hash == want {
                out = rp.nickname.map(|s| s.to_string());
            }
        });
        out
    }

    #[test]
    fn nickname_defaults_to_none_then_roundtrips() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        let gh = sha256(b"github.com");
        assert_eq!(
            nick_of(&mut fs, "github.com"),
            None,
            "unset → rpId fallback"
        );

        assert!(set_rp_nickname(&dev(), &mut fs, &gh, "Work GitHub"));
        assert_eq!(
            nick_of(&mut fs, "github.com").as_deref(),
            Some("Work GitHub")
        );
    }

    #[test]
    fn nickname_update_then_clear() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        let gh = sha256(b"github.com");
        assert!(set_rp_nickname(&dev(), &mut fs, &gh, "first"));
        assert!(set_rp_nickname(&dev(), &mut fs, &gh, "second"));
        assert_eq!(nick_of(&mut fs, "github.com").as_deref(), Some("second"));
        // An empty nickname clears it — the RP reverts to its rpId.
        assert!(set_rp_nickname(&dev(), &mut fs, &gh, ""));
        assert_eq!(nick_of(&mut fs, "github.com"), None);
    }

    #[test]
    fn nickname_on_unknown_rp_is_rejected() {
        let (mut fs, _seed) = provisioned();
        let ghost = sha256(b"nobody.example");
        assert!(!set_rp_nickname(&dev(), &mut fs, &ghost, "ghost"));
    }

    #[test]
    fn nickname_too_long_is_rejected_and_not_stored() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        let gh = sha256(b"github.com");
        let long = "a".repeat(RP_NICK_MAX_LEN + 1);
        assert!(!set_rp_nickname(&dev(), &mut fs, &gh, &long));
        assert_eq!(nick_of(&mut fs, "github.com"), None);
        // Exactly the cap is accepted.
        let max = "b".repeat(RP_NICK_MAX_LEN);
        assert!(set_rp_nickname(&dev(), &mut fs, &gh, &max));
        assert_eq!(
            nick_of(&mut fs, "github.com").as_deref(),
            Some(max.as_str())
        );
    }

    #[test]
    fn nickname_is_per_rp_and_survives_a_new_account() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u-a", "a", "A", 0);
        add(&mut fs, &seed, 2, "google.com", b"u-b", "b", "B", 0);
        let gh = sha256(b"github.com");
        let gg = sha256(b"google.com");
        assert!(set_rp_nickname(&dev(), &mut fs, &gh, "GH"));
        assert!(set_rp_nickname(&dev(), &mut fs, &gg, "GG"));
        // Adding another github account (bumps the count) must not disturb the nickname.
        add(&mut fs, &seed, 3, "github.com", b"u-c", "c", "C", 0);
        assert_eq!(nick_of(&mut fs, "github.com").as_deref(), Some("GH"));
        assert_eq!(nick_of(&mut fs, "google.com").as_deref(), Some("GG"));
    }

    #[test]
    fn nickname_is_dropped_when_its_rp_disappears() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "solo.example", b"u", "n", "N", 0);
        let h = sha256(b"solo.example");
        assert!(set_rp_nickname(&dev(), &mut fs, &h, "Solo"));

        // Delete the only credential — the RP (and its nickname) go away.
        let solo = fids_under(&mut fs, "solo.example");
        assert!(delete_cred(&mut fs, solo[0]));

        // Re-create the same RP; it must NOT inherit the old nickname.
        add(&mut fs, &seed, 2, "solo.example", b"u2", "n2", "N2", 0);
        assert_eq!(
            nick_of(&mut fs, "solo.example"),
            None,
            "a fresh RP at a reused slot is unnamed"
        );
    }

    #[test]
    fn nickname_is_sealed_at_rest() {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        let gh = sha256(b"github.com");
        assert!(set_rp_nickname(&dev(), &mut fs, &gh, "secretname"));
        // The cleartext must not appear in any EF_RPNICK slot's bytes.
        let mut rec = [0u8; 256];
        let mut found_cleartext = false;
        for i in 0..MAX_RESIDENT_CREDENTIALS {
            if let Some(n) = fs.read(EF_RPNICK + i, &mut rec) {
                let n = n.min(rec.len());
                if rec[..n]
                    .windows(b"secretname".len())
                    .any(|w| w == b"secretname")
                {
                    found_cleartext = true;
                }
            }
        }
        assert!(!found_cleartext, "nickname must be sealed, not cleartext");
    }
}
