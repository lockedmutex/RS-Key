// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! Fast RSA bignum modular exponentiation for ARMv7E-M (Cortex-M33 + DSP),
//! wrapping the vendored rsa-armv7 C + ARM assembly (Emil Lenngren, BSD-2-Clause
//! — see `csrc/LICENSE.txt`). The host build (no ARM assembler) falls back to a
//! num-bigint-dig modexp, keeping the prime-search logic testable. All multi-byte
//! values are **little-endian** except the modexp exponent (big-endian, per the C API).

/// Largest modulus this handles: an RSA-4096 prime is 2048 bits = 256 bytes. The
/// asm requires the modulus length to be a multiple of 32 bytes — every standard
/// RSA prime size (512/1024/1536/2048-bit) qualifies.
pub const MAX_MOD: usize = 256;

// ----------------------------------------------------------- small primes ----

const N_SMALL: usize = 1280;

/// The first [`N_SMALL`] odd primes (3, 5, 7, …), computed at compile time. Trial
/// division by these rejects the vast majority of composite candidates cheaply,
/// before the (relatively) expensive strong-MR modexp. How many of them a given
/// candidate is actually divided by is [`sieve_count`] of its length — the
/// larger the prime, the dearer that modexp, so the deeper it pays to sieve.
const SMALL_PRIMES: [u32; N_SMALL] = build_small_primes();

/// How many small primes to trial-divide a candidate of `cand_len` bytes by.
///
/// Each division that rejects a composite saves one strong-MR modexp, and the
/// modexp cost grows far faster with key size than a trial division does:
/// measured on the RP2350 (the `keygen-bench` vendor command), one strong MR
/// is ~35 ms at a 1024-bit prime and ~239 ms at 2048-bit, while one trial
/// division is ~11 µs and ~23 µs. The break-even prime bound (sieve while
/// `p < c_modexp / c_div`) is therefore ~3.1k and ~10.5k respectively — far
/// past the flat 256-prime (≤1619) sieve we used to run. The optimum scales
/// ~quadratically with prime length (modexp ~k³, division ~k), so step the
/// count by candidate size:
const fn sieve_count(cand_len: usize) -> usize {
    match cand_len {
        0..=64 => 256,    // ≤ RSA-1024 half (rare; fips blocks 1024 gen anyway)
        65..=128 => 448,  // RSA-2048 half (1024-bit) → primes ≲ 3.1k
        129..=192 => 832, // RSA-3072 half (1536-bit)
        _ => N_SMALL,     // RSA-4096 half (2048-bit) → primes ≲ 10.5k
    }
}

const fn build_small_primes() -> [u32; N_SMALL] {
    let mut primes = [0u32; N_SMALL];
    let mut count = 0;
    let mut cand = 3u32;
    while count < N_SMALL {
        let mut is_prime = true;
        let mut d = 3u32;
        while d * d <= cand {
            if cand.is_multiple_of(d) {
                is_prime = false;
                break;
            }
            d += 2;
        }
        if is_prime {
            primes[count] = cand;
            count += 1;
        }
        cand += 2;
    }
    primes
}

/// `n mod m`, with `n` little-endian — Horner's method over the bytes from the
/// most significant down. `m` must be non-zero and `< 2^23` (so the intermediate
/// `(r << 8) | b` stays within `u32`, keeping this on the M33's hardware 32-bit
/// divide rather than the much slower 64-bit software path).
pub fn mod_small(n_le: &[u8], m: u32) -> u32 {
    debug_assert!(m != 0 && m < (1 << 23));
    let mut r: u32 = 0;
    for &b in n_le.iter().rev() {
        r = ((r << 8) | b as u32) % m;
    }
    r
}

/// Does `n` (little-endian) have a small prime factor among the first
/// [`sieve_count`] primes for its length? Trial division only ever *rejects*,
/// so it can never misclassify a composite as prime — at worst a too-shallow
/// sieve just lets more composites through to the (vetted) strong-MR test.
pub fn has_small_factor(n_le: &[u8]) -> bool {
    SMALL_PRIMES[..sieve_count(n_le.len())]
        .iter()
        .any(|&p| mod_small(n_le, p) == 0)
}

// ------------------------------------------------------ incremental sieve -----

/// Force a fresh window after this many steps even if no overflow — a cap, not
/// a correctness bound (the residues never drift). Keeps the candidate stream
/// from wandering arbitrarily far from a fresh random draw.
const SIEVE_WINDOW: u32 = 1 << 14;

/// A running small-prime sieve over consecutive candidates `n, n+2, n+4, …`.
///
/// The flat [`has_small_factor`] re-derives every residue `n mod pᵢ` from
/// scratch (a Horner pass per prime) on every candidate. But consecutive odd
/// candidates differ by 2, so each residue just steps `r ← (r + 2) mod pᵢ` —
/// one add and a compare, no division, no Horner. One full `mod_small` set is
/// paid once when a window is (re)seeded, then amortized over thousands of
/// near-free steps. The compositeness verdict is identical to
/// [`has_small_factor`] (proved by the `incremental_matches_flat` test); only
/// the candidate *stream* changes from independent draws to "scan up from a
/// random odd start", which is exactly how OpenSSL/GMP generate RSA primes.
/// The primality decision (strong MR + Lucas) is untouched, so this cannot
/// affect key strength — only search speed.
pub struct IncrementalSieve {
    half: usize,
    cnt: usize,
    // `MAX_MOD` is already a single prime's width (an RSA-4096 prime = 256 B).
    cand: [u8; MAX_MOD],
    res: [u32; N_SMALL],
    steps: u32,
    seeded: bool,
}

impl Default for IncrementalSieve {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalSieve {
    /// An unseeded sieve; `const` so it can initialize a `static`.
    pub const fn new() -> Self {
        Self {
            half: 0,
            cnt: 0,
            cand: [0; MAX_MOD],
            res: [0; N_SMALL],
            steps: 0,
            seeded: false,
        }
    }

    /// True until the first [`reseed`](Self::reseed), and again once a window is
    /// exhausted — the caller must reseed before the next [`step`](Self::step).
    pub fn needs_seed(&self) -> bool {
        !self.seeded
    }

    /// Begin a fresh window from `seed_le` (caller-supplied random bytes, length
    /// `half`): apply the odd + top-two-bits mask (so the product of two such
    /// primes keeps `2·half·8` bits) and compute every residue once.
    pub fn reseed(&mut self, half: usize, seed_le: &[u8]) {
        debug_assert!((2..=MAX_MOD).contains(&half));
        self.half = half;
        self.cnt = sieve_count(half);
        self.cand[..half].copy_from_slice(&seed_le[..half]);
        self.cand[half - 1] |= 0xC0;
        self.cand[0] |= 0x01;
        for (r, &p) in self.res[..self.cnt]
            .iter_mut()
            .zip(&SMALL_PRIMES[..self.cnt])
        {
            *r = mod_small(&self.cand[..half], p);
        }
        self.steps = 0;
        self.seeded = true;
    }

    /// Advance to the next candidate (`n += 2`) and update every residue.
    /// `Some(true)` — passes the small-prime sieve (no factor); `Some(false)` —
    /// composite; `None` — the window ended (top bits would overflow, or the
    /// step cap was hit): reseed before stepping again.
    pub fn step(&mut self) -> Option<bool> {
        if !self.seeded {
            return None;
        }
        // n += 2, little-endian carry.
        let mut carry = 2u16;
        let mut i = 0;
        while carry != 0 && i < self.half {
            let s = self.cand[i] as u16 + carry;
            self.cand[i] = s as u8;
            carry = s >> 8;
            i += 1;
        }
        self.steps += 1;
        // The top two bits must stay set (else the modulus could be short) and
        // the window is capped; either way, end the window.
        if self.cand[self.half - 1] & 0xC0 != 0xC0 || self.steps >= SIEVE_WINDOW {
            self.seeded = false;
            return None;
        }
        // Every residue steps by 2; one conditional subtract keeps it in range.
        // All are updated even after a zero is seen, so the next step stays
        // correct.
        let mut composite = false;
        for (r, &p) in self.res[..self.cnt]
            .iter_mut()
            .zip(&SMALL_PRIMES[..self.cnt])
        {
            *r += 2;
            if *r >= p {
                *r -= p;
            }
            composite |= *r == 0;
        }
        Some(!composite)
    }

    /// The current candidate (little-endian, `half` bytes).
    pub fn candidate(&self) -> &[u8] {
        &self.cand[..self.half]
    }

    /// Wipe the candidate window (a found prime may still sit in it).
    pub fn scrub(&mut self) {
        use zeroize::Zeroize;
        self.cand.zeroize();
        self.res.zeroize();
        self.seeded = false;
    }
}

// -------------------------------------------------------- modexp backend -----

#[cfg(target_os = "none")]
unsafe extern "C" {
    /// rsa-armv7 `bignum_modexp_private_exponent` (see `csrc/bignum_high_level.h`).
    fn bignum_modexp_private_exponent(
        result: *mut u32,
        exponent: *const u8,
        modulus: *const u32,
        exponent_length_bytes: usize,
        modulus_length_bytes: usize,
        temp: *mut u32,
    );
}

#[cfg(target_os = "none")]
fn bytes_to_words_le(src: &[u8], dst: &mut [u32]) {
    for (i, w) in dst.iter_mut().enumerate() {
        let b = i * 4;
        *w = u32::from_le_bytes([src[b], src[b + 1], src[b + 2], src[b + 3]]);
    }
}

#[cfg(target_os = "none")]
fn words_to_bytes_le(src: &[u32], dst: &mut [u8]) {
    for (i, w) in src.iter().enumerate() {
        dst[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// `out = base ^ exponent mod modulus`, all little-endian except `exponent_be`.
/// `modulus_le.len()` must be a multiple of 32 and ≤ [`MAX_MOD`]; `base_le` may be
/// shorter (it is zero-extended). On the device this calls the ARM-assembly
/// routine; on the host it uses num-bigint-dig.
#[cfg(target_os = "none")]
pub fn modexp_priv(base_le: &[u8], exponent_be: &[u8], modulus_le: &[u8], out_le: &mut [u8]) {
    let mod_len = modulus_le.len();
    debug_assert!(mod_len.is_multiple_of(32) && mod_len <= MAX_MOD);
    let words = mod_len / 4;

    // The C wants base placed in `temp` at byte offset 2 × modulus length; `temp`
    // must be ≥ 19 × modulus length bytes; `result` separate from `modulus`.
    let mut temp = [0u32; 19 * MAX_MOD / 4];
    let mut result = [0u32; MAX_MOD / 4];
    let mut modulus = [0u32; MAX_MOD / 4];

    bytes_to_words_le(modulus_le, &mut modulus[..words]);

    // `modulus_bitwise_inv` (= ~modulus) lives at temp + 18·mod_len. The public
    // wrapper does NOT fill it (only the CRT path does), yet the internal modexp
    // reads it — fill it here, or it uses garbage and returns a wrong result.
    for i in 0..words {
        temp[18 * words + i] = !modulus[i];
    }

    let mut base_buf = [0u8; MAX_MOD];
    base_buf[..base_le.len()].copy_from_slice(base_le);
    bytes_to_words_le(&base_buf[..mod_len], &mut temp[2 * words..3 * words]);

    // SAFETY: all buffers are ≥ the sizes the C requires (asserted above for the
    // modulus; `temp` is 19× the max, `result`/`modulus` are MAX_MOD); `result`
    // does not overlap `modulus`; the exponent is a valid big-endian slice.
    unsafe {
        bignum_modexp_private_exponent(
            result.as_mut_ptr(),
            exponent_be.as_ptr(),
            modulus.as_ptr(),
            exponent_be.len(),
            mod_len,
            temp.as_mut_ptr(),
        );
    }
    words_to_bytes_le(&result[..words], &mut out_le[..mod_len]);
    // For keygen the modulus IS the prime candidate (and `temp` holds its
    // Montgomery state + complement) — wipe the working set.
    use zeroize::Zeroize;
    temp.zeroize();
    result.zeroize();
    modulus.zeroize();
    base_buf.zeroize();
}

/// Host fallback (no ARM assembly): the same operation via num-bigint-dig.
#[cfg(not(target_os = "none"))]
pub fn modexp_priv(base_le: &[u8], exponent_be: &[u8], modulus_le: &[u8], out_le: &mut [u8]) {
    use num_bigint_dig::BigUint;
    let r = BigUint::from_bytes_le(base_le).modpow(
        &BigUint::from_bytes_be(exponent_be),
        &BigUint::from_bytes_le(modulus_le),
    );
    let bytes = r.to_bytes_le();
    let n = bytes.len().min(out_le.len());
    out_le[..n].copy_from_slice(&bytes[..n]);
    out_le[n..].fill(0);
}

/// Fermat primality pre-filter to base 2: `2^(n-1) mod n == 1`. `n` is the
/// little-endian candidate, which must be **odd** and a multiple of 32 bytes. A
/// composite almost always fails (only rare Fermat pseudoprimes slip through, to
/// be caught by the vetted final primality test), and a prime always passes — so
/// this never rejects a real prime.
pub fn passes_fermat_base2(n_le: &[u8]) -> bool {
    use zeroize::Zeroize;
    let mod_len = n_le.len();
    // exponent = n − 1 in big-endian. n is odd, so n − 1 just clears bit 0.
    let mut exp_be = [0u8; MAX_MOD];
    for i in 0..mod_len {
        exp_be[mod_len - 1 - i] = n_le[i];
    }
    exp_be[mod_len - 1] &= 0xFE;

    let mut out = [0u8; MAX_MOD];
    modexp_priv(&[2u8], &exp_be[..mod_len], n_le, &mut out[..mod_len]);
    let prime = out[0] == 1 && out[1..mod_len].iter().all(|&b| b == 0);
    // `exp_be` is candidate − 1; for the accepted candidate that is p − 1.
    exp_be.zeroize();
    out.zeroize();
    prime
}

// ------------------------------------------------------- strong Miller-Rabin --

/// Trailing zero bits of a non-zero little-endian value.
fn trailing_zeros_le(v: &[u8]) -> usize {
    for (i, &b) in v.iter().enumerate() {
        if b != 0 {
            return i * 8 + b.trailing_zeros() as usize;
        }
    }
    v.len() * 8
}

/// `out_be = v_le >> s`, emitted big-endian (the modexp exponent format);
/// `out_be.len() == v_le.len()`, high bytes zero-padded.
fn shr_into_be(v_le: &[u8], s: usize, out_be: &mut [u8]) {
    let len = v_le.len();
    let (bytes, bits) = (s / 8, (s % 8) as u32);
    for i in 0..len {
        let lo = v_le.get(i + bytes).copied().unwrap_or(0) as u16;
        let hi = v_le.get(i + bytes + 1).copied().unwrap_or(0) as u16;
        let b = if bits == 0 {
            lo
        } else {
            (lo >> bits) | (hi << (8 - bits))
        };
        out_be[len - 1 - i] = b as u8;
    }
}

/// Little-endian value == 1.
fn is_one_le(v: &[u8]) -> bool {
    v[0] == 1 && v[1..].iter().all(|&b| b == 0)
}

/// Strong Miller-Rabin probable-prime test to base 2 — the Miller-Rabin half
/// of Baillie-PSW — on the (SRAM-resident) asm modexp. `n_le` is the odd
/// little-endian candidate, length a multiple of 32 bytes, like
/// [`passes_fermat_base2`] but strictly stronger: write n − 1 = d·2^s (d odd);
/// n passes iff 2^d ≡ ±1 (mod n) or one of the s − 1 successive squarings
/// hits n − 1. A chain that reaches 1 any other way has exhibited a
/// nontrivial square root of 1, i.e. a factor. Mirrors num-bigint-dig's
/// `probably_prime_miller_rabin(n, 1, force2 = true)` exactly — the host
/// tests hold the two implementations equal over random candidates and the
/// canonical pseudoprime families.
pub fn passes_strong_mr_base2(n_le: &[u8]) -> bool {
    use zeroize::Zeroize;
    let len = n_le.len();
    debug_assert!(len >= 2 && n_le[0] & 1 == 1);

    // n − 1: n is odd, so clearing bit 0 is the whole subtraction.
    let mut nm1 = [0u8; MAX_MOD];
    nm1[..len].copy_from_slice(n_le);
    nm1[0] &= 0xFE;

    // n − 1 = d · 2^s, d odd; the exponent rides big-endian.
    let s = trailing_zeros_le(&nm1[..len]);
    let mut d_be = [0u8; MAX_MOD];
    shr_into_be(&nm1[..len], s, &mut d_be[..len]);

    let mut x = [0u8; MAX_MOD];
    modexp_priv(&[2u8], &d_be[..len], n_le, &mut x[..len]);

    let mut verdict = is_one_le(&x[..len]) || x[..len] == nm1[..len];
    if !verdict {
        for _ in 1..s {
            // One modular squaring: exponent 2 costs ~two multiplications.
            let mut sq = [0u8; MAX_MOD];
            modexp_priv(&x[..len], &[2u8], n_le, &mut sq[..len]);
            x[..len].copy_from_slice(&sq[..len]);
            sq.zeroize();
            if x[..len] == nm1[..len] {
                verdict = true;
                break;
            }
            if is_one_le(&x[..len]) {
                break; // nontrivial √1 — certainly composite
            }
        }
    }
    // For the accepted candidate these hold p − 1 and its power residues.
    nm1.zeroize();
    d_be.zeroize();
    x.zeroize();
    verdict
}

// ------------------------------------------------------------- self-test -----

/// A 256-bit prime and a 256-bit odd composite (little-endian), for an on-device
/// correctness check of the modexp/Fermat path.
const KAT_PRIME_LE: [u8; 32] = [
    0x73, 0x7b, 0xb1, 0xa3, 0x7f, 0x31, 0x80, 0x1c, 0xd1, 0x1a, 0x67, 0x06, 0xfb, 0x40, 0xd6, 0xbd,
    0x57, 0x52, 0x68, 0x46, 0x90, 0x3b, 0xb1, 0x3e, 0xde, 0x56, 0x24, 0x39, 0xf4, 0x60, 0xdc, 0x91,
];
const KAT_COMPOSITE_LE: [u8; 32] = [
    0xb9, 0x22, 0x68, 0x48, 0x3a, 0x7a, 0xde, 0xb9, 0xff, 0x27, 0x6e, 0x4c, 0x64, 0xd2, 0x64, 0xd6,
    0xed, 0x8c, 0x41, 0x96, 0xc9, 0xdb, 0x75, 0x94, 0x2d, 0x10, 0xb8, 0xff, 0x48, 0xf0, 0x78, 0xd4,
];

/// Known-answer test of the modexp path: a known prime must pass and a known
/// composite must fail BOTH the base-2 Fermat test and the strong Miller-Rabin
/// gate the keygen actually uses. Catches a wrong asm result (marshaling /
/// calling-convention bug) before it can weaken the primality decision.
pub fn self_test() -> bool {
    passes_fermat_base2(&KAT_PRIME_LE)
        && !passes_fermat_base2(&KAT_COMPOSITE_LE)
        && passes_strong_mr_base2(&KAT_PRIME_LE)
        && !passes_strong_mr_base2(&KAT_COMPOSITE_LE)
}

/// Kani proof harnesses (`cargo kani -p rsk-rsa-asm`): exhaustive over every
/// input up to the stated bound, where `incremental_matches_flat` below only
/// samples random seeds.
#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
