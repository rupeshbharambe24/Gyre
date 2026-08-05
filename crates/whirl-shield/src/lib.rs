//! **The inbound rotor — protect a system.**
//!
//! This is the other half of the fabric: instead of hiding a person's outbound
//! traffic, it hides and protects a service that others connect *to*. Two admission
//! mechanisms live here:
//!
//! - **Moving-target-defense (MTD) ingress hopping.** The public ingress a client
//!   connects to is derived from a shared key and the current time window, so an
//!   authorized client (and the origin) can always find it while a scanner without the
//!   key cannot pre-target a stable address.
//! - **Proof-of-work admission.** Opening a connection costs a client puzzle whose
//!   difficulty scales with load, pricing out floods while a normal client pays a small
//!   constant.
//!
//! **Honest ceilings (design decision D22).** MTD ingress derivation needs a
//! client-held key, so it serves a **closed / authorized client set** — not arbitrary
//! open-web clients (that is Cloudflare's domain, and we do not compete there). PoW
//! *re-prices* asymmetry; it does **not** beat a resourced adversary (a botnet or ASIC
//! farm outcomputes mobile clients), and it does **nothing** against pure L3/L4
//! volumetric floods that saturate a link before any puzzle is evaluated. The win here
//! is a trust-topology and targeting win for authenticated tunnels, not raw capacity.
//!
//! The cryptography is the audited [`hmac`] + [`sha2`] crates (D11).

use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// Length, in bytes, of an ingress relay address label (matches the fabric).
pub const ADDR_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Moving-target-defense ingress hopping
// ---------------------------------------------------------------------------

/// A moving ingress schedule. The current valid ingress is `HMAC(key, window)` mapped
/// onto a set of candidate relays; holders of `key` compute it, scanners cannot.
pub struct IngressSchedule {
    key: Vec<u8>,
    window: Duration,
    candidates: Vec<[u8; ADDR_LEN]>,
}

impl IngressSchedule {
    /// Build a schedule over `candidates`, rotating every `window`. `key` is the shared
    /// secret an authorized client and the origin both hold.
    pub fn new(key: &[u8], window: Duration, candidates: Vec<[u8; ADDR_LEN]>) -> Self {
        Self {
            key: key.to_vec(),
            window,
            candidates,
        }
    }

    /// The window counter for a given time-since-epoch.
    pub fn window_counter(&self, now: Duration) -> u64 {
        let win = self.window.as_millis().max(1);
        (now.as_millis() / win) as u64
    }

    /// The ingress relay valid in window `counter`.
    pub fn ingress_at(&self, counter: u64) -> [u8; ADDR_LEN] {
        if self.candidates.is_empty() {
            return [0u8; ADDR_LEN];
        }
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(&counter.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        let pick = u64::from_be_bytes(tag[0..8].try_into().unwrap());
        self.candidates[(pick % self.candidates.len() as u64) as usize]
    }

    /// The ingress relay valid at time `now` (since epoch).
    pub fn current_ingress(&self, now: Duration) -> [u8; ADDR_LEN] {
        self.ingress_at(self.window_counter(now))
    }
}

// ---------------------------------------------------------------------------
// Proof-of-work admission
// ---------------------------------------------------------------------------

/// Count the leading zero *bits* of a byte string (the PoW difficulty metric).
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// A client puzzle: find a nonce whose `SHA-256(challenge || nonce)` has at least
/// `difficulty_bits` leading zero bits.
pub struct Puzzle {
    challenge: [u8; 32],
    difficulty_bits: u32,
}

/// A solved puzzle: the winning `nonce` and how many `attempts` it took.
#[derive(Clone, Copy, Debug)]
pub struct Solution {
    pub nonce: u64,
    pub attempts: u64,
}

impl Puzzle {
    /// A puzzle for `challenge` at `difficulty_bits` leading-zero-bit difficulty.
    pub fn new(challenge: [u8; 32], difficulty_bits: u32) -> Self {
        Self {
            challenge,
            difficulty_bits,
        }
    }

    fn meets(&self, nonce: u64) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge);
        hasher.update(nonce.to_be_bytes());
        leading_zero_bits(&hasher.finalize()) >= self.difficulty_bits
    }

    /// Brute-force a solution (what the client pays).
    pub fn solve(&self) -> Solution {
        let mut nonce = 0u64;
        let mut attempts = 0u64;
        loop {
            attempts += 1;
            if self.meets(nonce) {
                return Solution { nonce, attempts };
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    /// Verify a client's nonce (one hash — what the server pays).
    pub fn verify(&self, nonce: u64) -> bool {
        self.meets(nonce)
    }
}

/// Admission difficulty as a function of observed load in `[0, 1]` (0 = idle, 1 =
/// under flood). A normal client always pays the base cost; attackers pay far more
/// as they drive the load up.
pub fn difficulty_for_load(load: f64) -> u32 {
    const BASE_BITS: f64 = 8.0;
    const MAX_EXTRA_BITS: f64 = 12.0;
    (BASE_BITS + load.clamp(0.0, 1.0) * MAX_EXTRA_BITS) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(n: u8) -> Vec<[u8; ADDR_LEN]> {
        (1..=n).map(|i| [i; ADDR_LEN]).collect()
    }

    #[test]
    fn client_and_origin_agree_on_the_moving_ingress() {
        let key = b"shared secret";
        let win = Duration::from_secs(60);
        let client = IngressSchedule::new(key, win, candidates(8));
        let origin = IngressSchedule::new(key, win, candidates(8));
        for counter in 0..100 {
            assert_eq!(client.ingress_at(counter), origin.ingress_at(counter));
        }
    }

    #[test]
    fn a_scanner_without_the_key_cannot_track_the_ingress() {
        let win = Duration::from_secs(60);
        let authorized = IngressSchedule::new(b"real key", win, candidates(8));
        let scanner = IngressSchedule::new(b"guessed key", win, candidates(8));
        // Over many windows a wrong key rarely lands on the right ingress; assert it is
        // wrong the large majority of the time (chance would be ~1/8).
        let mismatches = (0..200)
            .filter(|&c| authorized.ingress_at(c) != scanner.ingress_at(c))
            .count();
        assert!(
            mismatches > 150,
            "a wrong key should miss most windows, missed {mismatches}/200"
        );
    }

    #[test]
    fn the_ingress_actually_moves() {
        let schedule = IngressSchedule::new(b"k", Duration::from_secs(60), candidates(8));
        let distinct: std::collections::HashSet<_> =
            (0..200).map(|c| schedule.ingress_at(c)).collect();
        assert!(distinct.len() > 1, "the ingress must hop across windows");
    }

    #[test]
    fn pow_solution_verifies_and_verification_is_the_easy_side() {
        let puzzle = Puzzle::new([7u8; 32], 16);
        let solution = puzzle.solve();
        assert!(
            puzzle.verify(solution.nonce),
            "the solved nonce must verify"
        );
        // Solving took real work; verifying took one hash.
        assert!(solution.attempts > 1);
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x0F, 0xFF]), 16 + 4);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn difficulty_rises_with_load() {
        assert!(difficulty_for_load(1.0) > difficulty_for_load(0.0));
        assert_eq!(difficulty_for_load(-5.0), difficulty_for_load(0.0)); // clamped
    }
}
