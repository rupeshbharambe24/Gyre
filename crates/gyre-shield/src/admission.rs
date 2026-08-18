//! **A real admission protocol** on top of a pluggable [`pow::PowAlgorithm`](crate::pow) puzzle.
//!
//! A raw puzzle is a *cost function*, not an admission control: on its own it takes a
//! caller-supplied challenge, so a client can pick its own, pre-compute a solution offline,
//! and replay that one solution forever. Nothing about it is bound to a server, a time, or a
//! single use. Wiring that directly in front of a service would produce a gate an attacker
//! passes once and then bypasses permanently. This module fixes exactly that, and only that
//! — it is honest about which DoS it addresses (see the ceiling note below). The puzzle
//! *algorithm* is chosen via [`Admission::with_algorithm`] (SHA-256 by default, or the
//! memory-hard Equi-X under the `equix` feature) and is bound into each challenge's tag, so it
//! is as unforgeable as the difficulty.
//!
//! ## What a real gate needs, and how each is met here
//!
//! 1. **The server picks the challenge, not the client.** [`Admission::issue`] mints a
//!    random challenge id, so a client cannot choose a favourable one or reuse work.
//! 2. **Challenges expire.** Each carries an issue deadline; a stale solution is refused.
//!    Expiry bounds both the offline pre-compute window and the size of the spent set.
//! 3. **A solution is single-use.** The server records redeemed challenge ids and refuses a
//!    replay. The set is pruned as challenges expire, so it cannot grow without bound.
//! 4. **Difficulty is bound into the challenge.** The load-scaled difficulty is inside the
//!    authenticated token, so a client cannot downgrade it.
//! 5. **Issuing a challenge is STATELESS.** This is the subtle, load-bearing one. If issuing
//!    a challenge cost the server memory, then *flooding the issue endpoint* would itself be
//!    the denial of service — you would have moved the DoS one step earlier, not solved it.
//!    A challenge is therefore self-authenticating: `id ‖ expiry ‖ difficulty ‖
//!    HMAC(server_key, id ‖ expiry ‖ difficulty)`. The server verifies a returned challenge
//!    is one it issued **without having stored it**, exactly like a SYN cookie. The only
//!    state the server keeps is the spent set of *solved* challenges, and only until they
//!    expire.
//!
//! ## Honest ceiling — the DoS this does and does not address
//!
//! This is **application-layer (L7) admission pricing**. It makes each admission cost an
//! attacker real work while the server pays one HMAC plus one hash to check it. It does
//! **nothing** against a **volumetric (L3/L4) flood**: a stream of packets that saturates
//! the link never reaches this code, and no proof-of-work changes the physics of a full
//! pipe. Volumetric defence is capacity — anycast scrubbing — and Gyre neither has it nor
//! claims it (decision **D22**). The value here is real but bounded: it is the onion-service
//! model — *hide the origin so the flood has no target, and price the requests that do
//! arrive* — and it complements a scrubber, it does not replace one.

use std::collections::HashMap;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::pow::{self, TAG_SHA256};
use crate::{difficulty_for_load, Solution};

type HmacSha256 = Hmac<Sha256>;

/// The authenticated bytes of a challenge, minus the tag: `id ‖ expiry ‖ difficulty ‖ algorithm`.
/// The 1-byte algorithm tag is last so `id`/`expiry`/`difficulty` keep their original offsets.
const CHALLENGE_BODY_LEN: usize = 32 + 8 + 4 + 1;

/// Serialized length of a [`Challenge`] on the wire: body plus a 32-byte tag.
pub const CHALLENGE_LEN: usize = CHALLENGE_BODY_LEN + 32;

/// A server-issued admission challenge. Self-authenticating: it carries an HMAC over its own
/// fields, so the issuing server can verify it later without having stored it.
///
/// It is **not** secret — a client must see it to solve it — but it is **unforgeable** and
/// **unmodifiable** by anyone without the server key. A client cannot change the difficulty,
/// extend the expiry, or fabricate a challenge the server never issued.
#[derive(Clone, Debug)]
pub struct Challenge {
    id: [u8; 32],
    expiry_millis: u64,
    difficulty_bits: u32,
    /// Which [`pow::PowAlgorithm`] this challenge is for (bound into the tag, so a client
    /// cannot swap a hard algorithm for a cheap one any more than it can downgrade difficulty).
    algorithm: u8,
    tag: [u8; 32],
}

impl Challenge {
    /// Solve this challenge with its own algorithm — the work the client pays.
    ///
    /// Returns `None` if the challenge names an algorithm this build cannot solve (e.g. an
    /// Equi-X challenge without the `equix` feature), so the client fails cleanly rather than
    /// sending a proof the server will reject anyway.
    pub fn solve(&self) -> Option<Solution> {
        pow::solve_for(self.algorithm, &self.id, self.difficulty_bits).map(Solution::new)
    }

    /// The difficulty this challenge demands (bound into the tag, so it is not negotiable).
    pub fn difficulty_bits(&self) -> u32 {
        self.difficulty_bits
    }

    /// The puzzle algorithm this challenge is for (a [`pow`] tag, bound into the [`tag`]).
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Serialize for transport: `id ‖ expiry ‖ difficulty ‖ algorithm ‖ tag`, big-endian,
    /// [`CHALLENGE_LEN`] bytes.
    pub fn to_bytes(&self) -> [u8; CHALLENGE_LEN] {
        let mut out = [0u8; CHALLENGE_LEN];
        out[..CHALLENGE_BODY_LEN].copy_from_slice(&self.body());
        out[CHALLENGE_BODY_LEN..].copy_from_slice(&self.tag);
        out
    }

    /// Parse a challenge from the wire. Does **not** authenticate it — that is
    /// [`Admission::redeem`]'s job, which is the only party holding the server key.
    pub fn from_bytes(bytes: &[u8; CHALLENGE_LEN]) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[..32]);
        let mut e = [0u8; 8];
        e.copy_from_slice(&bytes[32..40]);
        let mut d = [0u8; 4];
        d.copy_from_slice(&bytes[40..44]);
        let algorithm = bytes[44];
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[CHALLENGE_BODY_LEN..]);
        Self {
            id,
            expiry_millis: u64::from_be_bytes(e),
            difficulty_bits: u32::from_be_bytes(d),
            algorithm,
            tag,
        }
    }

    /// The body the tag authenticates: `id ‖ expiry ‖ difficulty ‖ algorithm`.
    fn body(&self) -> [u8; CHALLENGE_BODY_LEN] {
        let mut body = [0u8; CHALLENGE_BODY_LEN];
        body[..32].copy_from_slice(&self.id);
        body[32..40].copy_from_slice(&self.expiry_millis.to_be_bytes());
        body[40..44].copy_from_slice(&self.difficulty_bits.to_be_bytes());
        body[44] = self.algorithm;
        body
    }
}

/// Why an admission attempt was refused. Every arm is a *refusal*: the protocol fails
/// closed, so anything that is not an explicit `Ok` denies admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    /// The challenge's tag does not verify under the server key — forged or tampered.
    #[error("challenge is not one this server issued (bad tag)")]
    Forged,
    /// The challenge issue deadline has passed.
    #[error("challenge has expired")]
    Expired,
    /// The submitted nonce does not meet the challenge's difficulty.
    #[error("proof of work does not satisfy the challenge")]
    BadSolution,
    /// This challenge has already been redeemed once.
    #[error("challenge already spent (replay)")]
    Replay,
}

/// The admission controller. Holds the secret key that authenticates challenges and the
/// spent set of already-redeemed ones.
///
/// One instance guards one service. It is deliberately **not** `Clone`: two copies would
/// have independent spent sets and a solution could be replayed once against each.
pub struct Admission {
    server_key: [u8; 32],
    ttl: Duration,
    /// The puzzle algorithm this gate issues challenges for (a [`pow`] tag).
    algorithm: u8,
    /// Redeemed challenge id -> its expiry, so the set can be pruned as entries age out.
    spent: HashMap<[u8; 32], u64>,
}

impl Admission {
    /// A fresh controller with a random server key and the given challenge lifetime, issuing
    /// the default **SHA-256** puzzle.
    ///
    /// `ttl` is the whole security-vs-usability dial: shorter means a smaller pre-compute
    /// window and a smaller spent set, but less tolerance for a slow client or clock skew.
    pub fn new(ttl: Duration) -> Self {
        Self::with_algorithm(ttl, TAG_SHA256)
    }

    /// A controller that issues challenges for a specific puzzle algorithm — e.g.
    /// [`pow::TAG_EQUIX`](crate::pow::TAG_EQUIX) for the memory-hard puzzle (which requires the
    /// crate's `equix` feature, or every redemption fails closed as unsupported).
    pub fn with_algorithm(ttl: Duration, algorithm: u8) -> Self {
        let mut server_key = [0u8; 32];
        getrandom::fill(&mut server_key).expect("OS RNG");
        Self {
            server_key,
            ttl,
            algorithm,
            spent: HashMap::new(),
        }
    }

    fn tag(&self, body: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.server_key).expect("HMAC any key len");
        mac.update(body);
        mac.finalize().into_bytes().into()
    }

    /// Issue a challenge for a client, priced at the current `load`.
    ///
    /// **Stateless**: this stores nothing, so an attacker flooding it costs the server one
    /// random draw and one HMAC per call and no memory at all. That property is the whole
    /// reason the DoS is not simply relocated to this endpoint.
    pub fn issue(&self, now: Duration, load: f64) -> Challenge {
        let mut id = [0u8; 32];
        getrandom::fill(&mut id).expect("OS RNG");
        let expiry_millis = (now + self.ttl).as_millis() as u64;
        let difficulty_bits = difficulty_for_load(load);

        let mut challenge = Challenge {
            id,
            expiry_millis,
            difficulty_bits,
            algorithm: self.algorithm,
            tag: [0u8; 32],
        };
        challenge.tag = self.tag(&challenge.body());
        challenge
    }

    /// Redeem a solved challenge. Returns `Ok(())` iff the challenge is authentic, unexpired,
    /// correctly solved, and not previously spent — checked in that order, and every check
    /// fails closed.
    ///
    /// On success the challenge id is recorded so it cannot be redeemed again, and expired
    /// entries are pruned, so the spent set is bounded by the number of *solutions* seen
    /// within one `ttl` window rather than growing forever.
    pub fn redeem(
        &mut self,
        challenge: &Challenge,
        solution: &Solution,
        now: Duration,
    ) -> Result<(), Denied> {
        // 1. Authenticity — constant-time, before anything derived from the challenge is
        //    trusted. A forged or tampered challenge (including a downgraded difficulty)
        //    fails here.
        let expected = self.tag(&challenge.body());
        if expected.ct_eq(&challenge.tag).unwrap_u8() != 1 {
            return Err(Denied::Forged);
        }

        // 2. Freshness. A stale solution — including one pre-computed long in advance — is
        //    refused once its challenge's deadline passes.
        let now_millis = now.as_millis() as u64;
        if now_millis >= challenge.expiry_millis {
            return Err(Denied::Expired);
        }

        // 3. The actual proof of work, checked by the challenge's own (authenticated)
        //    algorithm. An algorithm this build cannot verify — e.g. an Equi-X challenge on a
        //    server without the `equix` feature — fails closed here rather than being admitted.
        if !pow::verify_for(
            challenge.algorithm,
            &challenge.id,
            &solution.proof,
            challenge.difficulty_bits,
        ) {
            return Err(Denied::BadSolution);
        }

        // 4. Single use. Prune first so the check and the set stay bounded by TTL.
        self.spent.retain(|_, expiry| *expiry > now_millis);
        if self.spent.contains_key(&challenge.id) {
            return Err(Denied::Replay);
        }
        self.spent.insert(challenge.id, challenge.expiry_millis);
        Ok(())
    }

    /// How many unexpired spent challenges are currently retained. Diagnostic; a caller can
    /// watch this to confirm the set stays bounded under load.
    pub fn spent_len(&self) -> usize {
        self.spent.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    fn solved(challenge: &Challenge) -> Solution {
        challenge
            .solve()
            .expect("the default SHA-256 algorithm is always supported")
    }

    #[test]
    fn an_honest_client_is_admitted() {
        let mut gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        let c = gate.issue(now, 0.0);
        let s = solved(&c);
        assert_eq!(gate.redeem(&c, &s, now), Ok(()));
    }

    #[test]
    fn a_solution_cannot_be_replayed() {
        let mut gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        let c = gate.issue(now, 0.0);
        let s = solved(&c);
        assert_eq!(gate.redeem(&c, &s, now), Ok(()), "first use admitted");
        assert_eq!(
            gate.redeem(&c, &s, now),
            Err(Denied::Replay),
            "the SAME solved challenge must be refused the second time — this is the whole \
             difference between an admission protocol and a cost function"
        );
    }

    #[test]
    fn a_forged_challenge_is_refused() {
        let mut gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        // A challenge this server never issued: build one with a made-up tag.
        let forged = Challenge {
            id: [7u8; 32],
            expiry_millis: (now + TTL).as_millis() as u64,
            difficulty_bits: 8,
            algorithm: TAG_SHA256,
            tag: [0u8; 32],
        };
        let s = solved(&forged);
        assert_eq!(gate.redeem(&forged, &s, now), Err(Denied::Forged));
    }

    #[test]
    fn a_downgraded_difficulty_is_refused_as_forgery() {
        // Under flood the server issues a hard challenge. A client that rewrites the
        // difficulty field to something cheap must be caught — the difficulty is inside the
        // authenticated body, so tampering breaks the tag.
        let mut gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        let hard = gate.issue(now, 1.0);
        assert!(
            hard.difficulty_bits() > 8,
            "flood must price above the idle floor"
        );

        let mut downgraded = hard.clone();
        downgraded.difficulty_bits = 1; // cheat: pay almost nothing
        let cheap = solved(&downgraded);
        assert_eq!(
            gate.redeem(&downgraded, &cheap, now),
            Err(Denied::Forged),
            "rewriting the difficulty must fail authentication, not admit a cheap solve"
        );
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let mut gate = Admission::new(TTL);
        let issued = Duration::from_secs(100);
        let c = gate.issue(issued, 0.0);
        let s = solved(&c);
        let after = issued + TTL + Duration::from_secs(1);
        assert_eq!(
            gate.redeem(&c, &s, after),
            Err(Denied::Expired),
            "a solution presented after the challenge's deadline must be refused"
        );
    }

    #[test]
    fn a_wrong_nonce_is_refused() {
        let mut gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        let c = gate.issue(now, 1.0); // non-trivial difficulty
        let wrong = Solution::new(0u64.to_be_bytes().to_vec());
        // nonce 0 is overwhelmingly unlikely to satisfy a flood-level puzzle
        assert_eq!(gate.redeem(&c, &wrong, now), Err(Denied::BadSolution));
    }

    #[test]
    fn the_spent_set_is_bounded_by_ttl_not_by_traffic() {
        // Redeem many challenges, then let them all expire and redeem one more. The pruning
        // on redeem must drop the aged entries, so the set reflects a TTL window of
        // solutions, not the all-time total. Otherwise the spent set is itself a slow DoS.
        let mut gate = Admission::new(TTL);
        let t0 = Duration::from_secs(100);
        for _ in 0..25 {
            let c = gate.issue(t0, 0.0);
            let s = solved(&c);
            gate.redeem(&c, &s, t0).unwrap();
        }
        assert_eq!(
            gate.spent_len(),
            25,
            "all 25 are live within the TTL window"
        );

        let later = t0 + TTL + Duration::from_secs(1);
        let c = gate.issue(later, 0.0);
        let s = solved(&c);
        gate.redeem(&c, &s, later).unwrap();
        assert_eq!(
            gate.spent_len(),
            1,
            "the 25 expired entries must be pruned; only the fresh redemption remains"
        );
    }

    #[test]
    fn issuing_stores_nothing() {
        // The DoS-critical property: issuing a challenge must not grow server state, or the
        // issue endpoint is the new soft target.
        let gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        for _ in 0..10_000 {
            let _ = gate.issue(now, 1.0);
        }
        assert_eq!(
            gate.spent_len(),
            0,
            "ten thousand issued challenges must cost zero stored state"
        );
    }

    #[test]
    fn a_challenge_survives_a_wire_round_trip() {
        let gate = Admission::new(TTL);
        let now = Duration::from_secs(100);
        let c = gate.issue(now, 0.5);
        let back = Challenge::from_bytes(&c.to_bytes());
        assert_eq!(back.id, c.id);
        assert_eq!(back.expiry_millis, c.expiry_millis);
        assert_eq!(back.difficulty_bits, c.difficulty_bits);
        assert_eq!(back.algorithm, c.algorithm);
        assert_eq!(back.tag, c.tag);
    }

    #[test]
    fn the_algorithm_is_bound_into_the_tag_and_cannot_be_swapped() {
        // The algorithm sits inside the authenticated body, exactly like difficulty. A client
        // that rewrites it — to claim a puzzle it would rather solve, or one this server cannot
        // verify — must fail authentication, not slip past.
        let mut gate = Admission::new(TTL); // issues SHA-256
        let now = Duration::from_secs(100);
        let mut c = gate.issue(now, 0.0);
        let s = solved(&c); // a valid SHA-256 proof for the real challenge
        c.algorithm = pow::TAG_EQUIX; // tamper: claim a different algorithm
        assert_eq!(
            gate.redeem(&c, &s, now),
            Err(Denied::Forged),
            "swapping the algorithm must break the tag, like any other body edit"
        );
    }

    #[cfg(feature = "equix")]
    #[test]
    fn an_equix_gate_issues_solves_and_admits_end_to_end() {
        // The whole point of wiring: a gate configured for the memory-hard puzzle issues an
        // Equi-X challenge, the client solves it with the challenge's own algorithm, and redeem
        // admits it — proving Equi-X runs through the gate, not just as a standalone function.
        let mut gate = Admission::with_algorithm(TTL, pow::TAG_EQUIX);
        let now = Duration::from_secs(100);
        let c = gate.issue(now, 0.0);
        assert_eq!(c.algorithm(), pow::TAG_EQUIX);
        let s = c.solve().expect("the equix feature is enabled");
        assert_eq!(
            gate.redeem(&c, &s, now),
            Ok(()),
            "a valid Equi-X solve is admitted"
        );
        assert_eq!(
            gate.redeem(&c, &s, now),
            Err(Denied::Replay),
            "and it is single-use, like any admission"
        );
    }
}
