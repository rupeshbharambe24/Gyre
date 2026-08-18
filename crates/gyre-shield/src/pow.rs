//! **Pluggable client-puzzle algorithms for admission.**
//!
//! Admission pricing needs a puzzle that is expensive to *solve* and cheap to *verify*. The
//! default is **SHA-256 leading-zero-bits**: simple, dependency-free, MIT — but it is the
//! most ASIC/GPU-friendly choice possible, so a hardware attacker solves puzzles orders of
//! magnitude faster than an honest phone, quietly undermining the "priced admission"
//! fairness the gate depends on.
//!
//! The optional **`equix`** feature swaps in **Equi-X** (Tor proposal-327), a *memory-hard*
//! function that narrows that gap. Equi-X (the `equix`/`hashx` crates) is **LGPL-3.0**, so it
//! is **off by default** — the default build ships only the SHA-256 puzzle and never links any
//! LGPL code. A build that wants memory-hard admission opts into `--features equix` and
//! accepts LGPL for that build; nothing forces it on the pure-MIT default.
//!
//! Both algorithms speak the same [`PowAlgorithm`] trait, so the admission layer is written
//! against the trait and the choice is a one-line swap plus a wire tag.

use crate::leading_zero_bits;
use sha2::{Digest, Sha256};

/// Wire tag for the default SHA-256 puzzle (stored in an authenticated challenge so the
/// verifier knows which algorithm a proof is for).
pub const TAG_SHA256: u8 = 1;
/// Wire tag for the optional memory-hard Equi-X puzzle.
pub const TAG_EQUIX: u8 = 2;

/// A client-puzzle algorithm: costly to solve, cheap to verify.
///
/// `difficulty_bits` is a **relative** knob — higher means more work — but the *absolute*
/// cost per bit differs by algorithm and is documented on each implementation (SHA-256 spends
/// `~2^bits` hashes; Equi-X spends memory-hard solves scaled down from the same knob). A
/// `proof` is opaque bytes the client produces and the server checks; its length and meaning
/// are the algorithm's own business.
pub trait PowAlgorithm {
    /// The 1-byte wire tag identifying this algorithm inside an authenticated challenge.
    fn tag(&self) -> u8;
    /// Solve `challenge` at `difficulty_bits` — the work the client pays. Returns proof bytes.
    fn solve(&self, challenge: &[u8; 32], difficulty_bits: u32) -> Vec<u8>;
    /// Verify `proof` for `challenge` at `difficulty_bits` — cheap, what the server pays.
    fn verify(&self, challenge: &[u8; 32], proof: &[u8], difficulty_bits: u32) -> bool;
}

/// The default puzzle: find a nonce whose `SHA-256(challenge ‖ nonce)` has at least
/// `difficulty_bits` leading zero bits. Solve is `~2^difficulty_bits` hashes; verify is one
/// hash. Pure MIT, but ASIC/GPU-friendly — the reason the `equix` feature exists.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Pow;

fn sha256_meets(challenge: &[u8; 32], nonce: u64, bits: u32) -> bool {
    let mut h = Sha256::new();
    h.update(challenge);
    h.update(nonce.to_be_bytes());
    leading_zero_bits(&h.finalize()) >= bits
}

impl PowAlgorithm for Sha256Pow {
    fn tag(&self) -> u8 {
        TAG_SHA256
    }

    fn solve(&self, challenge: &[u8; 32], difficulty_bits: u32) -> Vec<u8> {
        let mut nonce = 0u64;
        loop {
            if sha256_meets(challenge, nonce, difficulty_bits) {
                return nonce.to_be_bytes().to_vec();
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    fn verify(&self, challenge: &[u8; 32], proof: &[u8], difficulty_bits: u32) -> bool {
        let Ok(arr) = <[u8; 8]>::try_from(proof) else {
            return false;
        };
        sha256_meets(challenge, u64::from_be_bytes(arr), difficulty_bits)
    }
}

#[cfg(feature = "equix")]
pub use equix_impl::EquixPow;

/// Solve `challenge` at `difficulty_bits` with the algorithm named by `tag`.
///
/// Returns `None` for an unknown or unsupported tag — including an Equi-X challenge on a build
/// without the `equix` feature. A client that cannot recognise the server's algorithm simply
/// cannot proceed, rather than guessing.
pub fn solve_for(tag: u8, challenge: &[u8; 32], difficulty_bits: u32) -> Option<Vec<u8>> {
    match tag {
        TAG_SHA256 => Some(Sha256Pow.solve(challenge, difficulty_bits)),
        #[cfg(feature = "equix")]
        TAG_EQUIX => Some(EquixPow.solve(challenge, difficulty_bits)),
        _ => None,
    }
}

/// Verify `proof` against `challenge` at `difficulty_bits` for the algorithm named by `tag`.
///
/// **Fails closed on an unknown or unsupported tag** — returns `false`. In particular, a server
/// built without the `equix` feature cannot accept an Equi-X proof, so it refuses it rather than
/// admitting an unverifiable one.
pub fn verify_for(tag: u8, challenge: &[u8; 32], proof: &[u8], difficulty_bits: u32) -> bool {
    match tag {
        TAG_SHA256 => Sha256Pow.verify(challenge, proof, difficulty_bits),
        #[cfg(feature = "equix")]
        TAG_EQUIX => EquixPow.verify(challenge, proof, difficulty_bits),
        _ => false,
    }
}

#[cfg(feature = "equix")]
mod equix_impl {
    use super::{leading_zero_bits, PowAlgorithm, Sha256, TAG_EQUIX};
    use sha2::Digest;

    /// Equi-X (Equihash60,3) solution byte length.
    const SOL_BYTES: usize = 16;

    /// A **memory-hard** admission puzzle (Tor proposal-327). Each attempt is an Equi-X
    /// solve — memory-hard, so a GPU/ASIC loses the large edge it holds over SHA-256. Tunable
    /// difficulty is layered on exactly as Tor does it: keep solving with a fresh nonce until
    /// a solution's hash clears an *effort* target. Verification is one cheap Equi-X check
    /// plus one hash, so the solve/verify asymmetry the gate needs is preserved.
    ///
    /// **LGPL-3.0** (via the `equix`/`hashx` crates). Compiled only with the `equix` feature.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct EquixPow;

    /// Map Gyre's `[8, 20]` difficulty knob to a small Equi-X **effort** (extra leading-zero
    /// bits required on the solution hash). Each effort bit roughly doubles the expected
    /// number of memory-hard solves, so this stays deliberately tiny: the memory-hardness of a
    /// single solve — not the bit count — is where the cost and the GPU-resistance live.
    /// `[8, 20]` maps to `[0, 3]` effort bits (≈1–8 solves).
    fn effort_bits(difficulty_bits: u32) -> u32 {
        difficulty_bits.saturating_sub(8) / 4
    }

    fn sol_hash_ok(sol_bytes: &[u8], effort: u32) -> bool {
        let mut h = Sha256::new();
        h.update(sol_bytes);
        leading_zero_bits(&h.finalize()) >= effort
    }

    /// The Equi-X challenge string is `challenge ‖ nonce`, so each nonce is a fresh puzzle.
    fn challenge_input(challenge: &[u8; 32], nonce: u64) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(challenge);
        buf[32..].copy_from_slice(&nonce.to_be_bytes());
        buf
    }

    impl PowAlgorithm for EquixPow {
        fn tag(&self) -> u8 {
            TAG_EQUIX
        }

        fn solve(&self, challenge: &[u8; 32], difficulty_bits: u32) -> Vec<u8> {
            let effort = effort_bits(difficulty_bits);
            let mut nonce = 0u64;
            loop {
                let input = challenge_input(challenge, nonce);
                // A small fraction of challenges violate HashX program constraints; skip them.
                if let Ok(solutions) = equix::solve(&input) {
                    for sol in solutions.iter() {
                        let bytes = sol.to_bytes();
                        if sol_hash_ok(&bytes, effort) {
                            let mut proof = Vec::with_capacity(8 + SOL_BYTES);
                            proof.extend_from_slice(&nonce.to_be_bytes());
                            proof.extend_from_slice(&bytes);
                            return proof;
                        }
                    }
                }
                nonce = nonce.wrapping_add(1);
            }
        }

        fn verify(&self, challenge: &[u8; 32], proof: &[u8], difficulty_bits: u32) -> bool {
            if proof.len() != 8 + SOL_BYTES {
                return false;
            }
            let nonce = u64::from_be_bytes(proof[..8].try_into().expect("checked len 8"));
            let sol_bytes = &proof[8..];
            if !sol_hash_ok(sol_bytes, effort_bits(difficulty_bits)) {
                return false;
            }
            let arr: [u8; SOL_BYTES] = match sol_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let input = challenge_input(challenge, nonce);
            equix::verify_bytes(&input, &arr).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_solve_then_verify_round_trips() {
        let alg = Sha256Pow;
        let challenge = [7u8; 32];
        let proof = alg.solve(&challenge, 12);
        assert!(
            alg.verify(&challenge, &proof, 12),
            "a fresh solve must verify"
        );
        assert_eq!(alg.tag(), TAG_SHA256);
    }

    #[test]
    fn sha256_verify_rejects_a_tampered_proof_and_a_raised_bar() {
        let alg = Sha256Pow;
        let challenge = [7u8; 32];
        let proof = alg.solve(&challenge, 10);
        // A different challenge must not accept this proof.
        assert!(
            !alg.verify(&[8u8; 32], &proof, 10),
            "wrong challenge must fail"
        );
        // A wrong-length proof must fail, not panic.
        assert!(!alg.verify(&challenge, b"short", 10));
        // The same proof at a much higher difficulty is astronomically unlikely to clear it.
        assert!(
            !alg.verify(&challenge, &proof, 40),
            "a 10-bit proof must not satisfy a 40-bit bar"
        );
    }

    #[cfg(feature = "equix")]
    #[test]
    fn equix_solve_then_verify_round_trips() {
        let alg = EquixPow;
        let challenge = [3u8; 32];
        // Low difficulty (effort 0) keeps the test to a handful of memory-hard solves.
        let proof = alg.solve(&challenge, 8);
        assert!(
            alg.verify(&challenge, &proof, 8),
            "a fresh Equi-X solve must verify"
        );
        assert_eq!(alg.tag(), TAG_EQUIX);
        // Garbage of the right length must be rejected by the Equi-X check.
        let garbage = vec![0u8; proof.len()];
        assert!(
            !alg.verify(&challenge, &garbage, 8),
            "an invalid Equi-X solution must not verify"
        );
        // Wrong length must fail cleanly.
        assert!(!alg.verify(&challenge, b"short", 8));
    }
}
