//! Property-based tests for the erasure-coding core (S3).
//!
//! The unit tests check specific hand-picked cases; these check the *invariants* over
//! thousands of generated inputs, and shrink any failure to a minimal counterexample.
//! The headline property is the one the whole multipath design rests on: **any** `data`
//! of the `data + parity` fragments reconstruct the message — not just a convenient
//! subset.

use gyre_fec::{encode, Fragment, Reassembler};
use proptest::prelude::*;

/// Deterministic Fisher–Yates shuffle (xorshift64*), so a failing case reproduces
/// exactly from its seed rather than depending on ambient randomness.
fn shuffled(n: usize, seed: u64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    let mut s = seed | 1;
    for i in (1..n).rev() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        idx.swap(i, (s % (i as u64 + 1)) as usize);
    }
    idx
}

proptest! {
    /// **The core S3 guarantee.** Whichever `data` fragments happen to survive — any
    /// subset, in any arrival order — rebuild the original message byte for byte.
    #[test]
    fn any_data_fragments_reconstruct_the_message(
        msg in prop::collection::vec(any::<u8>(), 0..1500),
        data in 2usize..=6,
        parity in 1usize..=4,
        seed in any::<u64>(),
    ) {
        let frags = encode(&msg, 0xFEED, data, parity).unwrap();
        prop_assert_eq!(frags.len(), data + parity);

        let keep: Vec<usize> = shuffled(data + parity, seed).into_iter().take(data).collect();
        let mut reasm = Reassembler::new();
        let mut out = None;
        for i in keep {
            out = reasm.insert(frags[i].clone()).unwrap();
        }
        prop_assert_eq!(out.as_deref(), Some(msg.as_slice()));
    }

    /// The flip side: `data - 1` fragments are never enough. An adversary who collects
    /// fewer than the threshold gets no plaintext out of the coding layer.
    #[test]
    fn fewer_than_data_fragments_never_reconstruct(
        msg in prop::collection::vec(any::<u8>(), 1..800),
        data in 3usize..=6,
        parity in 1usize..=3,
        seed in any::<u64>(),
    ) {
        let frags = encode(&msg, 7, data, parity).unwrap();
        let keep: Vec<usize> = shuffled(data + parity, seed).into_iter().take(data - 1).collect();
        let mut reasm = Reassembler::new();
        for i in keep {
            prop_assert!(reasm.insert(frags[i].clone()).unwrap().is_none());
        }
    }

    /// Every fragment survives serialization to the wire and back, for arbitrary field
    /// values — including ones `encode` would never produce.
    #[test]
    fn fragment_survives_a_wire_round_trip(
        msg_id in any::<u64>(),
        index in any::<u16>(),
        data_shards in any::<u16>(),
        total_shards in any::<u16>(),
        orig_len in any::<u32>(),
        shard in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let frag = Fragment { msg_id, index, data_shards, total_shards, orig_len, shard };
        prop_assert_eq!(Fragment::from_bytes(&frag.to_bytes()).unwrap(), frag);
    }

    /// Robustness: the wire parser must never panic on hostile input — it either parses
    /// or returns an error. This is the fuzzing property, run on stable in CI.
    #[test]
    fn parsing_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = Fragment::from_bytes(&bytes);
    }

    /// Robustness: reassembling attacker-chosen fragments must never panic either —
    /// mismatched shapes and out-of-range indices are rejected, not trusted.
    #[test]
    fn reassembling_arbitrary_fragments_never_panics(
        raw in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..80), 0..6),
    ) {
        let mut reasm = Reassembler::new();
        for bytes in raw {
            if let Ok(frag) = Fragment::from_bytes(&bytes) {
                let _ = reasm.insert(frag);
            }
        }
    }
}
