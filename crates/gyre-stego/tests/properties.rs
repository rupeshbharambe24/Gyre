//! Property-based tests for LSB steganography (Addition 5).
//!
//! The important invariants are that `capacity_bytes` agrees *exactly* with what `embed`
//! will accept, that the carrier is visually unchanged above the low bit, and that
//! `extract` — which reads an attacker-controlled length header — never panics or
//! allocates unboundedly.

use gyre_stego::{capacity_bytes, embed, extract, fits, LENGTH_HEADER_BITS};
use proptest::prelude::*;

proptest! {
    /// Round-trip **and** boundary in one property: `fits` must predict `embed`'s outcome
    /// exactly in both directions, and anything accepted must come back byte-identical.
    ///
    /// Regression: this originally used `secret.len() <= capacity_bytes(cover.len())` and
    /// proptest shrank it to `cover = [], secret = []` — a cover under the 32-byte length
    /// header reports capacity `0`, which reads as "an empty secret fits" even though
    /// `embed` correctly refuses. `fits` exists to remove that ambiguity.
    #[test]
    fn fits_predicts_embedding_exactly_and_secrets_round_trip(
        cover in prop::collection::vec(any::<u8>(), 0..2000),
        secret in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        if fits(cover.len(), secret.len()) {
            let carrier = embed(&cover, &secret).unwrap();
            prop_assert_eq!(extract(&carrier).unwrap(), secret);
        } else {
            prop_assert!(embed(&cover, &secret).is_err(), "a secret that does not fit must be rejected");
        }
    }

    /// A cover smaller than the length header can never carry anything — not even the
    /// empty message — however `capacity_bytes` rounds.
    #[test]
    fn a_cover_below_the_header_size_carries_nothing(
        cover_len in 0usize..LENGTH_HEADER_BITS,
        secret_len in 0usize..8,
    ) {
        prop_assert!(!fits(cover_len, secret_len));
        prop_assert!(embed(&vec![0u8; cover_len], &vec![0u8; secret_len]).is_err());
    }

    /// Above the header, `fits` and `capacity_bytes` agree — capacity is meaningful there.
    #[test]
    fn above_the_header_capacity_and_fits_agree(
        cover_len in LENGTH_HEADER_BITS..3000,
        secret_len in 0usize..300,
    ) {
        prop_assert_eq!(fits(cover_len, secret_len), secret_len <= capacity_bytes(cover_len));
    }

    /// The carrier must look unchanged: same length, and only the least-significant bit
    /// of any byte may differ. That is the entire premise of the technique.
    #[test]
    fn only_the_low_bit_ever_changes(
        cover in prop::collection::vec(any::<u8>(), 300..1200),
        secret in prop::collection::vec(any::<u8>(), 0..30),
    ) {
        prop_assume!(secret.len() <= capacity_bytes(cover.len()));
        let carrier = embed(&cover, &secret).unwrap();
        prop_assert_eq!(carrier.len(), cover.len());
        for (c, s) in cover.iter().zip(&carrier) {
            prop_assert_eq!(c & 0xFE, s & 0xFE, "the high 7 bits must be preserved");
        }
    }

    /// Robustness: `extract` reads a 32-bit length straight out of attacker-controlled
    /// bits, so it must never panic and never allocate beyond the carrier it was given.
    #[test]
    fn extracting_arbitrary_bytes_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        if let Ok(secret) = extract(&bytes) {
            prop_assert!(secret.len() <= bytes.len(), "cannot extract more than the carrier holds");
        }
    }

    /// Capacity is monotone in the cover size and never claims more than the cover.
    #[test]
    fn capacity_is_monotone_and_bounded(a in 0usize..5000, b in 0usize..5000) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(capacity_bytes(lo) <= capacity_bytes(hi));
        prop_assert!(capacity_bytes(hi) <= hi);
    }
}
