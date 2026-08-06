//! Property-based tests for 2-server IT-PIR (Addition 6).
//!
//! Two invariants matter: the scheme must recover the *exact* record for any directory
//! shape and any target, and the two masks must differ in exactly one position — which is
//! simultaneously why a single server learns nothing and why collusion is fatal.

use gyre_pir::{build_queries, recover, Directory};
use proptest::prelude::*;

/// The XOR scheme requires equal-length records; normalise generated ones to the first
/// record's length so the generator can stay simple.
fn equalized(records: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let len = records[0].len();
    records
        .into_iter()
        .map(|mut r| {
            r.resize(len, 0);
            r
        })
        .collect()
}

proptest! {
    /// For any directory and any target, XORing the two servers' answers returns exactly
    /// the requested record — neither server having learned which one it was.
    #[test]
    fn pir_recovers_the_exact_record(
        records in prop::collection::vec(prop::collection::vec(any::<u8>(), 8..40), 1..24),
        target_seed in any::<usize>(),
    ) {
        let records = equalized(records);
        let n = records.len();
        let target = target_seed % n;

        let dir = Directory::new(records.clone());
        let (qa, qb) = build_queries(n, target);
        let got = recover(&dir.answer(&qa), &dir.answer(&qb));

        prop_assert_eq!(got, records[target].clone());
    }

    /// The masks differ in exactly one position: the target. One server sees a uniformly
    /// random mask (learns nothing); two colluding servers XOR them and learn everything.
    #[test]
    fn the_two_masks_differ_only_at_the_target(n in 1usize..40, seed in any::<usize>()) {
        let target = seed % n;
        let (qa, qb) = build_queries(n, target);
        prop_assert_eq!(qa.len(), n);
        prop_assert_eq!(qb.len(), n);

        let differing: Vec<usize> = (0..n).filter(|&i| qa[i] != qb[i]).collect();
        prop_assert_eq!(differing, vec![target]);
    }

    /// The default path — downloading everything — returns the directory unchanged, which
    /// is what makes it leak-free with no non-collusion assumption.
    #[test]
    fn download_all_returns_every_record_verbatim(
        records in prop::collection::vec(prop::collection::vec(any::<u8>(), 4..24), 1..16),
    ) {
        let records = equalized(records);
        let dir = Directory::new(records.clone());
        prop_assert_eq!(dir.len(), records.len());
        prop_assert!(!dir.is_empty());
        prop_assert_eq!(dir.download_all(), records.as_slice());
    }
}
