//! Property-based tests for the threshold-signed directory (Addition 4).
//!
//! The whole point of `t`-of-`n` is that no single authority — and no authority replaying
//! itself — can manufacture a quorum. These properties pin acceptance to the count of
//! *distinct, valid* signers for arbitrary consensus bodies and signer sets.

use gyre_directory::{
    accept_consensus, build_is_blessed, detect_equivocation, Authority, Consensus,
};
use proptest::prelude::*;

proptest! {
    // ed25519 keygen + signing dominate; a smaller case count keeps the suite fast.
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// A consensus is accepted **exactly** when at least `threshold` distinct authorities
    /// signed it — never on fewer, and always on enough.
    #[test]
    fn acceptance_tracks_the_distinct_signer_count(
        n in 1usize..6,
        offered in 0usize..6,
        threshold in 1usize..6,
        epoch in any::<u64>(),
        body in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        let authorities: Vec<Authority> = (0..n).map(|_| Authority::generate()).collect();
        let keys: Vec<_> = authorities.iter().map(Authority::public).collect();
        let consensus = Consensus::new(epoch, body);
        let msg = consensus.signing_bytes();

        let signing = offered.min(n);
        let sigs: Vec<_> = (0..signing).map(|i| (i, authorities[i].sign(&msg))).collect();

        prop_assert_eq!(
            accept_consensus(&consensus, &sigs, &keys, threshold),
            signing >= threshold
        );
    }

    /// One authority replaying its own signature can never reach a quorum of two — the
    /// count is over *distinct* authorities, not over signatures.
    #[test]
    fn a_replayed_signature_never_inflates_the_quorum(
        epoch in any::<u64>(),
        copies in 2usize..6,
    ) {
        let authorities: Vec<Authority> = (0..3).map(|_| Authority::generate()).collect();
        let keys: Vec<_> = authorities.iter().map(Authority::public).collect();
        let consensus = Consensus::new(epoch, b"canonical body".to_vec());
        let msg = consensus.signing_bytes();

        let sigs: Vec<_> = (0..copies).map(|_| (0usize, authorities[0].sign(&msg))).collect();
        prop_assert!(
            !accept_consensus(&consensus, &sigs, &keys, 2),
            "{copies} copies of one signature must not reach a 2-of-3 quorum"
        );
    }

    /// A signature over a *different* body never validates — an authority cannot sign one
    /// consensus and have it counted for another.
    #[test]
    fn a_signature_does_not_transfer_between_bodies(
        epoch in any::<u64>(),
        a in prop::collection::vec(any::<u8>(), 0..30),
        b in prop::collection::vec(any::<u8>(), 0..30),
    ) {
        prop_assume!(a != b);
        let authority = Authority::generate();
        let keys = vec![authority.public()];

        let first = Consensus::new(epoch, a);
        let second = Consensus::new(epoch, b);
        let sigs = vec![(0usize, authority.sign(&first.signing_bytes()))];

        prop_assert!(accept_consensus(&first, &sigs, &keys, 1));
        prop_assert!(!accept_consensus(&second, &sigs, &keys, 1));
    }

    /// Equivocation is detected exactly when two *different* bodies for the *same* epoch
    /// are both validly signed — and never when the epochs differ or the bodies match.
    #[test]
    fn equivocation_is_detected_only_on_conflicting_bodies_in_one_epoch(
        epoch in any::<u64>(),
        same_epoch in any::<bool>(),
        different_body in any::<bool>(),
    ) {
        let authorities: Vec<Authority> = (0..2).map(|_| Authority::generate()).collect();
        let keys: Vec<_> = authorities.iter().map(Authority::public).collect();

        let a = Consensus::new(epoch, b"body-a".to_vec());
        let b = Consensus::new(
            if same_epoch { epoch } else { epoch.wrapping_add(1) },
            if different_body { b"body-b".to_vec() } else { b"body-a".to_vec() },
        );

        let sign = |c: &Consensus| -> Vec<(usize, _)> {
            let msg = c.signing_bytes();
            (0..2).map(|i| (i, authorities[i].sign(&msg))).collect()
        };

        prop_assert_eq!(
            detect_equivocation(&a, &sign(&a), &b, &sign(&b), &keys, 2),
            same_epoch && different_body
        );
    }

    /// A build hash is blessed only once enough *independent* rebuilders signed that exact
    /// hash — reproducible builds are only as strong as the number of distinct verifiers.
    #[test]
    fn a_build_is_blessed_only_by_enough_independent_rebuilders(
        hash in prop::array::uniform32(any::<u8>()),
        rebuilders in 1usize..5,
        signing in 0usize..5,
        threshold in 1usize..5,
    ) {
        let keys_owned: Vec<Authority> = (0..rebuilders).map(|_| Authority::generate()).collect();
        let keys: Vec<_> = keys_owned.iter().map(Authority::public).collect();

        let signed = signing.min(rebuilders);
        let sigs: Vec<_> = (0..signed).map(|i| (i, keys_owned[i].sign(&hash))).collect();

        prop_assert_eq!(build_is_blessed(&hash, &sigs, &keys, threshold), signed >= threshold);
    }
}
