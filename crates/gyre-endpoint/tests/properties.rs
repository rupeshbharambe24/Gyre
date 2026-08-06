//! Property-based tests for endpoint hardening (Addition 2).
//!
//! Forward secrecy needs every ratchet step to yield a *fresh* key; compartmentalisation
//! needs per-context personas to be reproducible for their owner yet cryptographically
//! unlinkable across contexts; and the uniform fingerprint only feeds the crowd if it is
//! genuinely identical for everyone.

use std::collections::HashSet;

use gyre_endpoint::{naive_fingerprint, uniform_fingerprint, Identity, Ratchet};
use proptest::prelude::*;

proptest! {
    /// Every step of the ratchet chain produces a key never seen before. A repeat would
    /// silently destroy forward secrecy.
    #[test]
    fn every_ratchet_step_yields_a_fresh_key(
        seed in prop::array::uniform32(any::<u8>()),
        steps in 2usize..40,
    ) {
        let mut ratchet = Ratchet::new(seed);
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..steps {
            prop_assert!(seen.insert(ratchet.next_message_key()), "a ratchet key repeated");
        }
    }

    /// The chain is a deterministic function of its seed (so both ends stay in step), and
    /// distinct seeds never collide on the first key.
    #[test]
    fn the_ratchet_is_deterministic_in_its_seed(
        a in prop::array::uniform32(any::<u8>()),
        b in prop::array::uniform32(any::<u8>()),
    ) {
        let mut ra = Ratchet::new(a);
        let mut ra_again = Ratchet::new(a);
        let first = ra.next_message_key();
        prop_assert_eq!(first, ra_again.next_message_key(), "same seed must replay identically");

        if a != b {
            let mut rb = Ratchet::new(b);
            prop_assert_ne!(first, rb.next_message_key(), "distinct seeds must diverge");
        }
    }

    /// Personas are reproducible for their owner (same context ⇒ same key) but unlinkable
    /// across contexts (different context ⇒ different key), for any master secret.
    #[test]
    fn personas_are_reproducible_yet_unlinkable(
        master in prop::array::uniform32(any::<u8>()),
        c1 in "[a-z]{1,12}",
        c2 in "[a-z]{1,12}",
    ) {
        let id = Identity::new(master);
        let p1 = id.persona(&c1);

        prop_assert_eq!(p1.context(), c1.as_str());
        prop_assert_eq!(p1.key(), id.persona(&c1).key(), "same context must be reproducible");

        if c1 != c2 {
            prop_assert_ne!(
                p1.key(),
                id.persona(&c2).key(),
                "different contexts must be cryptographically unlinkable"
            );
        }
    }

    /// Two different users derive different keys for the *same* context, so a shared
    /// context name never links two identities.
    #[test]
    fn two_identities_never_share_a_persona_key(
        a in prop::array::uniform32(any::<u8>()),
        b in prop::array::uniform32(any::<u8>()),
        context in "[a-z]{1,12}",
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(
            Identity::new(a).persona(&context).key(),
            Identity::new(b).persona(&context).key()
        );
    }

    /// The uniform fingerprint is byte-identical for everyone (it feeds the crowd), while
    /// the naive per-user one is not — the contrast is the whole lesson.
    #[test]
    fn the_uniform_fingerprint_is_identical_while_a_naive_one_is_not(
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        prop_assert_eq!(uniform_fingerprint(), uniform_fingerprint());
        if a != b {
            prop_assert_ne!(naive_fingerprint(a), naive_fingerprint(b), "a naive fingerprint identifies you");
        }
    }
}
