//! Property-based tests for the pluggable-transport framework (Addition 1).
//!
//! Every transport in the swappable set must round-trip arbitrary already-encrypted
//! bytes, and — because a transport parses bytes straight off a hostile wire — must never
//! panic on garbage. The payload range deliberately crosses the 16 KiB TLS record
//! boundary so `TlsMimic`'s multi-record chunking is exercised.

use gyre_obfs::{default_transports, shannon_entropy_bits_per_byte, Obfuscator, Polymorphic};
use proptest::prelude::*;

fn key() -> [u8; 32] {
    [0x5Au8; 32]
}

proptest! {
    // Payloads up to ~20 KiB with HMAC keystreams are the slow part; fewer cases keeps
    // the suite fast while still crossing the record boundary many times.
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Agility is the defense, so *every* transport must be interchangeable: obfuscate
    /// then deobfuscate returns the original bytes exactly.
    #[test]
    fn every_transport_round_trips(inner in prop::collection::vec(any::<u8>(), 0..20_000)) {
        for transport in default_transports(key()) {
            let wire = transport.obfuscate(&inner);
            let back = transport.deobfuscate(&wire).unwrap();
            prop_assert_eq!(back, inner.clone(), "transport {} must round-trip", transport.name());
        }
    }

    /// Robustness: a censor can feed us anything. Every transport must reject garbage
    /// with an error rather than panicking.
    #[test]
    fn deobfuscating_arbitrary_bytes_never_panics(
        wire in prop::collection::vec(any::<u8>(), 0..600),
    ) {
        for transport in default_transports(key()) {
            let _ = transport.deobfuscate(&wire);
        }
    }

    /// The entropy meter is always a valid bits-per-byte figure. It exists to *measure*
    /// the honest ceiling — that "looks-like-nothing" output is itself a DPI fingerprint.
    #[test]
    fn entropy_is_always_within_bounds(bytes in prop::collection::vec(any::<u8>(), 0..2000)) {
        let e = shannon_entropy_bits_per_byte(&bytes);
        prop_assert!((0.0..=8.0).contains(&e), "entropy {e} outside 0..=8");
    }

    /// The polymorphic transport must never emit the same wire bytes twice for the same
    /// input — a fresh nonce and padding each time is what makes it "look like nothing".
    #[test]
    fn polymorphic_output_never_repeats(inner in prop::collection::vec(any::<u8>(), 1..500)) {
        let poly = Polymorphic::new(key());
        prop_assert_ne!(poly.obfuscate(&inner), poly.obfuscate(&inner));
    }

    /// A transport keyed differently cannot recover the plaintext — it either errors or
    /// returns something else, but never the original bytes.
    #[test]
    fn a_wrong_key_never_recovers_the_plaintext(
        inner in prop::collection::vec(any::<u8>(), 32..400),
    ) {
        let wire = Polymorphic::new(key()).obfuscate(&inner);
        let wrong = Polymorphic::new([0xA5u8; 32]);
        if let Ok(out) = wrong.deobfuscate(&wire) {
            prop_assert_ne!(out, inner.clone(), "a wrong key must not recover the plaintext");
        }
    }
}
