//! Property-based tests for the Sphinx onion wrapper (S0).
//!
//! These assert the separation-of-knowledge guarantee over generated routes and
//! payloads, plus the fixed-size-on-the-wire property that makes cover traffic possible
//! at all — and that the wire parser never panics on hostile input.

use std::time::Duration;

use gyre_sphinx::{
    exponential_delays, null_surb, packet_from_bytes, packet_to_bytes, wrap, Relay, Unwrapped,
    ADDRESS_LEN, DEST_ADDRESS_LEN,
};
use proptest::prelude::*;

proptest! {
    // X25519 keygen + onion construction dominate the runtime, so a smaller case
    // count keeps the suite fast while still exercising hundreds of routes.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// **The S0 guarantee.** For any payload and any route length, the exit recovers the
    /// exact payload and every middle relay learns *only* the next hop — never both ends.
    #[test]
    fn onion_delivers_exactly_and_reveals_only_the_next_hop(
        payload in prop::collection::vec(any::<u8>(), 0..256),
        hops in 1usize..=4,
    ) {
        let relays: Vec<Relay> = (0..hops)
            .map(|i| Relay::new([(i as u8) + 1; ADDRESS_LEN]))
            .collect();
        let route: Vec<_> = relays.iter().map(Relay::as_node).collect();
        let dest = [0xD5u8; DEST_ADDRESS_LEN];

        let mut in_flight = Some(wrap(&payload, &route, dest, null_surb()).unwrap());
        for (i, relay) in relays.iter().enumerate() {
            let packet = in_flight.take().expect("a packet is in flight");
            match relay.process(packet).unwrap() {
                Unwrapped::Forward { next_address, packet, .. } => {
                    prop_assert!(i + 1 < hops, "only non-exit hops forward");
                    prop_assert_eq!(next_address, relays[i + 1].address());
                    in_flight = Some(packet);
                }
                Unwrapped::Final { dest_address, payload: got } => {
                    prop_assert_eq!(i, hops - 1, "only the last hop delivers");
                    prop_assert_eq!(dest_address, dest);
                    prop_assert_eq!(got.as_slice(), payload.as_slice());
                }
            }
        }
    }

    /// Cover traffic only works if a tiny decoy and a long real message are
    /// **indistinguishable by length**. Sphinx's fixed padding must guarantee that for
    /// *any* pair of payloads, not just the ones in the unit test.
    #[test]
    fn every_packet_is_the_same_size_on_the_wire(
        a in prop::collection::vec(any::<u8>(), 0..256),
        b in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let relays: Vec<Relay> = (1u8..=3).map(|i| Relay::new([i; ADDRESS_LEN])).collect();
        let route: Vec<_> = relays.iter().map(Relay::as_node).collect();
        let dest = [9u8; DEST_ADDRESS_LEN];

        let pa = packet_to_bytes(&wrap(&a, &route, dest, null_surb()).unwrap());
        let pb = packet_to_bytes(&wrap(&b, &route, dest, null_surb()).unwrap());
        prop_assert_eq!(pa.len(), pb.len());
    }

    /// Layered encryption is bound to each hop's key: a relay that is not on the route
    /// can never process the packet, whatever the payload.
    #[test]
    fn a_relay_off_the_route_can_never_process(
        payload in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let on_route = Relay::new([1u8; ADDRESS_LEN]);
        let stranger = Relay::new([2u8; ADDRESS_LEN]);
        let packet = wrap(
            &payload,
            &[on_route.as_node()],
            [3u8; DEST_ADDRESS_LEN],
            null_surb(),
        ).unwrap();
        prop_assert!(stranger.process(packet).is_err());
    }

    /// Packets survive serialization to the wire and back unchanged.
    #[test]
    fn packet_survives_a_wire_round_trip(
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let relay = Relay::new([1u8; ADDRESS_LEN]);
        let packet = wrap(
            &payload,
            &[relay.as_node()],
            [4u8; DEST_ADDRESS_LEN],
            null_surb(),
        ).unwrap();
        let bytes = packet_to_bytes(&packet);
        let parsed = packet_from_bytes(&bytes).unwrap();
        prop_assert_eq!(packet_to_bytes(&parsed), bytes);
    }

    /// Robustness: a relay parses packets straight off a hostile network, so the parser
    /// must never panic — it either parses or returns an error.
    #[test]
    fn parsing_arbitrary_bytes_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..2200),
    ) {
        let _ = packet_from_bytes(&bytes);
    }

    /// The mixing schedule always yields exactly one delay per hop, and a zero mean is
    /// safe (no division by zero) — the FAST lane depends on that.
    #[test]
    fn the_delay_schedule_has_one_delay_per_hop(n in 0usize..8, millis in 0u64..200) {
        let delays = exponential_delays(n, Duration::from_millis(millis));
        prop_assert_eq!(delays.len(), n);
        if millis == 0 {
            prop_assert!(delays.iter().all(|d| d.to_nanos() == 0));
        }
    }
}
