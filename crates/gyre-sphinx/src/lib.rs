//! **Milestone S0 — a Sphinx onion, built and processed hop-by-hop.**
//!
//! This is the first brick of the outbound rotor. It proves the core property the
//! whole design rests on: a packet can be routed through several relays such that
//! **no relay learns both its predecessor and the final destination**, and the exit
//! recovers the exact payload.
//!
//! We do **not** implement the Sphinx construction ourselves — that would violate
//! design decision **D11** (never roll your own crypto). All the cryptography lives
//! in the audited [`sphinx_packet`] crate (Nym's implementation of the Sphinx paper,
//! Danezis–Goldberg). This crate only adds an ergonomic, well-typed wrapper.
//!
//! Per-hop Poisson mixing delays (S2) are supported here via [`wrap_with_delays`]
//! and [`exponential_delays`]; still to come are erasure-coded multipath (S3) and
//! the FAST/MIX lanes (S4).

use std::time::Duration;

use sphinx_packet::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH,
};
use sphinx_packet::header::delays::generate_from_average_duration;
use sphinx_packet::packet::ProcessedPacketData;
use sphinx_packet::route::{
    Destination, DestinationAddressBytes, NodeAddressBytes, SURBIdentifier,
};
use x25519_dalek::{PublicKey, StaticSecret};

/// Re-exported so callers can build routes, delay schedules, and *hold packets* without
/// depending on `sphinx-packet` directly.
///
/// `SphinxPacket` appears throughout this crate's public API ([`wrap`], [`unwrap`],
/// [`Relay::process`], [`packet_from_bytes`]), so a caller that wants to store one — in a
/// queue, an event, or a struct field — must be able to *name* the type. Without this
/// re-export they would have to add their own `sphinx-packet` dependency, which is exactly
/// the coupling this wrapper exists to prevent (**D11**).
pub use sphinx_packet::header::delays::Delay;
pub use sphinx_packet::route::Node;
pub use sphinx_packet::SphinxPacket;

/// Length, in bytes, of a relay address label in the Sphinx format we use.
pub const ADDRESS_LEN: usize = NODE_ADDRESS_LENGTH;
/// Length, in bytes, of a destination address in the Sphinx format we use.
pub const DEST_ADDRESS_LEN: usize = DESTINATION_ADDRESS_LENGTH;

/// Errors from building or processing a Gyre onion packet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying Sphinx layer rejected the packet (bad key, malformed, replay…).
    #[error("sphinx: {0}")]
    Sphinx(#[from] sphinx_packet::Error),
}

/// Convenience alias for results from this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A relay's long-term X25519 keypair plus its address label.
///
/// In S0 the address is an opaque label the caller assigns (so tests can assert
/// "hop *i* only learned hop *i+1*"). Later milestones bind it to a real transport
/// address published by the decentralized directory (Add 4).
pub struct Relay {
    secret: StaticSecret,
    public: PublicKey,
    address: [u8; NODE_ADDRESS_LENGTH],
}

impl Relay {
    /// Generate a fresh relay with the given address label, using the OS CSPRNG.
    pub fn new(address: [u8; NODE_ADDRESS_LENGTH]) -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            address,
        }
    }

    /// A relay whose long-term key is derived deterministically from 32 secret bytes.
    ///
    /// Real relays need this: a relay that generated a fresh key on every restart would
    /// invalidate every descriptor already published about it, and every onion built for
    /// it in flight. The seed is the relay's long-term secret — treat it as one.
    pub fn from_secret_bytes(address: [u8; NODE_ADDRESS_LENGTH], secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            address,
        }
    }

    /// This relay's address label.
    pub fn address(&self) -> [u8; NODE_ADDRESS_LENGTH] {
        self.address
    }

    /// This relay's public key (what a client needs to include it in a circuit).
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// The routing descriptor a client uses to place this relay in a route.
    pub fn as_node(&self) -> Node {
        Node::new(NodeAddressBytes::from_bytes(self.address), self.public)
    }

    /// Process one onion packet at this relay, using its own secret key.
    ///
    /// The secret key never leaves the relay — this is why the field is private.
    pub fn process(&self, packet: SphinxPacket) -> Result<Unwrapped> {
        unwrap(packet, &self.secret)
    }
}

/// The outcome of one relay processing one packet.
pub enum Unwrapped {
    /// This is a middle hop: forward `packet` to `next_address`.
    ///
    /// The relay learns *only* the next address — never the origin or the final
    /// destination. `delay_nanos` is the mixing delay to hold the packet (0 in S0).
    Forward {
        next_address: [u8; NODE_ADDRESS_LENGTH],
        packet: SphinxPacket,
        delay_nanos: u64,
    },
    /// This is the exit hop: deliver `payload` to `dest_address`.
    Final {
        dest_address: [u8; DESTINATION_ADDRESS_LENGTH],
        payload: Vec<u8>,
    },
}

/// A null SURB identifier. S0 has no single-use reply blocks yet (those arrive with
/// the inbound rotor's rendezvous replies).
pub fn null_surb() -> SURBIdentifier {
    [0u8; IDENTIFIER_LENGTH]
}

/// Wrap `payload` into a Sphinx onion routed through `route` (in order) to
/// `dest_address`, with an explicit per-hop mixing-delay schedule.
///
/// `delays.len()` must equal `route.len()`: `delays[i]` is how long hop `i` holds
/// the packet before forwarding (the exit hop's delay is unused).
pub fn wrap_with_delays(
    payload: &[u8],
    route: &[Node],
    dest_address: [u8; DESTINATION_ADDRESS_LENGTH],
    surb_id: SURBIdentifier,
    delays: &[Delay],
) -> Result<SphinxPacket> {
    let destination = Destination::new(DestinationAddressBytes::from_bytes(dest_address), surb_id);
    Ok(SphinxPacket::new(
        payload.to_vec(),
        route,
        &destination,
        delays,
    )?)
}

/// Wrap `payload` with zero mixing delay at every hop — a FAST-lane or test packet.
pub fn wrap(
    payload: &[u8],
    route: &[Node],
    dest_address: [u8; DESTINATION_ADDRESS_LENGTH],
    surb_id: SURBIdentifier,
) -> Result<SphinxPacket> {
    let delays = vec![Delay::new_from_nanos(0); route.len()];
    wrap_with_delays(payload, route, dest_address, surb_id, &delays)
}

/// Sample `n` independent exponential per-hop mixing delays with the given mean
/// (Loopix-style Poisson mixing — the memoryless delay is what breaks the ordering
/// an observer could otherwise use). A zero mean yields zero delays.
pub fn exponential_delays(n: usize, mean: Duration) -> Vec<Delay> {
    generate_from_average_duration(n, mean)
}

/// Sample one exponential interval with the given mean, used to pace Poisson
/// cover-traffic emission.
pub fn exponential_interval(mean: Duration) -> Duration {
    generate_from_average_duration(1, mean)
        .first()
        .map(Delay::to_duration)
        .unwrap_or_default()
}

/// Process one packet with a relay secret key. Prefer [`Relay::process`]; this is
/// exposed for callers that hold the key separately.
pub fn unwrap(packet: SphinxPacket, relay_secret: &StaticSecret) -> Result<Unwrapped> {
    match packet.process(relay_secret)?.data {
        ProcessedPacketData::ForwardHop {
            next_hop_packet,
            next_hop_address,
            delay,
        } => Ok(Unwrapped::Forward {
            next_address: next_hop_address.to_bytes(),
            packet: next_hop_packet,
            delay_nanos: delay.to_nanos(),
        }),
        ProcessedPacketData::FinalHop {
            destination,
            identifier: _,
            payload,
        } => Ok(Unwrapped::Final {
            dest_address: destination.as_bytes(),
            payload: payload.recover_plaintext()?,
        }),
    }
}

/// Serialize an onion packet to its wire bytes (fixed-size header + payload).
pub fn packet_to_bytes(packet: &SphinxPacket) -> Vec<u8> {
    packet.to_bytes()
}

/// Parse an onion packet received off the wire.
pub fn packet_from_bytes(bytes: &[u8]) -> Result<SphinxPacket> {
    Ok(SphinxPacket::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cover traffic only works if it is indistinguishable from real traffic on the
    /// wire. Sphinx pads every payload to a fixed size, so a tiny cover marker and a
    /// longer real message serialize to exactly the same number of bytes.
    #[test]
    fn real_and_cover_packets_are_the_same_wire_size() {
        let relays: Vec<Relay> = (1u8..=3)
            .map(|i| Relay::new([i; NODE_ADDRESS_LENGTH]))
            .collect();
        let route: Vec<Node> = relays.iter().map(Relay::as_node).collect();
        let dest = [7u8; DESTINATION_ADDRESS_LENGTH];

        let real = wrap(b"a short but real message", &route, dest, null_surb()).unwrap();
        let cover = wrap(b"x", &route, dest, null_surb()).unwrap();

        assert_eq!(
            packet_to_bytes(&real).len(),
            packet_to_bytes(&cover).len(),
            "cover and real packets must be indistinguishable by length"
        );
    }

    /// The delay sampler returns one delay per hop, and a zero mean is safe (no
    /// division-by-zero) and yields all-zero delays.
    #[test]
    fn exponential_delays_respect_count_and_zero_mean() {
        assert_eq!(exponential_delays(3, Duration::from_millis(50)).len(), 3);
        let zeros = exponential_delays(4, Duration::ZERO);
        assert!(zeros.iter().all(|d| d.to_nanos() == 0));
    }

    /// The core S0 guarantee: a 3-hop onion delivers the exact payload, and every
    /// middle relay learns only the *next* hop's address — never both ends.
    #[test]
    fn three_hop_onion_delivers_and_reveals_only_next_hop() {
        let relays: Vec<Relay> = (1u8..=3)
            .map(|i| Relay::new([i; NODE_ADDRESS_LENGTH]))
            .collect();
        let route: Vec<Node> = relays.iter().map(Relay::as_node).collect();
        let dest = [42u8; DESTINATION_ADDRESS_LENGTH];
        let message = b"gyre S0 onion echo".to_vec();

        let mut in_flight = Some(wrap(&message, &route, dest, null_surb()).unwrap());
        for (i, relay) in relays.iter().enumerate() {
            let packet = in_flight.take().expect("a packet is in flight");
            match relay.process(packet).unwrap() {
                Unwrapped::Forward {
                    next_address,
                    packet,
                    delay_nanos,
                } => {
                    assert!(i < 2, "only the first two hops forward");
                    assert_eq!(
                        next_address,
                        relays[i + 1].address(),
                        "a relay must learn only the NEXT hop"
                    );
                    assert_eq!(delay_nanos, 0, "S0 uses zero mixing delay");
                    in_flight = Some(packet);
                }
                Unwrapped::Final {
                    dest_address,
                    payload,
                } => {
                    assert_eq!(i, 2, "the third hop is the exit");
                    assert_eq!(dest_address, dest, "exit sees the true destination");
                    assert_eq!(payload, message, "exit recovers the exact plaintext");
                }
            }
        }
    }

    /// A relay that is not on the route cannot process the packet — the layered
    /// encryption is bound to each hop's key.
    #[test]
    fn processing_with_the_wrong_key_fails() {
        let relay = Relay::new([1u8; NODE_ADDRESS_LENGTH]);
        let route = vec![relay.as_node()];
        let packet = wrap(
            b"secret",
            &route,
            [7u8; DESTINATION_ADDRESS_LENGTH],
            null_surb(),
        )
        .unwrap();

        let stranger = Relay::new([2u8; NODE_ADDRESS_LENGTH]);
        assert!(
            stranger.process(packet).is_err(),
            "a relay not on the route must fail to process"
        );
    }

    /// A single-hop route means the first (and only) hop is the exit.
    #[test]
    fn single_hop_delivers_immediately() {
        let relay = Relay::new([5u8; NODE_ADDRESS_LENGTH]);
        let route = vec![relay.as_node()];
        let dest = [8u8; DESTINATION_ADDRESS_LENGTH];
        let message = b"one hop".to_vec();
        let packet = wrap(&message, &route, dest, null_surb()).unwrap();

        match relay.process(packet).unwrap() {
            Unwrapped::Final {
                dest_address,
                payload,
            } => {
                assert_eq!(dest_address, dest);
                assert_eq!(payload, message);
            }
            Unwrapped::Forward { .. } => panic!("a single-hop route must deliver, not forward"),
        }
    }
}
