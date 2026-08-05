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
//! What is *not* here yet (later milestones): per-hop Poisson mixing delay (S2),
//! erasure-coded multipath (S3), the FAST/MIX lanes (S4), and the real transport.

use sphinx_packet::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH,
};
use sphinx_packet::header::delays::Delay;
use sphinx_packet::packet::ProcessedPacketData;
use sphinx_packet::route::{
    Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier,
};
use sphinx_packet::SphinxPacket;
use x25519_dalek::{PublicKey, StaticSecret};

/// Length, in bytes, of a relay address label in the Sphinx format we use.
pub const ADDRESS_LEN: usize = NODE_ADDRESS_LENGTH;
/// Length, in bytes, of a destination address in the Sphinx format we use.
pub const DEST_ADDRESS_LEN: usize = DESTINATION_ADDRESS_LENGTH;

/// Errors from building or processing a Whirlpool onion packet.
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
/// `dest_address`.
///
/// S0 uses zero mixing delay at every hop; per-hop Poisson delay is added in S2.
pub fn wrap(
    payload: &[u8],
    route: &[Node],
    dest_address: [u8; DESTINATION_ADDRESS_LENGTH],
    surb_id: SURBIdentifier,
) -> Result<SphinxPacket> {
    let destination = Destination::new(DestinationAddressBytes::from_bytes(dest_address), surb_id);
    let delays: Vec<Delay> = route.iter().map(|_| Delay::new_from_nanos(0)).collect();
    Ok(SphinxPacket::new(
        payload.to_vec(),
        route,
        &destination,
        &delays,
    )?)
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

    /// The core S0 guarantee: a 3-hop onion delivers the exact payload, and every
    /// middle relay learns only the *next* hop's address — never both ends.
    #[test]
    fn three_hop_onion_delivers_and_reveals_only_next_hop() {
        let relays: Vec<Relay> = (1u8..=3)
            .map(|i| Relay::new([i; NODE_ADDRESS_LENGTH]))
            .collect();
        let route: Vec<Node> = relays.iter().map(Relay::as_node).collect();
        let dest = [42u8; DESTINATION_ADDRESS_LENGTH];
        let message = b"whirlpool S0 onion echo".to_vec();

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
