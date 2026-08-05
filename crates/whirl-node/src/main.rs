//! **S0 demo.** Builds a small in-process circuit of relays, wraps a message into a
//! Sphinx onion at the "client", and echoes it hop-by-hop to the exit — printing
//! what each hop is (and, importantly, is *not*) allowed to see.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p whirl-node
//! ```
//!
//! This is a demonstration harness, not the real node service (that arrives with
//! the QUIC transport in a later milestone).

use whirl_common::{FlowClass, DEFAULT_HOPS};
use whirl_sphinx::{null_surb, wrap, Relay, Unwrapped, ADDRESS_LEN, DEST_ADDRESS_LEN};

fn main() {
    println!(
        "Whirlpool · S0 — Sphinx onion echo  ({} hops, lane={})",
        DEFAULT_HOPS,
        FlowClass::Fast
    );
    println!("{}", "-".repeat(64));

    // A tiny in-process circuit of DEFAULT_HOPS relays, address-labelled 1..=N so
    // the "learns only the next hop" property is visible in the output.
    let relays: Vec<Relay> = (1..=DEFAULT_HOPS as u8)
        .map(|i| Relay::new([i; ADDRESS_LEN]))
        .collect();
    let route: Vec<_> = relays.iter().map(Relay::as_node).collect();

    let dest = [42u8; DEST_ADDRESS_LEN];
    let message = b"hello from the client, through the whirlpool";

    println!(
        "client  wrapping {} bytes for a {}-hop route -> exit delivers to dest #{}",
        message.len(),
        route.len(),
        dest[0]
    );

    let mut in_flight = Some(wrap(message, &route, dest, null_surb()).expect("wrap onion"));
    for (i, relay) in relays.iter().enumerate() {
        let packet = in_flight.take().expect("a packet is in flight");
        match relay.process(packet).expect("process onion") {
            Unwrapped::Forward {
                next_address,
                packet,
                delay_nanos,
            } => {
                println!(
                    "  hop {}  relay #{:<2}  forward -> #{:<2}   (delay {}ns; learns nothing else)",
                    i + 1,
                    relay.address()[0],
                    next_address[0],
                    delay_nanos
                );
                in_flight = Some(packet);
            }
            Unwrapped::Final {
                dest_address,
                payload,
            } => {
                println!(
                    "  hop {}  relay #{:<2}  EXIT    -> deliver to dest #{}",
                    i + 1,
                    relay.address()[0],
                    dest_address[0]
                );
                assert_eq!(payload, message, "payload survived the onion intact");
                println!("delivered: {:?}", String::from_utf8_lossy(&payload));
            }
        }
    }

    println!("{}", "-".repeat(64));
    println!("OK  no hop saw both ends; the exit recovered the exact payload.");
}
