//! Property-based tests for the wire framing (S1).
//!
//! Relays read frames straight off a hostile network, so two things must hold for any
//! input: a frame written by us always reads back byte-identical, and an attacker-chosen
//! length prefix can never make us allocate more than `MAX_FRAME` — a 4-byte header must
//! not be able to demand gigabytes.

use gyre_net::{read_frame, write_frame, Error, MAX_FRAME};
use proptest::prelude::*;

/// A fresh current-thread runtime per case; creation is cheap and it keeps each property
/// deterministic and independent.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(fut)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any payload survives the length-prefixed framing exactly.
    #[test]
    fn frames_round_trip(payload in prop::collection::vec(any::<u8>(), 0..4000)) {
        block_on(async {
            let mut wire: Vec<u8> = Vec::new();
            write_frame(&mut wire, &payload).await.unwrap();
            prop_assert_eq!(wire.len(), 4 + payload.len(), "u32 length prefix + body");

            let mut reader = wire.as_slice();
            let got = read_frame(&mut reader).await.unwrap();
            prop_assert_eq!(got.as_deref(), Some(payload.as_slice()));
            Ok(())
        })?;
    }

    /// **The DoS guard.** Any length prefix above `MAX_FRAME` is rejected *before* the
    /// buffer is allocated, so a 4-byte header can never trigger a huge allocation.
    #[test]
    fn oversized_length_prefixes_are_rejected_before_allocating(
        len in (MAX_FRAME as u32 + 1)..=u32::MAX,
    ) {
        block_on(async {
            let header = len.to_be_bytes();
            let mut reader = &header[..];
            let result = read_frame(&mut reader).await;
            prop_assert!(
                matches!(result, Err(Error::FrameTooLarge(n)) if n == len as usize),
                "an oversized frame must be refused"
            );
            Ok(())
        })?;
    }

    /// Robustness: arbitrary or truncated stream bytes must never panic the reader — it
    /// returns a frame, a clean end-of-stream, or an error.
    #[test]
    fn arbitrary_stream_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        block_on(async {
            let mut reader = bytes.as_slice();
            let _ = read_frame(&mut reader).await;
        });
    }

    /// An empty stream is a clean end-of-stream, not an error — that is how a relay
    /// distinguishes "peer hung up" from "peer sent garbage".
    #[test]
    fn an_empty_stream_is_a_clean_end_of_stream(_run in 0u8..4) {
        block_on(async {
            let mut reader: &[u8] = &[];
            prop_assert!(matches!(read_frame(&mut reader).await, Ok(None)));
            Ok(())
        })?;
    }
}
