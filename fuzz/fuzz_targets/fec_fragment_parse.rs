//! Fuzz the erasure-coding fragment parser and the reassembler. Fragments arrive as
//! attacker-influenced Sphinx payloads: mismatched shapes and out-of-range indices must
//! be rejected, never trusted.
#![no_main]
use libfuzzer_sys::fuzz_target;

use gyre_fec::{Fragment, Reassembler};

fuzz_target!(|data: &[u8]| {
    if let Ok(frag) = Fragment::from_bytes(data) {
        // Re-serializing a parsed fragment must never panic either.
        let _ = frag.to_bytes();
        let mut reasm = Reassembler::new();
        let _ = reasm.insert(frag);
    }
});
