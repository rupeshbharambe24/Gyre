//! Fuzz LSB extraction. The 32-bit length header is read straight out of
//! attacker-controlled bits, so it must never panic or allocate beyond the carrier.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(secret) = gyre_stego::extract(data) {
        assert!(
            secret.len() <= data.len(),
            "extracted more than the carrier could hold"
        );
    }
});
