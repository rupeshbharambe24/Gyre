//! Fuzz the capability-token issuer. It decompresses a client-supplied ristretto point,
//! so arbitrary bytes must be rejected cleanly.
#![no_main]
use libfuzzer_sys::fuzz_target;

use gyre_shield::token::Issuer;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut blinded = [0u8; 32];
        blinded.copy_from_slice(&data[..32]);
        let issuer = Issuer::new();
        let _ = issuer.issue(blinded);
    }
});
