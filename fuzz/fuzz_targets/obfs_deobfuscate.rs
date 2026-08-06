//! Fuzz every pluggable transport's de-obfuscation path. A censor can feed a bridge
//! anything at all; each transport must error rather than panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

use gyre_obfs::default_transports;

fuzz_target!(|data: &[u8]| {
    for transport in default_transports([0x5A; 32]) {
        let _ = transport.deobfuscate(data);
    }
});
