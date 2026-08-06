//! Fuzz the Sphinx wire parser. A relay calls this on bytes straight off a hostile
//! network, so it must reject anything malformed without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gyre_sphinx::packet_from_bytes(data);
});
