//! **`gyre-lookup`** — privately fetch a directory record via 2-server IT-PIR.
//!
//! Fetches record `--target i` from an `--records N` directory replicated on two `gyre-dir`
//! servers, **without either server learning `i`**. Prints the recovered record and verifies
//! it against the known demo record for `i`.
//!
//! ```text
//! gyre-lookup --dir-a 127.0.0.1:9701 --dir-b 127.0.0.1:9702 --records 64 --target 7
//! ```
//!
//! Honest ceiling: information-theoretic privacy **only if the two servers do not collude**,
//! and off by default (a full signed-consensus download already leaks nothing and is cheaper).

use std::net::SocketAddr;
use std::process::ExitCode;

use gyre_cli::{demo_record, flag, flag_or, pir_lookup};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let (Some(a), Some(b)) = (flag(&args, "--dir-a"), flag(&args, "--dir-b")) else {
        eprintln!("gyre-lookup: --dir-a and --dir-b host:port are required");
        return ExitCode::FAILURE;
    };
    let (Ok(dir_a), Ok(dir_b)): (Result<SocketAddr, _>, Result<SocketAddr, _>) =
        (a.parse(), b.parse())
    else {
        eprintln!("gyre-lookup: bad --dir-a / --dir-b address");
        return ExitCode::FAILURE;
    };
    let records = match flag_or::<usize>(&args, "--records", 64) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("gyre-lookup: {e}");
            return ExitCode::FAILURE;
        }
    };
    let target = match flag_or::<usize>(&args, "--target", 0) {
        Ok(t) if t < records => t,
        Ok(t) => {
            eprintln!("gyre-lookup: --target {t} is out of range (records = {records})");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("gyre-lookup: {e}");
            return ExitCode::FAILURE;
        }
    };

    let record = match pir_lookup(dir_a, dir_b, records, target).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gyre-lookup: {e}");
            return ExitCode::FAILURE;
        }
    };

    let hex: String = record.iter().take(8).map(|b| format!("{b:02x}")).collect();
    if record == demo_record(target) {
        println!(
            "gyre-lookup: privately fetched record {target} of {records} -> {hex}… (verified)"
        );
        println!("  neither server learned the index: each received only a uniformly random mask");
        ExitCode::SUCCESS
    } else {
        eprintln!("gyre-lookup: recovered record does not match the expected demo record");
        ExitCode::FAILURE
    }
}
