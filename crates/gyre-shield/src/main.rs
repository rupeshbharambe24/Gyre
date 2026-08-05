//! Inbound-shield demo: the ingress hops (authorized client + origin agree, a scanner
//! does not), PoW admission cost rises with load while verification stays one hash, and
//! a rendezvous lets the origin be reached without publishing any inbound address. Run
//! it with `cargo run -p gyre-shield`.

use std::time::Duration;

use gyre_net::{read_frame, write_frame};
use gyre_shield::rendezvous::{dial, RendezvousRelay};
use gyre_shield::{difficulty_for_load, IngressSchedule, Puzzle};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    println!("Gyre · Inbound Shield — MTD hopping + PoW admission + rendezvous");
    println!("{}", "-".repeat(70));

    // ---- Moving-target-defense ingress hopping ----
    let candidates: Vec<[u8; 32]> = (1..=8).map(|i| [i; 32]).collect();
    let window = Duration::from_secs(30);
    let key = b"origin<->client shared key";
    let origin = IngressSchedule::new(key, window, candidates.clone());
    let client = IngressSchedule::new(key, window, candidates.clone());
    let scanner = IngressSchedule::new(b"scanner's wrong guess", window, candidates);

    println!("MTD ingress hopping — origin & authorized client agree; a scanner cannot:");
    println!("  window   ingress (origin=client)   scanner target   result");
    let mut scanner_hits = 0;
    for counter in 0..6u64 {
        let real = origin.ingress_at(counter)[0];
        let client_view = client.ingress_at(counter)[0];
        let scan = scanner.ingress_at(counter)[0];
        let hit = scan == real;
        scanner_hits += u32::from(hit);
        println!(
            "   {counter:>4}           #{real:<2} (client #{client_view:<2})          #{scan:<2}           {}",
            if hit { "HIT" } else { "miss" }
        );
    }
    println!("  scanner located the ingress in {scanner_hits}/6 windows (blind chance ~1/8)");
    println!("{}", "-".repeat(70));

    // ---- Proof-of-work admission ----
    println!("PoW admission — difficulty scales with load; the server verifies in 1 hash:");
    for (label, load) in [("idle ", 0.0f64), ("busy ", 0.5), ("flood", 1.0)] {
        let bits = difficulty_for_load(load);
        let solution = Puzzle::new([0x42; 32], bits).solve();
        println!(
            "  load={label} ({load:.1})  ->  difficulty {bits:>2} bits  ->  client solved in {:>8} hashes",
            solution.attempts
        );
    }
    println!("{}", "-".repeat(70));

    // ---- Rendezvous origin-hiding ----
    println!("Rendezvous — the origin dials OUT; a client reaches it via a meeting point:");
    let rp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind rp");
    let rp_addr = rp_listener.local_addr().unwrap();
    tokio::spawn(RendezvousRelay::new().serve(rp_listener));

    let cookie = b"demo-rendezvous-cookie".to_vec();
    let origin_cookie = cookie.clone();
    let origin_task = tokio::spawn(async move {
        let mut stream = dial(rp_addr, &origin_cookie).await.unwrap();
        let request = read_frame(&mut stream).await.unwrap().unwrap();
        let mut response = b"pong: ".to_vec();
        response.extend_from_slice(&request);
        write_frame(&mut stream, &response).await.unwrap();
    });

    let mut client_stream = dial(rp_addr, &cookie).await.expect("client dial");
    write_frame(&mut client_stream, b"ping")
        .await
        .expect("send");
    let response = read_frame(&mut client_stream).await.unwrap().unwrap();
    origin_task.await.unwrap();

    println!(
        "  origin published NO inbound address; met the client at rendezvous :{}",
        rp_addr.port()
    );
    println!(
        "  client sent \"ping\" and received {:?} (the relay copied opaque bytes only)",
        String::from_utf8_lossy(&response)
    );
    println!("{}", "-".repeat(70));

    // ---- Anonymous capability tokens ----
    println!("Capability tokens — redeem an unlinkable token to skip the PoW:");
    let mut issuer = gyre_shield::token::Issuer::new();
    let (state, blinded) = gyre_shield::token::blind();
    let issued = issuer.issue(blinded).expect("issue");
    let token = gyre_shield::token::unblind(state, issued).expect("unblind");
    println!("  issuer saw only a blinded point (never the token)");
    println!(
        "  redeem #1: {}   redeem #2 (double-spend): {}",
        issuer.redeem(&token),
        issuer.redeem(&token)
    );
    println!("{}", "-".repeat(70));
    println!(
        "Honest ceiling (D22): MTD + rendezvous serve an authorized/closed client set, not the"
    );
    println!(
        "open web; PoW re-prices asymmetry but does nothing for L3/L4 floods. A trust-topology"
    );
    println!("win for authenticated tunnels, not raw scrubbing capacity.");
}
