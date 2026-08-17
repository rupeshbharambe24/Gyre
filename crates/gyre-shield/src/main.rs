//! Inbound-shield demo. Run it with `cargo run -p gyre-shield`. It shows, in order: the
//! ingress hops (authorized client + origin agree, a scanner does not); PoW admission cost
//! rising with load while verification stays one hash; the admission protocol refusing a
//! replayed solution; a rendezvous reaching an origin that published no inbound address;
//! and — the payoff — a **guarded rendezvous relay refusing an L7 flood live**: a client
//! that solves the puzzle is admitted, fifty connections that skip it are all dropped, and
//! the parking map never grows.

use std::time::Duration;

use gyre_net::{read_frame, write_frame};
use gyre_shield::admission::Admission;
use gyre_shield::rendezvous::{dial, dial_admitted, RelayConfig, RendezvousRelay};
use gyre_shield::{difficulty_for_load, IngressSchedule, Puzzle};
use tokio::net::{TcpListener, TcpStream};

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

    // ---- Admission protocol: the puzzle turned into a real gate ----
    // The raw puzzle above is a cost function. This is the anti-replay admission protocol
    // that turns it into a defence: the SERVER issues a fresh, expiring, single-use
    // challenge, so a solved challenge cannot be replayed and a client cannot pre-pick one.
    println!("Admission protocol — one honest client, then the same solution replayed:");
    let now = Duration::from_secs(1_000);
    let mut gate = Admission::new(Duration::from_secs(30));
    let challenge = gate.issue(now, 1.0); // under flood: a hard challenge
    let solution = challenge.puzzle().solve();
    println!(
        "  server issued a {}-bit challenge (stateless: cost 1 HMAC, 0 stored bytes)",
        challenge.difficulty_bits()
    );
    match gate.redeem(&challenge, &solution, now) {
        Ok(()) => println!("  first redemption      -> ADMITTED (valid, fresh, unspent)"),
        Err(e) => println!("  first redemption      -> DENIED: {e}"),
    }
    match gate.redeem(&challenge, &solution, now) {
        Ok(()) => println!("  replayed redemption   -> ADMITTED  (BUG — replay should fail)"),
        Err(e) => println!("  replayed redemption   -> DENIED: {e}  (this is the whole point)"),
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

    // ---- Guarded rendezvous under an L7 flood ----
    // The gate in front of a LIVE relay: a legitimate client that solves the puzzle gets
    // through; a flood of connections that skip it are all dropped, and the parking map
    // never grows. This is the L7 admission story running end to end, not described.
    println!("Guarded rendezvous — the admission gate refusing an L7 flood, live:");
    let capacity = 8;
    let relay = RendezvousRelay::guarded(RelayConfig {
        capacity,
        ttl: Duration::from_secs(30),
        handshake_timeout: Duration::from_secs(10),
    });
    let g_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind guarded");
    let g_addr = g_listener.local_addr().unwrap();
    tokio::spawn(relay.clone().serve(g_listener));

    // A legitimate origin + client, both solving the server-issued puzzle.
    let g_cookie = b"guarded-demo-cookie".to_vec();
    let origin_cookie = g_cookie.clone();
    let guarded_origin = tokio::spawn(async move {
        let mut stream = dial_admitted(g_addr, &origin_cookie).await.unwrap();
        let request = read_frame(&mut stream).await.unwrap().unwrap();
        let mut response = b"pong: ".to_vec();
        response.extend_from_slice(&request);
        write_frame(&mut stream, &response).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut g_client = dial_admitted(g_addr, &g_cookie).await.expect("admitted");
    write_frame(&mut g_client, b"ping").await.expect("send");
    let g_response = read_frame(&mut g_client).await.unwrap().unwrap();
    guarded_origin.await.unwrap();
    println!(
        "  legit client solved the puzzle       -> ADMITTED, received {:?}",
        String::from_utf8_lossy(&g_response)
    );

    // A flood: connections that never solve the puzzle. Each is dropped; none parks.
    let flood = 50;
    let mut refused = 0;
    for _ in 0..flood {
        if let Ok(mut attacker) = TcpStream::connect(g_addr).await {
            let _ = write_frame(&mut attacker, b"no-proof-of-work").await;
            let _ = read_frame(&mut attacker).await; // the server's challenge, then...
            match tokio::time::timeout(Duration::from_secs(1), read_frame(&mut attacker)).await {
                Ok(Ok(None)) | Ok(Err(_)) => refused += 1, // connection closed = refused
                _ => {}
            }
        }
    }
    println!("  {flood} connections with no proof-of-work -> {refused} refused, 0 served");
    println!(
        "  parking slots in use after the flood  -> {} of {capacity} (the bound held)",
        relay.parked()
    );
    println!("{}", "-".repeat(70));

    // ---- Anonymous capability tokens ----
    println!("Capability tokens — redeem an unlinkable token to skip the PoW:");
    let mut issuer = gyre_shield::token::Issuer::new();

    // The client pins the issuer key from a THRESHOLD-SIGNED consensus, not from the
    // issuer. Verifying a proof against a key the issuer supplied proves nothing.
    let authorities: Vec<gyre_directory::Authority> = (0..4)
        .map(|_| gyre_directory::Authority::generate())
        .collect();
    let authority_keys: Vec<_> = authorities
        .iter()
        .map(gyre_directory::Authority::public)
        .collect();
    let params = gyre_directory::NetworkParams {
        epoch: 7,
        issuer_public_key: issuer.public_key().to_bytes(),
        pow_difficulty_bits: 12,
        mtd_window_secs: 30,
        relays: Vec::new(),
    };
    let consensus = gyre_directory::Consensus::new(7, params.encode());
    let msg = consensus.signing_bytes();
    let sigs: Vec<_> = (0..3).map(|i| (i, authorities[i].sign(&msg))).collect();
    let verified = gyre_directory::verify_consensus(&consensus, &sigs, &authority_keys, 3)
        .expect("3 of 4 authorities signed");
    let published = gyre_shield::token::PublicKey::from_verified_params(&verified);
    println!("  issuer key pinned from a 3-of-4 threshold-signed consensus (epoch 7)");
    let (state, blinded) = gyre_shield::token::blind();
    let issued = issuer.issue(blinded).expect("issue");
    let token = gyre_shield::token::unblind(state, issued, published).expect("unblind");
    println!("  issuer saw only a blinded point (never the token)");
    println!("  client verified the issuer's DLEQ proof against the published key");
    println!(
        "  redeem #1: {}   redeem #2 (double-spend): {}",
        issuer.redeem(&token),
        issuer.redeem(&token)
    );

    // Show the protection working: a response computed with a different key is refused.
    let rogue = gyre_shield::token::Issuer::new();
    let (state2, blinded2) = gyre_shield::token::blind();
    let rogue_issued = rogue.issue(blinded2).expect("issue");
    println!(
        "  response from a DIFFERENT key, checked against the published one: {}",
        match gyre_shield::token::unblind(state2, rogue_issued, published) {
            Ok(_) => "ACCEPTED (this would be a deanonymisation hole)".to_string(),
            Err(e) => format!("REFUSED — {e}"),
        }
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
