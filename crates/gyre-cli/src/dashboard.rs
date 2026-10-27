//! A tiny, **dependency-free** status dashboard for a guarded rendezvous relay.
//!
//! It serves two things over plain HTTP/1.1 (hand-rolled on the tokio runtime already in the
//! tree — no web framework, no new crates):
//!
//! - `GET /`            → a self-contained live page (polls the JSON below every second)
//! - `GET /stats.json`  → a snapshot of [`RendezvousRelay::stats`]
//!
//! It is **observability only**: it reads the relay's atomic counters and never touches
//! admission. Bind it to loopback (`127.0.0.1`) unless you deliberately want it reachable.

use std::net::SocketAddr;

use gyre_shield::rendezvous::RendezvousRelay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The live page, embedded at compile time.
const PAGE: &str = include_str!("dashboard.html");

/// Serve the dashboard forever on `addr`, reading live stats from `relay`.
///
/// `algo_name` is the human label for the admission puzzle (e.g. `"SHA-256"`), which the relay
/// stats do not carry — the daemon knows it from its own `--pow` flag and passes it through.
pub async fn serve_dashboard(
    relay: RendezvousRelay,
    addr: SocketAddr,
    algo_name: String,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut sock, _peer) = listener.accept().await?;
        let relay = relay.clone();
        let algo = algo_name.clone();
        tokio::spawn(async move {
            // One small read is enough to see the request line; we only route on the path.
            let mut buf = [0u8; 2048];
            let n = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");

            let (status, ctype, body) = if path.starts_with("/stats.json") {
                ("200 OK", "application/json", stats_json(&relay, &algo))
            } else if path == "/" || path.starts_with("/index.html") || path.starts_with("/?") {
                ("200 OK", "text/html; charset=utf-8", PAGE.to_string())
            } else {
                (
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    "not found".to_string(),
                )
            };

            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
                 Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

/// Render a relay stats snapshot as a compact JSON object. Hand-rolled (the numbers are all
/// integers, a bounded float, a bool, and a short, already-safe algorithm label), so no JSON
/// dependency is pulled in.
fn stats_json(relay: &RendezvousRelay, algo_name: &str) -> String {
    let s = relay.stats();
    format!(
        "{{\"guarded\":{},\"algorithm\":\"{}\",\"capacity\":{},\"max_inflight\":{},\
         \"parked\":{},\"admitted\":{},\"refused\":{},\"effort_load\":{:.4},\"uptime_secs\":{}}}",
        s.guarded,
        algo_name.replace('"', "'"),
        s.capacity,
        s.max_inflight,
        s.parked,
        s.admitted,
        s.refused,
        s.effort_load,
        s.uptime_secs,
    )
}
