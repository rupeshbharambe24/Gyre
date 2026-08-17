//! Private directory retrieval over real sockets: two independent PIR servers, a client that
//! fetches a record without either server learning which. This proves the Access-pattern
//! mechanism is *wired*, not just a library.

use std::sync::Arc;

use gyre_cli::{demo_record, pir_lookup, serve_pir};
use tokio::net::TcpListener;

async fn start_server(records: usize) -> std::net::SocketAddr {
    let dir = Arc::new(gyre_pir::Directory::new(
        (0..records).map(demo_record).collect(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_pir(listener, dir));
    addr
}

#[tokio::test]
async fn a_pir_lookup_recovers_the_target_record_from_two_servers() {
    let records = 64;
    // Two *independent* server processes (here, tasks) holding identical replicated records.
    let a = start_server(records).await;
    let b = start_server(records).await;

    for target in [0usize, 7, 31, 63] {
        let got = pir_lookup(a, b, records, target).await.unwrap();
        assert_eq!(
            got,
            demo_record(target),
            "PIR must recover exactly record {target}"
        );
    }
}

#[tokio::test]
async fn neither_server_sees_a_point_query() {
    // The privacy claim, made concrete: the two masks differ in exactly one position (the
    // target), and each mask on its own is not a single-bit "I want record i" query — so a
    // single server cannot read the target off the mask it receives.
    let n = 64;
    let target = 19;
    let (qa, qb) = gyre_pir::build_queries(n, target);

    let differ: Vec<usize> = (0..n).filter(|&i| qa[i] != qb[i]).collect();
    assert_eq!(
        differ,
        vec![target],
        "the two masks must differ in exactly the target position"
    );

    // Each mask, alone, selects many records (≈ half), so it is not a point query that would
    // reveal the target to the server receiving it.
    let ones_a = qa.iter().filter(|&&b| b).count();
    assert!(
        ones_a > 1 && ones_a < n - 1,
        "a single mask must not be a 1-bit point query; it selected {ones_a} of {n}"
    );
}
