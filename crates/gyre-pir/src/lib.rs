//! **Addition 6 — private directory retrieval (surgical).**
//!
//! **The default is PIR OFF.** Every client downloads the whole signed consensus — since
//! all clients fetch the *identical* object, there is nothing to correlate, there is no
//! non-collusion assumption, and at Tor scale it is cheaper than any PIR scheme. Use
//! [`Directory::download_all`].
//!
//! This crate provides the surgical alternative for the one lookup whose *target* actually
//! leaks — the inbound **rendezvous descriptor**, where fetching record `i` reveals which
//! protected system a client is contacting. It is a classic **2-server information-
//! theoretic PIR** (the XOR scheme): the directory is replicated on two servers, the client
//! sends each a random query mask, and recovers record `i` without either server learning
//! `i`.
//!
//! **Honest ceiling.** The privacy is information-theoretic **only if the two servers do
//! not collude** — and Sybil infrastructure is squarely in our threat model, which is
//! exactly an attack on that assumption. If the servers collude, they XOR the two query
//! masks and immediately learn `i`. So this is *surgical*: reserve it for the sensitive
//! rendezvous lookup and keep the public relay list on full download. It also does not hide
//! *that* a lookup happened, only *which* record (a global observer, constraint 2).

/// A directory replicated across the two PIR servers: `n` equal-length records.
pub struct Directory {
    records: Vec<Vec<u8>>,
    record_len: usize,
}

impl Directory {
    /// Build a directory from equal-length `records`.
    pub fn new(records: Vec<Vec<u8>>) -> Self {
        let record_len = records.first().map(Vec::len).unwrap_or(0);
        Self {
            records,
            record_len,
        }
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the directory is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The **default** retrieval: download everything. Leak-free (all clients fetch the
    /// same object) and needs no non-collusion assumption.
    pub fn download_all(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// A server's PIR answer: the XOR of every record whose query bit is set.
    pub fn answer(&self, query: &[bool]) -> Vec<u8> {
        let mut acc = vec![0u8; self.record_len];
        for (record, &selected) in self.records.iter().zip(query) {
            if selected {
                for (a, b) in acc.iter_mut().zip(record) {
                    *a ^= b;
                }
            }
        }
        acc
    }
}

fn random_bit() -> bool {
    let mut byte = [0u8; 1];
    getrandom::fill(&mut byte).expect("OS RNG");
    byte[0] & 1 == 1
}

/// Build the two query masks a client sends to the two servers to privately fetch
/// `target` from an `n`-record directory. Each mask on its own is uniformly random, so a
/// single server learns nothing about `target`.
pub fn build_queries(n: usize, target: usize) -> (Vec<bool>, Vec<bool>) {
    let query_a: Vec<bool> = (0..n).map(|_| random_bit()).collect();
    let mut query_b = query_a.clone();
    if target < n {
        query_b[target] ^= true;
    }
    (query_a, query_b)
}

/// Recover the requested record by XORing the two servers' answers.
pub fn recover(answer_a: &[u8], answer_b: &[u8]) -> Vec<u8> {
    answer_a.iter().zip(answer_b).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> Directory {
        Directory::new(
            (0u8..8)
                .map(|i| format!("rendezvous-descriptor-{i}").into_bytes())
                .map(|mut r| {
                    r.resize(32, 0);
                    r
                })
                .collect(),
        )
    }

    #[test]
    fn two_server_pir_recovers_every_record() {
        let dir = directory();
        for target in 0..dir.len() {
            let (qa, qb) = build_queries(dir.len(), target);
            let recovered = recover(&dir.answer(&qa), &dir.answer(&qb));
            assert_eq!(recovered, dir.download_all()[target], "record {target}");
        }
    }

    #[test]
    fn a_single_query_hides_the_target_but_collusion_reveals_it() {
        let n = 8;
        let target = 5;
        let (qa, qb) = build_queries(n, target);
        // The two masks differ in exactly one position — the target. So either server
        // alone sees a random mask, but colluding servers XOR them and learn the target.
        let differing: Vec<usize> = (0..n).filter(|&i| qa[i] != qb[i]).collect();
        assert_eq!(
            differing,
            vec![target],
            "collusion (qa XOR qb) reveals the target"
        );
    }

    #[test]
    fn download_all_returns_the_whole_directory() {
        let dir = directory();
        assert_eq!(dir.download_all().len(), 8);
    }
}
