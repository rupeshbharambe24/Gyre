//! Shared setup for the standalone `gyre-relay` and `gyre-client` binaries.
//!
//! Everything before this point ran inside one process. These binaries are the first that
//! bind real sockets and talk to *other processes*, which is what a network simulator
//! (Shadow) and any real deployment both require.
//!
//! # Testnet key derivation — read this before deploying anything
//!
//! Relay keys here are derived from the relay's public label with a fixed, published
//! salt, so every process agrees on every key with no distribution step. That makes a
//! testnet trivial to launch and reproduce.
//!
//! **It also means every key is public.** Anyone who knows a label can compute that
//! relay's secret key and decrypt its layer. This is acceptable — and only acceptable —
//! for simulation and local testing, where there is nothing to protect. A real deployment
//! must generate secrets from the OS CSPRNG and publish only the *public* halves through
//! the threshold-signed consensus (`gyre-directory::NetworkParams`).

use std::net::SocketAddr;

use gyre_sphinx::{Relay, ADDRESS_LEN};
use sha2::{Digest, Sha256};

/// Salt for testnet key derivation. Published on purpose: these keys are not secret.
const TESTNET_SALT: &[u8] = b"gyre-testnet-relay-key/INSECURE-SIMULATION-ONLY";

/// Turn a short human label ("r1") into the fixed-width Sphinx address.
pub fn label_to_address(label: &str) -> [u8; ADDRESS_LEN] {
    let mut addr = [0u8; ADDRESS_LEN];
    let digest = Sha256::digest(label.as_bytes());
    addr.copy_from_slice(&digest[..ADDRESS_LEN.min(32)]);
    addr
}

/// Derive a relay's testnet keypair from its label. **Insecure by design** — see the
/// module docs.
pub fn testnet_relay(label: &str) -> Relay {
    let mut hasher = Sha256::new();
    hasher.update(TESTNET_SALT);
    hasher.update(label.as_bytes());
    let secret: [u8; 32] = hasher.finalize().into();
    Relay::from_secret_bytes(label_to_address(label), secret)
}

/// One `label=host:port` entry from the command line.
#[derive(Clone, Debug)]
pub struct PeerArg {
    pub label: String,
    pub addr: SocketAddr,
}

/// Parse repeated `--relay label=host:port` arguments.
pub fn parse_relays(args: &[String]) -> Result<Vec<PeerArg>, String> {
    let mut peers = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg != "--relay" {
            continue;
        }
        let spec = it.next().ok_or("--relay needs label=host:port")?;
        let (label, addr) = spec
            .split_once('=')
            .ok_or_else(|| format!("malformed --relay {spec:?}, expected label=host:port"))?;
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| format!("bad address in --relay {spec:?}: {e}"))?;
        peers.push(PeerArg {
            label: label.to_string(),
            addr,
        });
    }
    Ok(peers)
}

/// Read a `--flag value` argument.
pub fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

/// Read and parse a typed `--flag value`, or fall back to `default` when the flag is absent.
///
/// A flag that is *present but unparseable* is a configuration error, not a silent fallback —
/// a daemon started with `--capacity abc` should refuse to run, not quietly serve at the
/// default and leave the operator wondering.
pub fn flag_or<T>(args: &[String], name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match flag(args, name) {
        None => Ok(default),
        Some(value) => value.parse().map_err(|e| format!("{name} {value:?}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_keys_are_reproducible_across_processes() {
        // The whole point: two independently started processes derive the same key.
        assert_eq!(
            testnet_relay("r1").public_key().as_bytes(),
            testnet_relay("r1").public_key().as_bytes()
        );
        assert_ne!(
            testnet_relay("r1").public_key().as_bytes(),
            testnet_relay("r2").public_key().as_bytes()
        );
    }

    #[test]
    fn labels_map_to_distinct_addresses() {
        assert_ne!(label_to_address("r1"), label_to_address("r2"));
        assert_eq!(label_to_address("r1"), label_to_address("r1"));
    }

    #[test]
    fn relay_args_parse() {
        let args: Vec<String> = [
            "--relay",
            "r1=127.0.0.1:9001",
            "--relay",
            "r2=127.0.0.1:9002",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let peers = parse_relays(&args).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].label, "r1");
        assert_eq!(peers[1].addr.port(), 9002);
    }

    #[test]
    fn a_malformed_relay_arg_is_an_error_not_a_panic() {
        let args = vec!["--relay".to_string(), "no-equals-sign".to_string()];
        assert!(parse_relays(&args).is_err());
    }

    #[test]
    fn flag_or_parses_uses_default_and_rejects_garbage() {
        let args: Vec<String> = ["--capacity", "512"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // present and valid
        assert_eq!(flag_or::<usize>(&args, "--capacity", 1024).unwrap(), 512);
        // absent -> default
        assert_eq!(flag_or::<usize>(&args, "--missing", 1024).unwrap(), 1024);
        // present but garbage -> error, not a silent default
        let bad: Vec<String> = ["--capacity", "abc"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(flag_or::<usize>(&bad, "--capacity", 1024).is_err());
    }
}
