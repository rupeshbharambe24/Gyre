//! The **typed consensus body** — the network parameters both rotors read.
//!
//! A consensus body used to be opaque bytes, which meant the one value that makes the
//! capability token safe (the issuer's public key) had nowhere authoritative to live. It
//! lives here now, inside the document the directory authorities threshold-sign.
//!
//! The encoding is deliberately boring: fixed-width, big-endian, length-prefixed, and
//! **strict**. Decoding rejects a wrong magic, an unknown version, a truncated buffer, and
//! — importantly — any *trailing* bytes, so a document has exactly one valid encoding. A
//! parser that tolerated slack would let two different byte strings mean the same thing,
//! which is precisely how signature-covered documents get confused with each other.

/// Magic prefix so a body from some other protocol can never be misread as parameters.
const MAGIC: &[u8; 4] = b"GYRE";
/// Encoding version. Bumping this is a wire-format break.
pub const PARAMS_VERSION: u16 = 1;
/// Bytes before the relay list: magic ‖ version ‖ epoch ‖ issuer key ‖ pow ‖ mtd ‖ count.
const HEADER_LEN: usize = 4 + 2 + 8 + 32 + 4 + 4 + 2;
/// Bytes per relay entry: address ‖ x25519 public key ‖ QUIC certificate fingerprint.
const RELAY_LEN: usize = 32 + 32 + 32;

/// Errors from decoding a consensus body.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParamsError {
    /// The body does not start with the expected magic.
    #[error("not a gyre parameters document")]
    BadMagic,
    /// The body announces a version this build does not understand.
    #[error("unsupported parameters version {0} (this build understands {PARAMS_VERSION})")]
    UnsupportedVersion(u16),
    /// The body is shorter than its own declared contents, or carries trailing bytes.
    #[error("malformed parameters: expected {expected} bytes, got {actual}")]
    Malformed { expected: usize, actual: usize },
}

/// One relay as published in the consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    /// The relay's routing address label.
    pub address: [u8; 32],
    /// The relay's X25519 public key, used to build onion layers for it.
    pub public_key: [u8; 32],
    /// SHA-256 fingerprint of the relay's QUIC certificate.
    ///
    /// Relays have no CA-issued certificates, so a client pins this value and refuses any
    /// other certificate. Publishing it here — inside the threshold-signed document — is
    /// what stops an attacker from simply presenting its own certificate *and* its own
    /// fingerprint, the same trap the issuer key avoids.
    pub quic_fingerprint: [u8; 32],
}

/// The network parameters carried in a consensus body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkParams {
    /// The epoch these parameters describe. Must match the enclosing [`Consensus`] —
    /// checked on verification, so a body cannot be spliced from another epoch.
    ///
    /// [`Consensus`]: crate::Consensus
    pub epoch: u64,
    /// **The capability-token issuer's public key.** This is the value clients must pin:
    /// verifying an issuer's DLEQ proof against a key the *issuer* supplied proves nothing,
    /// so it has to come from a document a quorum of authorities signed.
    pub issuer_public_key: [u8; 32],
    /// Proof-of-work admission difficulty, in leading zero bits.
    pub pow_difficulty_bits: u32,
    /// The moving-target-defense ingress window, in seconds.
    pub mtd_window_secs: u32,
    /// The relays clients may build routes through.
    pub relays: Vec<RelayDescriptor>,
}

impl NetworkParams {
    /// Serialize to the canonical byte encoding that authorities sign.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.relays.len() * RELAY_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&PARAMS_VERSION.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.issuer_public_key);
        out.extend_from_slice(&self.pow_difficulty_bits.to_be_bytes());
        out.extend_from_slice(&self.mtd_window_secs.to_be_bytes());
        // A relay count above u16::MAX is not representable; saturate rather than wrap, so
        // an over-large list encodes to something that will fail its own length check
        // instead of silently encoding a different document.
        let count = u16::try_from(self.relays.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for relay in self.relays.iter().take(count as usize) {
            out.extend_from_slice(&relay.address);
            out.extend_from_slice(&relay.public_key);
            out.extend_from_slice(&relay.quic_fingerprint);
        }
        out
    }

    /// Parse a consensus body. Strict: exact length, known magic and version, no trailing
    /// bytes — so every document has exactly one valid encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ParamsError> {
        if bytes.len() < HEADER_LEN {
            return Err(ParamsError::Malformed {
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if &bytes[0..4] != MAGIC {
            return Err(ParamsError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != PARAMS_VERSION {
            return Err(ParamsError::UnsupportedVersion(version));
        }

        let epoch = u64::from_be_bytes(bytes[6..14].try_into().expect("8 bytes"));
        let issuer_public_key: [u8; 32] = bytes[14..46].try_into().expect("32 bytes");
        let pow_difficulty_bits = u32::from_be_bytes(bytes[46..50].try_into().expect("4 bytes"));
        let mtd_window_secs = u32::from_be_bytes(bytes[50..54].try_into().expect("4 bytes"));
        let count = u16::from_be_bytes([bytes[54], bytes[55]]) as usize;

        // Exact-length check. `count` is attacker-influenced, so the multiplication is
        // done in a width that cannot overflow (u16 * 64 fits comfortably in usize).
        let expected = HEADER_LEN + count * RELAY_LEN;
        if bytes.len() != expected {
            return Err(ParamsError::Malformed {
                expected,
                actual: bytes.len(),
            });
        }

        let relays = (0..count)
            .map(|i| {
                let at = HEADER_LEN + i * RELAY_LEN;
                RelayDescriptor {
                    address: bytes[at..at + 32].try_into().expect("32 bytes"),
                    public_key: bytes[at + 32..at + 64].try_into().expect("32 bytes"),
                    quic_fingerprint: bytes[at + 64..at + 96].try_into().expect("32 bytes"),
                }
            })
            .collect();

        Ok(NetworkParams {
            epoch,
            issuer_public_key,
            pow_difficulty_bits,
            mtd_window_secs,
            relays,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NetworkParams {
        NetworkParams {
            epoch: 42,
            issuer_public_key: [7u8; 32],
            pow_difficulty_bits: 12,
            mtd_window_secs: 30,
            relays: vec![
                RelayDescriptor {
                    address: [1u8; 32],
                    public_key: [2u8; 32],
                    quic_fingerprint: [5u8; 32],
                },
                RelayDescriptor {
                    address: [3u8; 32],
                    public_key: [4u8; 32],
                    quic_fingerprint: [6u8; 32],
                },
            ],
        }
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let params = sample();
        assert_eq!(NetworkParams::decode(&params.encode()).unwrap(), params);
    }

    #[test]
    fn an_empty_relay_list_is_valid() {
        let params = NetworkParams {
            relays: Vec::new(),
            ..sample()
        };
        assert_eq!(NetworkParams::decode(&params.encode()).unwrap(), params);
    }

    /// Trailing bytes must be rejected: if two different byte strings decoded to the same
    /// document, a signature over one would appear to cover the other.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(matches!(
            NetworkParams::decode(&bytes),
            Err(ParamsError::Malformed { .. })
        ));
    }

    #[test]
    fn truncation_is_rejected() {
        let bytes = sample().encode();
        for cut in [0, 1, HEADER_LEN - 1, HEADER_LEN, bytes.len() - 1] {
            assert!(
                NetworkParams::decode(&bytes[..cut]).is_err(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn a_foreign_document_is_rejected() {
        assert_eq!(
            NetworkParams::decode(&[0u8; 80]),
            Err(ParamsError::BadMagic)
        );
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = sample().encode();
        bytes[4..6].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(
            NetworkParams::decode(&bytes),
            Err(ParamsError::UnsupportedVersion(9))
        );
    }

    /// A lying relay count must not be trusted — it is checked against the real length.
    #[test]
    fn a_lying_relay_count_is_rejected() {
        let mut bytes = sample().encode();
        bytes[54..56].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            NetworkParams::decode(&bytes),
            Err(ParamsError::Malformed { .. })
        ));
    }
}
