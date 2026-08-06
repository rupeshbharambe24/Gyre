//! **Milestone S5 — QUIC transport.**
//!
//! Replaces "one TCP connection carrying everything" with QUIC's independent streams. The
//! win is concrete and narrow: a lost packet on one circuit no longer stalls every other
//! circuit sharing the connection (cross-circuit head-of-line blocking), because each
//! circuit gets its own stream.
//!
//! **This changes performance, not anonymity.** Onion routing, mixing, and the crowd are
//! what provide anonymity; the byte transport underneath them provides none. Nothing in
//! this module moves a number in `docs/SIMULATION.md`.
//!
//! # How relays are authenticated
//!
//! Relays have no domain names and no CA-issued certificates, so the usual web PKI does not
//! apply. The two tempting shortcuts are both wrong:
//!
//! - *Disable certificate verification* — then any machine can impersonate any relay, and
//!   the "encrypted" transport authenticates nothing.
//! - *Trust on first use* — an attacker present at first contact becomes the relay forever.
//!
//! Instead each relay generates a self-signed certificate and publishes its **SHA-256
//! fingerprint** in the threshold-signed consensus (`gyre-directory::NetworkParams`). A
//! client pins that fingerprint and rejects anything else. Two things must both hold for a
//! connection to succeed:
//!
//! 1. the presented certificate hashes to exactly the pinned fingerprint, and
//! 2. the peer proves possession of that certificate's private key — the ordinary TLS 1.3
//!    signature check, which is **delegated to rustls** rather than reimplemented.
//!
//! Returning success from the signature callbacks would be catastrophic: anyone could
//! replay a copy of the (public) certificate without holding its key. That delegation is
//! the single most important line in this file.
//!
//! # What is *not* implemented
//!
//! **MASQUE (RFC 9298 CONNECT-UDP) is not here.** MASQUE tunnels this traffic inside real
//! HTTP/3 so it looks like ordinary web traffic — a *censorship-resistance* feature that
//! belongs with `gyre-obfs`, not a performance one. QUIC delivers the head-of-line win on
//! its own; MASQUE is tracked separately and should not be assumed present.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::{Error, Result, MAX_FRAME};

/// The name presented in the TLS SNI field. Relays are identified by pinned fingerprint,
/// not by name, so this is a fixed placeholder — it is never used to make a trust decision.
const RELAY_SERVER_NAME: &str = "relay.gyre.invalid";

/// A relay's QUIC identity: a self-signed certificate, its private key, and the SHA-256
/// fingerprint that goes into the consensus for clients to pin.
pub struct RelayIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    fingerprint: [u8; 32],
}

impl RelayIdentity {
    /// Generate a fresh self-signed identity.
    pub fn generate() -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec![RELAY_SERVER_NAME.to_string()])
            .map_err(|e| Error::Tls(format!("generating relay certificate: {e}")))?;
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
            .map_err(|e| Error::Tls(format!("encoding relay key: {e}")))?;
        let fingerprint = Sha256::digest(cert_der.as_ref()).into();
        Ok(Self {
            cert: cert_der,
            key: key_der,
            fingerprint,
        })
    }

    /// The SHA-256 fingerprint of this relay's certificate — publish this in the consensus.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// Constant-time byte comparison. The fingerprint is public, so this is belt-and-braces
/// rather than strictly required — but a comparison that short-circuits on the first
/// differing byte is never the one you want in a verifier.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Accepts exactly one certificate: the one whose SHA-256 hash matches the pinned value.
///
/// Signature verification is **delegated to rustls**, so a peer must also prove it holds
/// the matching private key. Pinning alone would authenticate nothing — certificates are
/// public.
#[derive(Debug)]
struct PinnedFingerprint {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedFingerprint {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if constant_time_eq(&actual, &self.expected) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "relay certificate does not match the fingerprint pinned from the consensus".into(),
            ))
        }
    }

    // The two callbacks below MUST perform real signature verification. Returning
    // `Ok(...)` here would let anyone replay a copy of the pinned (public) certificate
    // without holding its private key, which would defeat the entire scheme.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Bind a QUIC listener for a relay.
pub fn server_endpoint(addr: SocketAddr, identity: &RelayIdentity) -> Result<Endpoint> {
    let mut tls = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(format!("server TLS versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|e| Error::Tls(format!("server certificate: {e}")))?;
    tls.alpn_protocols = vec![b"gyre/1".to_vec()];

    let quic = QuicServerConfig::try_from(tls)
        .map_err(|e| Error::Tls(format!("server QUIC config: {e}")))?;
    Endpoint::server(ServerConfig::with_crypto(Arc::new(quic)), addr).map_err(Error::Io)
}

/// Build a client endpoint that will only talk to a relay presenting `pinned_fingerprint`.
pub fn client_endpoint(pinned_fingerprint: [u8; 32]) -> Result<Endpoint> {
    let provider = ring_provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(format!("client TLS versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedFingerprint {
            expected: pinned_fingerprint,
            provider,
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"gyre/1".to_vec()];

    let quic =
        QuicClientConfig::try_from(tls).map_err(|e| Error::Tls(format!("client QUIC: {e}")))?;
    // Bind an ephemeral local port on the unspecified address.
    let mut endpoint =
        Endpoint::client("0.0.0.0:0".parse().expect("valid addr")).map_err(Error::Io)?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic)));
    Ok(endpoint)
}

/// Send one framed message to a relay over its own QUIC stream, and wait for the peer to
/// acknowledge the stream close.
///
/// Each call uses a fresh unidirectional stream: that is the whole point of the swap, since
/// a loss on one stream cannot stall another.
pub async fn send_framed(endpoint: &Endpoint, addr: SocketAddr, bytes: &[u8]) -> Result<()> {
    let conn = endpoint
        .connect(addr, RELAY_SERVER_NAME)
        .map_err(|e| Error::Tls(format!("connect: {e}")))?
        .await
        .map_err(|e| Error::Tls(format!("handshake: {e}")))?;
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| Error::Tls(format!("open stream: {e}")))?;

    let len = u32::try_from(bytes.len()).map_err(|_| Error::FrameTooLarge(bytes.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::Tls(format!("write length: {e}")))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|e| Error::Tls(format!("write body: {e}")))?;
    stream
        .finish()
        .map_err(|e| Error::Tls(format!("finish stream: {e}")))?;
    // Let the peer drain before the connection is dropped.
    conn.closed().await;
    Ok(())
}

/// Accept one incoming connection and read one framed message from its first stream.
///
/// The same `MAX_FRAME` guard as the TCP transport applies: an attacker-supplied length
/// prefix can never make us allocate more than a bounded buffer.
pub async fn accept_framed(endpoint: &Endpoint) -> Result<Option<Vec<u8>>> {
    let Some(incoming) = endpoint.accept().await else {
        return Ok(None);
    };
    let conn = incoming
        .await
        .map_err(|e| Error::Tls(format!("accept handshake: {e}")))?;
    let mut stream = match conn.accept_uni().await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Tls(format!("read body: {e}")))?;
    conn.close(0u32.into(), b"done");
    Ok(Some(buf))
}
