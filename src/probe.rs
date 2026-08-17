//! Phase-1 probe transport: TCP connect + TLS handshake against a raw IP,
//! measuring full-connection latency. Injectable so the engine and tests
//! never depend on a live network.
//! Handshake success alone marks an endpoint "open": phase-1 does not verify
//! certificates (anycast SNI fronting rarely matches the IP SAN), so the
//! verifier is bypassed on purpose; real configuration validation is what
//! phase-2 (Task 11) exists for.
//! `FakeTransport` (and its `Scripted` scripting type) exist only for tests
//! and are `#[cfg(test)]`-gated, so the public transport items stay the
//! lib's API surface.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// SNI sent on every phase-1 probe; Cloudflare serves a cert for it from any
/// of its CDN IPs.
pub const PROBE_SNI: &str = "cloudflare.com";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProbeError {
    #[error("connect refused/closed: {0}")]
    Refused(&'static str),
    #[error("timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u64 },
    #[error("tls handshake failed: {0}")]
    Tls(&'static str),
}

/// `Ok(latency_ms)` when the endpoint completed TCP+TLS within the budget.
/// Core type is an explicit future so `Arc<dyn Transport>` stays object-safe
/// for the server. `ip` may be v4 or v6; the connect goes to `[ip]:port`
/// either way.
pub trait Transport: Send + Sync {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<u32, ProbeError>> + Send + '_>>;
}

/// Real transport: tokio TcpStream + rustls, no cert verification (see the
/// module note). The SNI `ServerName` is built once here and cloned per
/// probe: `ServerName` holds an `Arc`-backed name, so a clone is a refcount
/// bump instead of the parse + allocation a per-probe build would cost on
/// every one of millions of probes.
pub struct TlsTransport {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsTransport {
    pub fn new() -> Self {
        // Explicit ring provider: no process-level install needed in tests
        // or when other rustls consumers install a different provider.
        let config = ClientConfig::builder_with_provider(ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name: ServerName::try_from(PROBE_SNI.to_owned())
                .expect("static SNI is a valid hostname"),
        }
    }
}

impl Default for TlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for TlsTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<u32, ProbeError>> + Send + '_>> {
        let start = Instant::now();
        let server_name = self.server_name.clone();
        Box::pin(async move {
            let fut = async {
                let stream = TcpStream::connect((ip, port))
                    .await
                    // Static reason, not the io error text: connect-refused is
                    // the common-case outcome on millions of probes, and the
                    // reason is diagnostic enough (the underlying errno text
                    // added nothing callers branch on).
                    .map_err(|_| ProbeError::Refused("connection refused/closed"))?;
                let mut tls = self
                    .connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|_| ProbeError::Tls("handshake failed"))?;
                // Half-close to signal we want no response data back.
                let _ = tls.shutdown().await;
                Ok(())
            };
            match timeout(Duration::from_millis(timeout_ms), fut).await {
                Ok(Ok(())) => Ok(start.elapsed().as_millis() as u32),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ProbeError::Timeout { timeout_ms }),
            }
        })
    }
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A scripted outcome plus an optional artificial delay so tests can
/// exercise cancellation while a probe is in flight.
#[cfg(test)]
#[derive(Clone)]
struct Scripted {
    /// Falls back to the last sequence entry once the queue is drained.
    outcome: Result<u32, ProbeError>,
    delay_ms: u64,
    sequence: std::collections::VecDeque<Result<u32, ProbeError>>,
}

/// Scripted transport for engine tests: each (ip, port) maps to a scripted
/// outcome. Latencies are returned verbatim so stop-condition math is
/// observable.
#[cfg(test)]
pub struct FakeTransport {
    script: std::sync::Mutex<std::collections::HashMap<(IpAddr, u16), Scripted>>,
}

#[cfg(test)]
impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl FakeTransport {
    pub fn new() -> Self {
        Self {
            script: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Chainable builder entry.
    pub fn ok(self, ip: IpAddr, port: u16, latency_ms: u32) -> Self {
        self.insert(ip, port, Ok(latency_ms));
        self
    }

    /// Chainable builder entry for an Ok outcome that only resolves after
    /// `delay_ms` of real time.
    pub fn ok_slow(self, ip: IpAddr, port: u16, latency_ms: u32, delay_ms: u64) -> Self {
        self.insert(ip, port, Ok(latency_ms));
        self.script
            .lock()
            .unwrap()
            .get_mut(&(ip, port))
            .unwrap()
            .delay_ms = delay_ms;
        self
    }

    /// Mutable insert for tests that script transports incrementally.
    pub fn insert(&self, ip: IpAddr, port: u16, outcome: Result<u32, ProbeError>) {
        self.script.lock().unwrap().insert(
            (ip, port),
            Scripted {
                outcome,
                delay_ms: 0,
                sequence: std::collections::VecDeque::new(),
            },
        );
    }

    /// Chainable builder for per-call outcomes (WARP loss tests): each call
    /// pops the next entry; the entry inserted first is used first.
    pub fn seq(self, ip: IpAddr, port: u16, outcomes: Vec<Result<u32, ProbeError>>) -> Self {
        self.script.lock().unwrap().insert(
            (ip, port),
            Scripted {
                outcome: outcomes
                    .last()
                    .cloned()
                    .unwrap_or(Err(ProbeError::Refused("empty sequence"))),
                delay_ms: 0,
                sequence: outcomes.into(),
            },
        );
        self
    }

    pub fn clear(&self) {
        self.script.lock().unwrap().clear();
    }

    #[cfg(test)]
    pub fn fail(self, ip: IpAddr, port: u16, err: ProbeError) -> Self {
        self.insert(ip, port, Err(err));
        self
    }
}

#[cfg(test)]
impl Transport for FakeTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        _timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<u32, ProbeError>> + Send + '_>> {
        let mut scripted = match self.script.lock().unwrap().get(&(ip, port)) {
            Some(s) => s.clone(),
            None => Scripted {
                outcome: Err(ProbeError::Refused("not scripted")),
                delay_ms: 0,
                sequence: std::collections::VecDeque::new(),
            },
        };
        if let Some(next) = scripted.sequence.pop_front() {
            self.script
                .lock()
                .unwrap()
                .get_mut(&(ip, port))
                .expect("scripted entry must still exist")
                .sequence = scripted.sequence;
            scripted.outcome = next;
        }
        Box::pin(async move {
            if scripted.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(scripted.delay_ms)).await;
            }
            scripted.outcome
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_transport_builds_without_network() {
        let _ = TlsTransport::new();
    }

    #[test]
    fn transport_builds_its_server_name_once_at_construction() {
        // The ServerName lives on the transport, so per-probe work is a
        // refcount bump on an Arc, never a parse + allocation (millions of
        // probes on a Full scan).
        let transport = TlsTransport::new();
        let expected = ServerName::try_from(PROBE_SNI.to_owned()).unwrap();
        match (&transport.server_name, &expected) {
            (ServerName::DnsName(a), ServerName::DnsName(b)) => {
                assert_eq!(a, b, "transport must use the documented probe SNI");
            }
            _ => panic!(
                "probe SNI must be a DNS name, got {:?}",
                transport.server_name
            ),
        }
        // Clones are cheap and equal: the per-probe path clones the stored
        // name, and the clone must round-trip identically.
        assert_eq!(transport.server_name.clone(), transport.server_name);
    }

    #[tokio::test]
    async fn fake_returns_scripted_outcomes() {
        let t = FakeTransport::new().ok("1.2.3.4".parse().unwrap(), 443, 42);
        assert_eq!(t.probe("1.2.3.4".parse().unwrap(), 443, 3000).await, Ok(42));
        assert_eq!(
            t.probe("5.6.7.8".parse().unwrap(), 443, 3000).await,
            Err(ProbeError::Refused("not scripted"))
        );
        let t = FakeTransport::new().fail(
            "9.9.9.9".parse().unwrap(),
            443,
            ProbeError::Timeout { timeout_ms: 3000 },
        );
        assert_eq!(
            t.probe("9.9.9.9".parse().unwrap(), 443, 3000).await,
            Err(ProbeError::Timeout { timeout_ms: 3000 })
        );
    }

    #[tokio::test]
    async fn fake_keys_v6_addresses_by_family() {
        let t = FakeTransport::new()
            .ok("2606:4700::1".parse().unwrap(), 443, 7)
            .ok("1.2.3.4".parse().unwrap(), 443, 9);
        assert_eq!(
            t.probe("2606:4700::1".parse().unwrap(), 443, 1000).await,
            Ok(7)
        );
        assert_eq!(t.probe("1.2.3.4".parse().unwrap(), 443, 1000).await, Ok(9));
    }

    #[tokio::test]
    async fn fake_sequence_is_consumed_then_repeats_last() {
        let t = FakeTransport::new().seq(
            "1.2.3.4".parse().unwrap(),
            443,
            vec![Ok(5), Err(ProbeError::Timeout { timeout_ms: 1 })],
        );
        assert_eq!(t.probe("1.2.3.4".parse().unwrap(), 443, 1).await, Ok(5));
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 1).await,
            Err(ProbeError::Timeout { timeout_ms: 1 })
        );
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 1).await,
            Err(ProbeError::Timeout { timeout_ms: 1 })
        );
    }
}
