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

pub trait Transport: Send + Sync {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<u32, ProbeError>> + Send + '_>>;
}

pub struct TlsTransport {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsTransport {
    pub fn new() -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(no_verify_client_config())),
            server_name: ServerName::try_from(PROBE_SNI.to_owned())
                .expect("static SNI is a valid hostname"),
        }
    }
}

pub(crate) fn no_verify_client_config() -> ClientConfig {
    ClientConfig::builder_with_provider(ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
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
                let stream = TcpStream::connect((ip, port)).await.map_err(|e| {
                    tracing::debug!(error = %e, "probe connect failed");
                    ProbeError::Refused("connection refused/closed")
                })?;
                let _ = stream.set_nodelay(true);
                let mut tls = self
                    .connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| {
                        tracing::debug!(error = %e, "probe tls handshake failed");
                        ProbeError::Tls("handshake failed")
                    })?;
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

#[cfg(any(test, feature = "test-helpers"))]
#[derive(Clone)]
struct Scripted {
    outcome: Result<u32, ProbeError>,
    delay_ms: u64,
    sequence: std::collections::VecDeque<Result<u32, ProbeError>>,
}

#[cfg(any(test, feature = "test-helpers"))]
pub struct FakeTransport {
    script: std::sync::Mutex<std::collections::HashMap<(IpAddr, u16), Scripted>>,
    pub rendezvous: Option<std::sync::Arc<tokio::sync::Barrier>>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl FakeTransport {
    pub fn new() -> Self {
        Self {
            script: std::sync::Mutex::new(std::collections::HashMap::new()),
            rendezvous: None,
        }
    }

    pub fn ok(self, ip: IpAddr, port: u16, latency_ms: u32) -> Self {
        self.insert(ip, port, Ok(latency_ms));
        self
    }

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

    pub fn fail(self, ip: IpAddr, port: u16, err: ProbeError) -> Self {
        self.insert(ip, port, Err(err));
        self
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Transport for FakeTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        _timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<u32, ProbeError>> + Send + '_>> {
        let scripted = {
            let mut map = self.script.lock().unwrap();
            match map.get_mut(&(ip, port)) {
                Some(entry) => {
                    if let Some(next) = entry.sequence.pop_front() {
                        entry.outcome = next;
                    }
                    entry.clone()
                }
                None => Scripted {
                    outcome: Err(ProbeError::Refused("not scripted")),
                    delay_ms: 0,
                    sequence: std::collections::VecDeque::new(),
                },
            }
        };
        let rendezvous = self.rendezvous.clone();
        Box::pin(async move {
            if let Some(barrier) = &rendezvous {
                barrier.wait().await;
            }
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
