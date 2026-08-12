//! Phase-1 probe transport: TCP connect + TLS handshake against a raw IP,
//! measuring full-connection latency. Injectable so the engine and tests
//! never depend on a live network.
//! Handshake success alone marks an endpoint "open": phase-1 does not verify
//! certificates (anycast SNI fronting rarely matches the IP SAN), so the
//! verifier is bypassed on purpose; real configuration validation is what
//! phase-2 (Task 11) exists for.
//! Transport trait is consumed by the ScanController (Task 5); this flag
//! errors out once nothing in the module is dead anymore.
#![expect(dead_code)]

use std::net::Ipv4Addr;
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
    Refused(String),
    #[error("timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u64 },
    #[error("tls handshake failed: {0}")]
    Tls(String),
}

/// `Ok(latency_ms)` when the endpoint completed TCP+TLS within the budget.
pub trait Transport: Send + Sync {
    async fn probe(&self, ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Result<u32, ProbeError>;
}

/// Real transport: tokio TcpStream + rustls, no cert verification (see the
/// module note).
pub struct TlsTransport {
    connector: TlsConnector,
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
        }
    }
}

impl Default for TlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for TlsTransport {
    async fn probe(&self, ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Result<u32, ProbeError> {
        let start = Instant::now();
        let server_name =
            ServerName::try_from(PROBE_SNI.to_owned()).expect("static SNI is a valid hostname");
        let fut = async {
            let stream = TcpStream::connect((ip, port))
                .await
                .map_err(|e| ProbeError::Refused(e.to_string()))?;
            let mut tls = self
                .connector
                .connect(server_name.clone(), stream)
                .await
                .map_err(|e| ProbeError::Tls(e.to_string()))?;
            // Half-close to signal we want no response data back.
            let _ = tls.shutdown().await;
            Ok(())
        };
        match timeout(Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok(())) => Ok(start.elapsed().as_millis() as u32),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ProbeError::Timeout { timeout_ms }),
        }
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

/// Scripted transport for engine tests: each (ip, port) maps to a scripted
/// outcome. Latencies are returned verbatim so stop-condition math is
/// observable.
pub struct FakeTransport {
    script: std::sync::Mutex<std::collections::HashMap<(u32, u16), Result<u32, ProbeError>>>,
}

impl FakeTransport {
    pub fn new() -> Self {
        Self {
            script: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn ok(self, ip: Ipv4Addr, port: u16, latency_ms: u32) -> Self {
        self.script
            .lock()
            .unwrap()
            .insert((u32::from(ip), port), Ok(latency_ms));
        self
    }

    #[cfg(test)]
    pub fn fail(self, ip: Ipv4Addr, port: u16, err: ProbeError) -> Self {
        self.script
            .lock()
            .unwrap()
            .insert((u32::from(ip), port), Err(err));
        self
    }
}

impl Transport for FakeTransport {
    async fn probe(&self, ip: Ipv4Addr, port: u16, _timeout_ms: u64) -> Result<u32, ProbeError> {
        match self.script.lock().unwrap().get(&(u32::from(ip), port)) {
            Some(r) => r.clone(),
            None => Err(ProbeError::Refused("not scripted".to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_transport_builds_without_network() {
        let _ = TlsTransport::new();
    }

    #[tokio::test]
    async fn fake_returns_scripted_outcomes() {
        let t = FakeTransport::new().ok("1.2.3.4".parse().unwrap(), 443, 42);
        assert_eq!(t.probe("1.2.3.4".parse().unwrap(), 443, 3000).await, Ok(42));
        assert_eq!(
            t.probe("5.6.7.8".parse().unwrap(), 443, 3000).await,
            Err(ProbeError::Refused("not scripted".to_owned()))
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
}
