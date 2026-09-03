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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    #[error("http status {0} not accepted")]
    HttpStatus(u16),
}

impl ProbeError {
    pub fn reason(&self) -> &'static str {
        match self {
            ProbeError::Refused(_) => "refused",
            ProbeError::Timeout { .. } => "timeout",
            ProbeError::Tls(_) => "tls_failed",
            ProbeError::HttpStatus(_) => "http_status",
        }
    }
}

pub type ProbeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProbeOutcome, ProbeError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub latency_ms: u32,
    pub sent: u32,
    pub received: u32,
    pub colo: Option<String>,
}

impl ProbeOutcome {
    pub fn plain(latency_ms: u32) -> Self {
        Self {
            latency_ms,
            sent: 1,
            received: 1,
            colo: None,
        }
    }
}

pub trait Transport: Send + Sync {
    fn probe(&self, ip: IpAddr, port: u16, timeout_ms: u64, idle_hold_ms: u64) -> ProbeFuture<'_>;
}

pub fn transport_for(
    mode: crate::api::types::ProbeMode,
    accepted_codes: &[u16],
) -> Arc<dyn Transport> {
    use crate::api::types::ProbeMode;
    match mode {
        ProbeMode::Tcp => Arc::new(TcpTransport),
        ProbeMode::Tls => Arc::new(TlsTransport::new()),
        ProbeMode::Http => Arc::new(HttpTransport::new(accepted_codes.to_vec())),
    }
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
    fn probe(&self, ip: IpAddr, port: u16, timeout_ms: u64, idle_hold_ms: u64) -> ProbeFuture<'_> {
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
                let latency = start.elapsed().as_millis() as u32;
                Ok((tls, latency))
            };
            match timeout(Duration::from_millis(timeout_ms), fut).await {
                Ok(Ok((mut tls, latency))) => {
                    if idle_hold_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(idle_hold_ms)).await;
                        let mut byte = [0u8; 1];
                        let held =
                            timeout(Duration::from_millis(timeout_ms), tls.read(&mut byte)).await;
                        match held {
                            Ok(Ok(0)) | Ok(Err(_)) => {
                                tracing::debug!("idle-hold probe closed by peer");
                                return Err(ProbeError::Refused("idle-hold RST"));
                            }
                            _ => {}
                        }
                    }
                    Ok(ProbeOutcome::plain(latency))
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ProbeError::Timeout { timeout_ms }),
            }
        })
    }
}

pub struct TcpTransport;

impl Transport for TcpTransport {
    fn probe(&self, ip: IpAddr, port: u16, timeout_ms: u64, idle_hold_ms: u64) -> ProbeFuture<'_> {
        let start = Instant::now();
        Box::pin(async move {
            let fut = async {
                let stream = TcpStream::connect((ip, port)).await.map_err(|e| {
                    tracing::debug!(error = %e, "probe connect failed");
                    ProbeError::Refused("connection refused/closed")
                })?;
                let _ = stream.set_nodelay(true);
                Ok(stream)
            };
            match timeout(Duration::from_millis(timeout_ms), fut).await {
                Ok(Ok(mut stream)) => {
                    if idle_hold_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(idle_hold_ms)).await;
                        let mut byte = [0u8; 1];
                        let held =
                            timeout(Duration::from_millis(timeout_ms), stream.read(&mut byte))
                                .await;
                        match held {
                            Ok(Ok(0)) | Ok(Err(_)) => {
                                tracing::debug!("idle-hold probe closed by peer");
                                return Err(ProbeError::Refused("idle-hold RST"));
                            }
                            _ => {}
                        }
                    }
                    Ok(ProbeOutcome::plain(start.elapsed().as_millis() as u32))
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ProbeError::Timeout { timeout_ms }),
            }
        })
    }
}

pub struct HttpTransport {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    accepted_codes: Vec<u16>,
}

impl HttpTransport {
    pub fn new(accepted_codes: Vec<u16>) -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(no_verify_client_config())),
            server_name: ServerName::try_from(PROBE_SNI.to_owned())
                .expect("static SNI is a valid hostname"),
            accepted_codes,
        }
    }
}

impl Transport for HttpTransport {
    fn probe(&self, ip: IpAddr, port: u16, timeout_ms: u64, idle_hold_ms: u64) -> ProbeFuture<'_> {
        let start = Instant::now();
        let server_name = self.server_name.clone();
        let connector = self.connector.clone();
        let accepted = self.accepted_codes.clone();
        Box::pin(async move {
            let fut = async {
                let stream = TcpStream::connect((ip, port)).await.map_err(|e| {
                    tracing::debug!(error = %e, "probe connect failed");
                    ProbeError::Refused("connection refused/closed")
                })?;
                let _ = stream.set_nodelay(true);
                let mut tls = connector.connect(server_name, stream).await.map_err(|e| {
                    tracing::debug!(error = %e, "probe tls handshake failed");
                    ProbeError::Tls("handshake failed")
                })?;
                tls.write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n")
                    .await
                    .map_err(|_| ProbeError::Refused("request write failed"))?;
                let mut buf = Vec::with_capacity(2048);
                let mut chunk = [0u8; 4096];
                loop {
                    let n = tls.read(&mut chunk).await.map_err(|e| {
                        tracing::debug!(error = %e, "probe response read failed");
                        ProbeError::Refused("response read failed")
                    })?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > 64 * 1024 {
                        return Err(ProbeError::Refused("trace response too large"));
                    }
                }
                let latency = start.elapsed().as_millis() as u32;
                Ok((tls, latency, buf))
            };
            match timeout(Duration::from_millis(timeout_ms), fut).await {
                Ok(Ok((mut tls, latency, buf))) => {
                    if idle_hold_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(idle_hold_ms)).await;
                        let mut byte = [0u8; 1];
                        let held =
                            timeout(Duration::from_millis(timeout_ms), tls.read(&mut byte)).await;
                        match held {
                            Ok(Ok(0)) | Ok(Err(_)) => {
                                tracing::debug!("idle-hold probe closed by peer");
                                return Err(ProbeError::Refused("idle-hold RST"));
                            }
                            _ => {}
                        }
                    }
                    let end_of_headers = find_subsequence(&buf, b"\r\n\r\n")
                        .ok_or(ProbeError::Refused("malformed http response"))?;
                    let head = &buf[..end_of_headers];
                    let body = &buf[end_of_headers + 4..];
                    let status = parse_status_line(head)
                        .ok_or(ProbeError::Refused("malformed status line"))?;
                    if !accepted.contains(&status) {
                        return Err(ProbeError::HttpStatus(status));
                    }
                    let colo = crate::geo::parse_colo(body);
                    Ok(ProbeOutcome {
                        latency_ms: latency,
                        sent: 1,
                        received: 1,
                        colo,
                    })
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ProbeError::Timeout { timeout_ms }),
            }
        })
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_status_line(head: &[u8]) -> Option<u16> {
    let head = std::str::from_utf8(head).ok()?;
    let mut parts = head.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
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
    outcome: Result<ProbeOutcome, ProbeError>,
    delay_ms: u64,
    idle_rst_ms: Option<u64>,
    sequence: std::collections::VecDeque<Result<ProbeOutcome, ProbeError>>,
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

    pub fn ok_loss(self, ip: IpAddr, port: u16, latency_ms: u32, sent: u32, received: u32) -> Self {
        self.insert_full(
            ip,
            port,
            Ok(ProbeOutcome {
                latency_ms,
                sent,
                received,
                colo: None,
            }),
        );
        self
    }

    pub fn ok_colo(self, ip: IpAddr, port: u16, latency_ms: u32, colo: &str) -> Self {
        self.insert_full(
            ip,
            port,
            Ok(ProbeOutcome {
                latency_ms,
                sent: 1,
                received: 1,
                colo: Some(colo.to_owned()),
            }),
        );
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

    pub fn idle_rst(self, ip: IpAddr, port: u16, latency_ms: u32, rst_after_ms: u64) -> Self {
        self.insert(ip, port, Ok(latency_ms));
        self.script
            .lock()
            .unwrap()
            .get_mut(&(ip, port))
            .unwrap()
            .idle_rst_ms = Some(rst_after_ms);
        self
    }

    pub fn insert(&self, ip: IpAddr, port: u16, outcome: Result<u32, ProbeError>) {
        self.insert_full(ip, port, outcome.map(ProbeOutcome::plain));
    }

    pub fn insert_full(&self, ip: IpAddr, port: u16, outcome: Result<ProbeOutcome, ProbeError>) {
        self.script.lock().unwrap().insert(
            (ip, port),
            Scripted {
                outcome,
                delay_ms: 0,
                idle_rst_ms: None,
                sequence: std::collections::VecDeque::new(),
            },
        );
    }

    pub fn seq(self, ip: IpAddr, port: u16, outcomes: Vec<Result<u32, ProbeError>>) -> Self {
        let expand = |outcome: Result<u32, ProbeError>| outcome.map(ProbeOutcome::plain);
        self.script.lock().unwrap().insert(
            (ip, port),
            Scripted {
                outcome: outcomes
                    .last()
                    .cloned()
                    .map(expand)
                    .unwrap_or(Err(ProbeError::Refused("empty sequence"))),
                delay_ms: 0,
                idle_rst_ms: None,
                sequence: outcomes.into_iter().map(expand).collect(),
            },
        );
        self
    }

    pub fn clear(&self) {
        self.script.lock().unwrap().clear();
    }

    pub fn fail(self, ip: IpAddr, port: u16, err: ProbeError) -> Self {
        self.insert_full(ip, port, Err(err));
        self
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Transport for FakeTransport {
    fn probe(&self, ip: IpAddr, port: u16, _timeout_ms: u64, idle_hold_ms: u64) -> ProbeFuture<'_> {
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
                    idle_rst_ms: None,
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
            if idle_hold_ms > 0
                && let Some(rst_after_ms) = scripted.idle_rst_ms
            {
                tokio::time::sleep(Duration::from_millis(rst_after_ms)).await;
                return Err(ProbeError::Refused("idle-hold RST"));
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
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 3000, 0).await,
            Ok(ProbeOutcome::plain(42))
        );
        assert_eq!(
            t.probe("5.6.7.8".parse().unwrap(), 443, 3000, 0).await,
            Err(ProbeError::Refused("not scripted"))
        );
        let t = FakeTransport::new().fail(
            "9.9.9.9".parse().unwrap(),
            443,
            ProbeError::Timeout { timeout_ms: 3000 },
        );
        assert_eq!(
            t.probe("9.9.9.9".parse().unwrap(), 443, 3000, 0).await,
            Err(ProbeError::Timeout { timeout_ms: 3000 })
        );
    }

    #[tokio::test]
    async fn fake_idle_rst_fails_only_when_idle_hold_is_on() {
        let t = FakeTransport::new().idle_rst("1.2.3.4".parse().unwrap(), 443, 9, 5);
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 3000, 20).await,
            Err(ProbeError::Refused("idle-hold RST"))
        );
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 3000, 0).await,
            Ok(ProbeOutcome::plain(9))
        );
    }

    #[tokio::test]
    async fn fake_loss_scripting_reports_sent_received() {
        let t = FakeTransport::new().ok_loss("1.2.3.4".parse().unwrap(), 443, 7, 4, 3);
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 3000, 0).await,
            Ok(ProbeOutcome {
                latency_ms: 7,
                sent: 4,
                received: 3,
                colo: None,
            })
        );
    }

    #[test]
    fn probe_error_reasons_are_stable() {
        assert_eq!(ProbeError::Refused("x").reason(), "refused");
        assert_eq!(ProbeError::Timeout { timeout_ms: 1 }.reason(), "timeout");
        assert_eq!(ProbeError::Tls("x").reason(), "tls_failed");
        assert_eq!(ProbeError::HttpStatus(503).reason(), "http_status");
    }

    #[tokio::test]
    async fn fake_keys_v6_addresses_by_family() {
        let t = FakeTransport::new()
            .ok("2606:4700::1".parse().unwrap(), 443, 7)
            .ok("1.2.3.4".parse().unwrap(), 443, 9);
        assert_eq!(
            t.probe("2606:4700::1".parse().unwrap(), 443, 1000, 0).await,
            Ok(ProbeOutcome::plain(7))
        );
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 1000, 0).await,
            Ok(ProbeOutcome::plain(9))
        );
    }

    #[tokio::test]
    async fn fake_sequence_is_consumed_then_repeats_last() {
        let t = FakeTransport::new().seq(
            "1.2.3.4".parse().unwrap(),
            443,
            vec![Ok(5), Err(ProbeError::Timeout { timeout_ms: 1 })],
        );
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 1, 0).await,
            Ok(ProbeOutcome::plain(5))
        );
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 1, 0).await,
            Err(ProbeError::Timeout { timeout_ms: 1 })
        );
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 1, 0).await,
            Err(ProbeError::Timeout { timeout_ms: 1 })
        );
    }

    #[tokio::test]
    async fn fake_colo_scripting_carries_the_trace_code() {
        let t = FakeTransport::new().ok_colo("1.2.3.4".parse().unwrap(), 443, 12, "LHR");
        assert_eq!(
            t.probe("1.2.3.4".parse().unwrap(), 443, 3000, 0).await,
            Ok(ProbeOutcome {
                latency_ms: 12,
                sent: 1,
                received: 1,
                colo: Some("LHR".to_owned()),
            })
        );
    }

    #[test]
    fn tcp_and_http_transports_build_without_network() {
        let _ = TcpTransport;
        let _ = HttpTransport::new(vec![200, 301, 302]);
        let _ = transport_for(crate::api::types::ProbeMode::Http, &[200]);
    }

    #[test]
    fn status_line_parse_accepts_standard_responses() {
        assert_eq!(parse_status_line(b"HTTP/1.1 200 OK"), Some(200));
        assert_eq!(
            parse_status_line(b"HTTP/1.1 301 Moved Permanently"),
            Some(301)
        );
        assert_eq!(parse_status_line(b"HTTP/1.0 302 Found"), Some(302));
    }

    #[test]
    fn status_line_parse_rejects_garbage() {
        assert_eq!(parse_status_line(b""), None);
        assert_eq!(parse_status_line(b"garbage"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 OK"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 200x"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 99999"), None);
    }

    #[test]
    fn find_subsequence_locates_the_header_body_boundary() {
        assert_eq!(
            find_subsequence(b"HTTP/1.1 200 OK\r\n\r\nbody", b"\r\n\r\n"),
            Some(15)
        );
        assert_eq!(find_subsequence(b"no terminator", b"\r\n\r\n"), None);
    }
}
