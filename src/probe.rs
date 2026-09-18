use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    snis: &[ServerName<'static>],
) -> Arc<dyn Transport> {
    use crate::api::types::ProbeMode;
    match mode {
        ProbeMode::Tcp => Arc::new(TcpTransport),
        ProbeMode::Tls => Arc::new(TlsTransport::new().with_snis(snis.to_vec())),
        ProbeMode::Http => {
            Arc::new(HttpTransport::with_shared(Arc::from(accepted_codes)).with_snis(snis.to_vec()))
        }
    }
}

/// Parse validated `--probe-snis` strings into handshake-ready names.
/// Config validation guarantees DNS-only entries; this re-checks cheaply so a
/// direct caller can never smuggle an IP literal into the SNI slot. Empty
/// means unset and falls back to today's single probe SNI.
pub fn parse_probe_snis(
    raw: &[String],
) -> Result<Vec<ServerName<'static>>, crate::api::types::ConfigError> {
    use crate::api::types::ConfigError;
    if raw.is_empty() {
        return Ok(vec![default_probe_sni()]);
    }
    raw.iter()
        .map(|s| {
            let name = ServerName::try_from(s.clone()).map_err(|_| {
                ConfigError::InvalidSni(s.clone(), "must be a DNS hostname".to_owned())
            })?;
            match name {
                ServerName::DnsName(_) => Ok(name),
                _ => Err(ConfigError::InvalidSni(
                    s.clone(),
                    "probe SNIs must be DNS hostnames, not IP addresses".to_owned(),
                )),
            }
        })
        .collect()
}

fn default_probe_sni() -> ServerName<'static> {
    ServerName::try_from(PROBE_SNI.to_owned()).expect("static SNI is a valid hostname")
}

/// Pick the next SNI in rotation order. Sequential callers observe a strict
/// round-robin; under concurrency the counter still spreads consecutive
/// probes across names with no RNG and no extra dials. (True per-worker
/// pinning would be unobservable anyway: task-to-worker assignment already
/// races. The injectable-transport seam stays untouched by design, ADR-011.)
fn pick_sni(
    snis: &[ServerName<'static>],
    hosts: &[String],
    next: &AtomicUsize,
) -> (ServerName<'static>, String) {
    debug_assert!(!snis.is_empty() && snis.len() == hosts.len());
    let i = next.fetch_add(1, Ordering::Relaxed) % snis.len();
    (snis[i].clone(), hosts[i].clone())
}

pub struct TlsTransport {
    connector: TlsConnector,
    snis: Arc<[ServerName<'static>]>,
    sni_hosts: Arc<[String]>,
    next_sni: AtomicUsize,
}

impl TlsTransport {
    pub fn new() -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(no_verify_client_config())),
            snis: Arc::from([default_probe_sni()]),
            sni_hosts: Arc::from([PROBE_SNI.to_owned()]),
            next_sni: AtomicUsize::new(0),
        }
    }

    /// Opt-in rotation set. Non-DNS entries are dropped (config validation
    /// rejects them first); an empty survivors list keeps the default single.
    pub fn with_snis(mut self, snis: Vec<ServerName<'static>>) -> Self {
        let kept: Vec<(ServerName<'static>, String)> = snis
            .into_iter()
            .filter_map(|name| {
                let host = match &name {
                    ServerName::DnsName(dns) => dns.as_ref().to_owned(),
                    _ => return None,
                };
                Some((name, host))
            })
            .collect();
        if !kept.is_empty() {
            let (names, hosts): (Vec<_>, Vec<_>) = kept.into_iter().unzip();
            self.snis = Arc::from(names);
            self.sni_hosts = Arc::from(hosts);
        }
        self
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
        let (server_name, _host) = pick_sni(&self.snis, &self.sni_hosts, &self.next_sni);
        let (connect_ms, tls_ms) = tls_budgets(timeout_ms);
        Box::pin(async move {
            let fut = async {
                let stream = timeout(
                    Duration::from_millis(connect_ms),
                    TcpStream::connect((ip, port)),
                )
                .await
                .map_err(|_| ProbeError::Timeout { timeout_ms })?
                .map_err(|e| {
                    tracing::debug!(error = %e, "probe connect failed");
                    ProbeError::Refused("connection refused/closed")
                })?;
                let _ = stream.set_nodelay(true);
                let mut tls = timeout(
                    Duration::from_millis(tls_ms),
                    self.connector.connect(server_name, stream),
                )
                .await
                .map_err(|_| ProbeError::Timeout { timeout_ms })?
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
        let connect_ms = tcp_connect_budget(timeout_ms);
        Box::pin(async move {
            let fut = async {
                let stream = timeout(
                    Duration::from_millis(connect_ms),
                    TcpStream::connect((ip, port)),
                )
                .await
                .map_err(|_| ProbeError::Timeout { timeout_ms })?
                .map_err(|e| {
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
    snis: Arc<[ServerName<'static>]>,
    sni_hosts: Arc<[String]>,
    next_sni: AtomicUsize,
    accepted_codes: std::sync::Arc<[u16]>,
}

impl HttpTransport {
    pub fn new(accepted_codes: Vec<u16>) -> Self {
        Self::with_shared(std::sync::Arc::from(accepted_codes))
    }

    /// Shared-codes constructor: each probe clones the Arc, not the Vec.
    pub fn with_shared(accepted_codes: std::sync::Arc<[u16]>) -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(no_verify_client_config())),
            snis: Arc::from([default_probe_sni()]),
            sni_hosts: Arc::from([PROBE_SNI.to_owned()]),
            next_sni: AtomicUsize::new(0),
            accepted_codes,
        }
    }

    /// Opt-in rotation set; same fallback rules as [`TlsTransport::with_snis`].
    pub fn with_snis(mut self, snis: Vec<ServerName<'static>>) -> Self {
        let kept: Vec<(ServerName<'static>, String)> = snis
            .into_iter()
            .filter_map(|name| {
                let host = match &name {
                    ServerName::DnsName(dns) => dns.as_ref().to_owned(),
                    _ => return None,
                };
                Some((name, host))
            })
            .collect();
        if !kept.is_empty() {
            let (names, hosts): (Vec<_>, Vec<_>) = kept.into_iter().unzip();
            self.snis = Arc::from(names);
            self.sni_hosts = Arc::from(hosts);
        }
        self
    }
}

/// Trace request bytes for one probe. The Host header tracks the rotated SNI
/// so the handshake name and the request target never disagree.
fn trace_request(host: &str) -> Vec<u8> {
    format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn step_budgets(timeout_ms: u64) -> (u64, u64, u64) {
    let connect_ms = (timeout_ms * 30 / 100).max(1);
    let tls_ms = (timeout_ms * 30 / 100).max(1);
    let rw_ms = timeout_ms.saturating_sub(connect_ms + tls_ms).max(1);
    (connect_ms, tls_ms, rw_ms)
}

fn tcp_connect_budget(timeout_ms: u64) -> u64 {
    (timeout_ms / 4).max(1)
}

fn tls_budgets(timeout_ms: u64) -> (u64, u64) {
    let connect_ms = tcp_connect_budget(timeout_ms);
    let tls_ms = (timeout_ms.saturating_sub(connect_ms) / 2).max(1);
    (connect_ms, tls_ms)
}

impl Transport for HttpTransport {
    fn probe(&self, ip: IpAddr, port: u16, timeout_ms: u64, idle_hold_ms: u64) -> ProbeFuture<'_> {
        let start = Instant::now();
        let (server_name, host) = pick_sni(&self.snis, &self.sni_hosts, &self.next_sni);
        let connector = self.connector.clone();
        let accepted = self.accepted_codes.clone();
        let (connect_ms, tls_ms, rw_ms) = step_budgets(timeout_ms);
        Box::pin(async move {
            let fut = async {
                let stream = timeout(
                    Duration::from_millis(connect_ms),
                    TcpStream::connect((ip, port)),
                )
                .await
                .map_err(|_| ProbeError::Timeout { timeout_ms })?
                .map_err(|e| {
                    tracing::debug!(error = %e, "probe connect failed");
                    ProbeError::Refused("connection refused/closed")
                })?;
                let _ = stream.set_nodelay(true);
                let mut tls = timeout(
                    Duration::from_millis(tls_ms),
                    connector.connect(server_name, stream),
                )
                .await
                .map_err(|_| ProbeError::Timeout { timeout_ms })?
                .map_err(|e| {
                    tracing::debug!(error = %e, "probe tls handshake failed");
                    ProbeError::Tls("handshake failed")
                })?;
                let buf = timeout(Duration::from_millis(rw_ms), async {
                    tls.write_all(&trace_request(&host))
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
                    Ok(buf)
                })
                .await
                .map_err(|_| ProbeError::Timeout { timeout_ms })??;
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

#[cfg(test)]
#[derive(Clone)]
struct Scripted {
    outcome: Result<ProbeOutcome, ProbeError>,
    delay_ms: u64,
    idle_rst_ms: Option<u64>,
    sequence: std::collections::VecDeque<Result<ProbeOutcome, ProbeError>>,
}

#[cfg(test)]
pub struct FakeTransport {
    script: std::sync::Mutex<std::collections::HashMap<(IpAddr, u16), Scripted>>,
    pub rendezvous: Option<std::sync::Arc<tokio::sync::Barrier>>,
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

#[cfg(test)]
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
        let (name, host) = pick_sni(&transport.snis, &transport.sni_hosts, &transport.next_sni);
        match (&name, &expected) {
            (ServerName::DnsName(a), ServerName::DnsName(b)) => {
                assert_eq!(
                    a.as_ref(),
                    b.as_ref(),
                    "transport must use the documented probe SNI"
                );
            }
            _ => panic!("probe SNI must be a DNS name, got {name:?}"),
        }
        assert_eq!(host, PROBE_SNI);
        assert_eq!(transport.snis.len(), 1);
    }

    #[test]
    fn sni_rotation_cycles_in_order_and_falls_back_to_default() {
        let names = ["a.example.com", "b.example.com", "c.example.com"]
            .into_iter()
            .map(|s| ServerName::try_from(s.to_owned()).unwrap())
            .collect::<Vec<_>>();
        let transport = TlsTransport::new().with_snis(names);
        let hosts: Vec<String> = (0..4)
            .map(|_| pick_sni(&transport.snis, &transport.sni_hosts, &transport.next_sni).1)
            .collect();
        assert_eq!(
            hosts,
            [
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "a.example.com"
            ]
        );

        let fallback = HttpTransport::with_shared(Arc::from([200u16])).with_snis(Vec::new());
        let (_, host) = pick_sni(&fallback.snis, &fallback.sni_hosts, &fallback.next_sni);
        assert_eq!(
            host, PROBE_SNI,
            "empty rotation set keeps the default single SNI"
        );

        let ip_only = HttpTransport::with_shared(Arc::from([200u16]))
            .with_snis(vec![ServerName::try_from("1.2.3.4".to_owned()).unwrap()]);
        let (_, host) = pick_sni(&ip_only.snis, &ip_only.sni_hosts, &ip_only.next_sni);
        assert_eq!(
            host, PROBE_SNI,
            "non-DNS entries never enter the rotation set"
        );
    }

    #[test]
    fn trace_request_carries_the_rotated_host() {
        let bytes = trace_request("speed.cloudflare.com");
        let text = String::from_utf8(bytes).expect("request is ASCII");
        assert!(text.starts_with("GET /cdn-cgi/trace HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: speed.cloudflare.com\r\n"));
        let default = trace_request(PROBE_SNI);
        assert!(
            String::from_utf8(default)
                .unwrap()
                .contains("\r\nHost: cloudflare.com\r\n")
        );
    }

    #[test]
    fn parse_probe_snis_accepts_dns_and_rejects_ips_and_garbage() {
        let input = ["example.com".to_owned(), "a.b-c.example".to_owned()];
        let parsed = parse_probe_snis(&input).expect("valid DNS names parse");
        assert_eq!(parsed.len(), 2);
        assert!(parse_probe_snis(&[]).expect("empty means unset").len() == 1);
        let ip = ["1.2.3.4".to_owned()];
        assert!(parse_probe_snis(&ip).is_err());
        let garbage = ["not a host!".to_owned()];
        assert!(parse_probe_snis(&garbage).is_err());
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
        let _ = transport_for(crate::api::types::ProbeMode::Http, &[200], &[]);
        let _ = transport_for(
            crate::api::types::ProbeMode::Tls,
            &[],
            &parse_probe_snis(&["example.com".to_owned()]).unwrap(),
        );
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
    fn step_budgets_split_30_30_remainder() {
        assert_eq!(step_budgets(3000), (900, 900, 1200));
        assert_eq!(step_budgets(100), (30, 30, 40));
        let (c, t, r) = step_budgets(1000);
        assert_eq!(c + t + r, 1000);
        let (c, t, r) = step_budgets(1);
        assert!(c >= 1 && t >= 1 && r >= 1);
    }

    #[test]
    fn tcp_connect_budget_is_quarter_of_timeout() {
        assert_eq!(tcp_connect_budget(4000), 1000);
        assert_eq!(tcp_connect_budget(3000), 750);
        assert_eq!(tcp_connect_budget(100), 25);
        assert_eq!(tcp_connect_budget(4), 1);
        assert_eq!(tcp_connect_budget(1), 1);
    }

    #[test]
    fn tls_budgets_split_quarter_then_half_remainder() {
        assert_eq!(tls_budgets(4000), (1000, 1500));
        assert_eq!(tls_budgets(3000), (750, 1125));
        assert_eq!(tls_budgets(100), (25, 37));
        for timeout_ms in [2, 3, 4, 7, 100, 1000, 3000, 8000] {
            let (connect_ms, tls_ms) = tls_budgets(timeout_ms);
            assert_eq!(connect_ms, tcp_connect_budget(timeout_ms));
            assert_eq!(tls_ms, ((timeout_ms - connect_ms) / 2).max(1));
            assert!(connect_ms >= 1 && tls_ms >= 1);
            assert!(
                connect_ms + tls_ms <= timeout_ms,
                "step budgets must fit inside the outer ceiling"
            );
        }
    }

    #[tokio::test]
    async fn budgeted_connect_healthy_keeps_identical_verdict() {
        let timeout_ms = 3000;
        let connect_ms = tcp_connect_budget(timeout_ms);
        let verdict: Result<ProbeOutcome, ProbeError> =
            timeout(Duration::from_millis(connect_ms), async {
                Ok::<ProbeOutcome, ProbeError>(ProbeOutcome::plain(42))
            })
            .await
            .map_err(|_| ProbeError::Timeout { timeout_ms })
            .expect("healthy connect must fit its budget");
        assert_eq!(verdict, Ok(ProbeOutcome::plain(42)));
    }

    #[tokio::test]
    async fn budgeted_handshake_healthy_keeps_identical_verdict() {
        let timeout_ms = 3000;
        let (_, tls_ms) = tls_budgets(timeout_ms);
        let verdict: Result<ProbeOutcome, ProbeError> =
            timeout(Duration::from_millis(tls_ms), async {
                Ok::<ProbeOutcome, ProbeError>(ProbeOutcome::plain(7))
            })
            .await
            .map_err(|_| ProbeError::Timeout { timeout_ms })
            .expect("healthy handshake must fit its budget");
        assert_eq!(verdict, Ok(ProbeOutcome::plain(7)));
    }

    #[tokio::test]
    async fn budgeted_connect_stall_fails_fast_with_outer_timeout() {
        let timeout_ms = 3000;
        let connect_ms = tcp_connect_budget(timeout_ms);
        assert!(connect_ms < timeout_ms);
        let start = Instant::now();
        let err = timeout(Duration::from_millis(connect_ms), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<ProbeOutcome, ProbeError>(ProbeOutcome::plain(1))
        })
        .await
        .map_err(|_| ProbeError::Timeout { timeout_ms })
        .expect_err("stalled connect must exhaust its budget");
        assert_eq!(err, ProbeError::Timeout { timeout_ms });
        assert_eq!(err.reason(), "timeout");
        assert!(
            start.elapsed() < Duration::from_millis(timeout_ms),
            "connect budget must fire well before the outer ceiling"
        );
    }

    #[tokio::test]
    async fn budgeted_handshake_stall_fails_fast_with_outer_timeout() {
        let timeout_ms = 3000;
        let (_, tls_ms) = tls_budgets(timeout_ms);
        assert!(tls_ms < timeout_ms);
        let start = Instant::now();
        let err = timeout(Duration::from_millis(tls_ms), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<ProbeOutcome, ProbeError>(ProbeOutcome::plain(1))
        })
        .await
        .map_err(|_| ProbeError::Timeout { timeout_ms })
        .expect_err("stalled handshake must exhaust its budget");
        assert_eq!(err, ProbeError::Timeout { timeout_ms });
        assert_eq!(err.reason(), "timeout");
        assert!(
            start.elapsed() < Duration::from_millis(timeout_ms),
            "handshake budget must fire well before the outer ceiling"
        );
    }

    #[tokio::test]
    async fn tcp_probe_healthy_loopback_keeps_verdict() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                drop(stream);
            }
        });
        let transport = TcpTransport;
        let start = Instant::now();
        let outcome = transport
            .probe(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
                3000,
                0,
            )
            .await
            .expect("loopback connect must succeed");
        assert!(start.elapsed() < Duration::from_millis(3000));
        assert_eq!((outcome.sent, outcome.received), (1, 1));
        assert_eq!(outcome.colo, None);
    }

    #[tokio::test]
    async fn tcp_probe_refused_keeps_reason() {
        // Port 0 is never valid for connect: the stack rejects it
        // synchronously, so this exercises the real Refused path with no I/O.
        let err = TcpTransport
            .probe(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
                3000,
                0,
            )
            .await
            .expect_err("port 0 must refuse");
        assert!(matches!(err, ProbeError::Refused(_)));
        assert_eq!(err.reason(), "refused");
    }

    #[tokio::test]
    async fn stalled_tls_transport_handshake_fails_fast() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(stream);
                });
            }
        });
        let transport = TlsTransport::new();
        let start = Instant::now();
        let err = transport
            .probe(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
                3000,
                0,
            )
            .await
            .expect_err("black-hole TLS handshake must fail");
        assert_eq!(err, ProbeError::Timeout { timeout_ms: 3000 });
        assert_eq!(err.reason(), "timeout");
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "per-step TLS budget must fire well before the full timeout"
        );
    }

    #[tokio::test]
    async fn stalled_tls_handshake_fails_fast() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(stream);
                });
            }
        });
        let transport = HttpTransport::new(vec![200, 301, 302]);
        let start = Instant::now();
        let err = transport
            .probe(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
                3000,
                0,
            )
            .await
            .expect_err("black-hole TLS handshake must fail");
        assert!(
            matches!(err, crate::probe::ProbeError::Timeout { .. }),
            "stalled handshake must surface as Timeout, got {err:?}"
        );
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "per-step TLS budget must fire well before the full timeout"
        );
    }

    #[test]
    fn find_subsequence_locates_the_header_body_boundary() {
        assert_eq!(
            find_subsequence(b"HTTP/1.1 200 OK\r\n\r\nbody", b"\r\n\r\n"),
            Some(15)
        );
        assert_eq!(find_subsequence(b"no terminator", b"\r\n\r\n"), None);
    }

    #[test]
    fn status_line_parse_accepts_http2_and_reasonless_responses() {
        // HTTP/2 has no reason phrase: "HTTP/2 200".
        assert_eq!(parse_status_line(b"HTTP/2 200"), Some(200));
        assert_eq!(parse_status_line(b"HTTP/1.1 403"), Some(403));
        assert_eq!(parse_status_line(b"HTTP/3 204 no body"), Some(204));
        // Version token alone is not enough.
        assert_eq!(parse_status_line(b"HTTP/2"), None);
    }
}
