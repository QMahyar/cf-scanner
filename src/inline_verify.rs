//! In-process phase-2 tunnel verifier: speaks VLESS and Trojan over
//! plain TCP/TLS directly, replacing the xray subprocess for the wire-
//! simple combos. The probe dials the candidate IP, completes the real
//! protocol handshake (TLS optional, no cert verification — anycast fronting
//! never matches the probed name), then GETs every probe URL through the
//! one tunnel. Fragmenting a TLS ClientHello is not possible with stock
//! rustls, so any fragment preset (including Custom) keeps xray's job; the
//! hybrid router in `verify.rs` decides per combo.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use rustls::pki_types::ServerName;
use sha2::{Digest as _, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::configs::{OutboundSpec, Protocol};
use crate::probe::no_verify_client_config;
use crate::socks;
use crate::verify::{ProbeRequest, TunnelProbe, TunnelResult};

/// Probe-shaped body cap, far below the socks client's 64 MiB reader cap:
/// the verifier only needs a /cdn-cgi/trace-sized body, so a hostile server
/// declaring a huge Content-Length or chunk size must fail the probe instead
/// of forcing a large zeroed allocation per attempt.
const MAX_PROBE_BODY_BYTES: usize = 1024 * 1024;
/// The HTTP head (status + headers) is tiny; anything bigger is a protocol
/// failure, not a real response.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Boxable tunnel stream: plain TCP when `security=none`, rustls when `tls`.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// In-process verifier over one candidate attempt. Holds no state between
/// attempts beyond the TLS connector (the client config is built once).
pub struct InlineTunnelProbe {
    connector: TlsConnector,
}

impl InlineTunnelProbe {
    pub fn new() -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(no_verify_client_config())),
        }
    }
}

impl Default for InlineTunnelProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of a whole multi-URL attempt, mirroring `XrayTunnelProbe`'s
/// contract: a candidate that refused the handshake, timed out, or failed a
/// URL yields `passed: false`; the probe call itself only errors on local
/// failures that should abort the phase.
struct InlineOutcome {
    passed: bool,
    latency_ms: Option<u32>,
    colo: Option<String>,
}

impl TunnelProbe for InlineTunnelProbe {
    fn probe(
        &self,
        req: ProbeRequest<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
        let spec = req.spec.clone();
        let sni = req.sni.map(str::to_owned);
        let probe_urls = req.probe_urls.to_vec();
        let connector = self.connector.clone();
        let ProbeRequest {
            dial_ip,
            timeout_ms,
            ..
        } = req;
        Box::pin(async move {
            // One budget for the WHOLE attempt: handshake + every URL.
            match timeout(
                Duration::from_millis(timeout_ms),
                run_attempt(&connector, &spec, dial_ip, sni.as_deref(), &probe_urls),
            )
            .await
            {
                Ok(InlineOutcome {
                    passed,
                    latency_ms,
                    colo,
                }) => Ok(TunnelResult {
                    passed,
                    latency_ms,
                    colo,
                    verifier: Some("inline"),
                }),
                Err(_) => {
                    tracing::debug!(ip = %dial_ip, "inline probe timed out");
                    Ok(TunnelResult {
                        passed: false,
                        latency_ms: None,
                        colo: None,
                        verifier: Some("inline"),
                    })
                }
            }
        })
    }
}

/// `probe_urls` are verified sequentially over ONE tunnel when they share a
/// target (host, port, scheme): keep-alive GETs, like a browser fetch loop.
/// A stream-level failure tears the tunnel down and retries that URL once on
/// a fresh tunnel; a non-200 status fails the URL without a retry. A pass
/// needs every URL to deliver 200; the colo comes from the first trace body.
async fn run_attempt(
    connector: &TlsConnector,
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni: Option<&str>,
    probe_urls: &[String],
) -> InlineOutcome {
    let started = Instant::now();
    let targets: Vec<Target> = match probe_urls.iter().map(|u| parse_target(u)).collect() {
        Ok(t) => t,
        Err(err) => {
            tracing::debug!(%err, ip = %dial_ip, "inline probe: bad probe URL");
            return InlineOutcome {
                passed: false,
                latency_ms: None,
                colo: None,
            };
        }
    };

    let mut all_ok = true;
    let mut colo = None;
    let mut tunnel: Option<(Target, LiveTunnel)> = None;
    for target in &targets {
        let mut retried = false;
        loop {
            let needs_fresh = tunnel
                .as_ref()
                .is_none_or(|(key, _)| !key.same_target(target));
            if needs_fresh {
                match open_live_tunnel(connector, spec, dial_ip, sni, target).await {
                    Ok(live) => tunnel = Some((target.clone(), live)),
                    Err(err) => {
                        tracing::debug!(%err, ip = %dial_ip, "inline probe: tunnel setup failed");
                        all_ok = false;
                        break;
                    }
                }
            }
            let Some((_, live)) = tunnel.as_mut() else {
                tracing::debug!(ip = %dial_ip, "inline probe: tunnel invariant violated");
                all_ok = false;
                break;
            };
            let Some(stream) = live.stream.take() else {
                tracing::debug!(ip = %dial_ip, "inline probe: tunnel invariant violated");
                all_ok = false;
                break;
            };
            match exchange(stream, &mut live.marker_consumed, spec, target).await {
                Ok((stream, status, body)) => {
                    live.stream = Some(stream);
                    if status == 200 {
                        if colo.is_none() {
                            colo = crate::geo::parse_colo(&body);
                        }
                    } else {
                        all_ok = false;
                    }
                    break;
                }
                Err(err) => {
                    tracing::debug!(%err, ip = %dial_ip, host = %target.host, "inline probe: exchange failed");
                    tunnel = None;
                    if !retried {
                        retried = true;
                        continue;
                    }
                    all_ok = false;
                    break;
                }
            }
        }
    }

    InlineOutcome {
        passed: all_ok,
        latency_ms: all_ok.then(|| started.elapsed().as_millis() as u32),
        colo,
    }
}

/// One probe URL, pre-parsed exactly like the socks client parses it.
#[derive(Clone)]
struct Target {
    host: String,
    port: u16,
    path: String,
    https: bool,
}

impl Target {
    /// Keep-alive only applies to identical targets: the vless/trojan
    /// header fixes the destination for the lifetime of the connection.
    fn same_target(&self, other: &Target) -> bool {
        self.host == other.host && self.port == other.port && self.https == other.https
    }
}

fn parse_target(url: &str) -> Result<Target> {
    let parsed = url::Url::parse(url).context("bad probe URL")?;
    Ok(Target {
        host: parsed
            .host_str()
            .ok_or_else(|| anyhow!("probe URL has no host"))?
            .to_owned(),
        port: parsed.port_or_known_default().unwrap_or(80),
        path: if parsed.path().is_empty() {
            "/".to_owned()
        } else {
            parsed.path().to_owned()
        },
        https: parsed.scheme() == "https",
    })
}

/// A tunneled connection ready for HTTP exchanges: protocol header sent,
/// inner TLS (for https probe targets) up.
struct LiveTunnel {
    stream: Option<Box<dyn AsyncStream>>,
    /// The one-time response marker was consumed already; later responses
    /// on this connection carry no marker.
    marker_consumed: bool,
}

/// Dial the candidate, complete the outer TLS handshake (when the config
/// asks for it), write the vless/trojan request header for `target`, and
/// open the inner TLS connection https targets need (verified against real
/// roots — the tunnel target is the actual probe host, not anycast junk).
async fn open_live_tunnel(
    connector: &TlsConnector,
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni: Option<&str>,
    target: &Target,
) -> Result<LiveTunnel> {
    let mut stream = establish(connector, spec, dial_ip, sni).await?;
    let header = build_protocol_header(spec, &target.host, target.port)?;
    stream.write_all(&header).await?;
    if target.https {
        let name = ServerName::try_from(target.host.clone())
            .context("probe host is not a valid TLS name")?;
        stream = Box::new(
            socks::tls_connector()
                .connect(name, stream)
                .await
                .context("inner TLS handshake to the probe target")?,
        );
    }
    Ok(LiveTunnel {
        stream: Some(stream),
        marker_consumed: false,
    })
}

/// TCP connect plus the outer TLS handshake when `security=tls`. The SNI is
/// the phase-2 combo's SNI when present, else the config's own server name,
/// else none (connecting without SNI is safe because verification is off).
async fn establish(
    connector: &TlsConnector,
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni: Option<&str>,
) -> Result<Box<dyn AsyncStream>> {
    let tcp = TcpStream::connect((dial_ip, spec.port))
        .await
        .context("tcp connect to candidate")?;
    if spec.security.eq_ignore_ascii_case("tls") {
        let name = outer_server_name(sni, spec.tls_server_name.as_deref(), dial_ip);
        let tls = connector
            .connect(name, tcp)
            .await
            .context("outer TLS handshake to candidate")?;
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

fn outer_server_name(
    sni: Option<&str>,
    spec_sni: Option<&str>,
    dial_ip: Ipv4Addr,
) -> ServerName<'static> {
    sni.or(spec_sni)
        .and_then(|name| ServerName::try_from(name.to_owned()).ok())
        .unwrap_or_else(|| ServerName::IpAddress(dial_ip.into()))
}

/// Bytes the client sends before the payload: the vless header is
/// `[ver 0][uuid 16][addons_len 0][cmd 1][port BE][atyp][addr]` (xray's
/// `PortThenAddress` order); trojan is `hex(SHA224(password)) \r\n
/// [cmd 1][atyp][addr][port BE] \r\n` per the official spec — the password
/// never rides the wire raw.
fn build_protocol_header(spec: &OutboundSpec, host: &str, port: u16) -> Result<Vec<u8>> {
    match spec.protocol {
        Protocol::Trojan => {
            let hash: String = Sha224::digest(spec.user_id.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let mut out = Vec::with_capacity(56 + 2 + 1 + 1 + host.len() + 2 + 2);
            out.extend_from_slice(hash.as_bytes());
            out.extend_from_slice(b"\r\n");
            out.push(0x01); // CONNECT
            write_socks5_addr(&mut out, host)?;
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(b"\r\n");
            Ok(out)
        }
        Protocol::Vless => {
            let uuid =
                parse_uuid(&spec.user_id).ok_or_else(|| anyhow!("vless user id is not a UUID"))?;
            let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + host.len());
            out.push(0x00); // protocol version
            out.extend_from_slice(&uuid);
            out.push(0x00); // addons length
            out.push(0x01); // TCP command
            out.extend_from_slice(&port.to_be_bytes());
            write_xray_addr(&mut out, host)?;
            Ok(out)
        }
        _ => bail!("inline probe cannot build a header for {:?}", spec.protocol),
    }
}

/// SOCKS5-style address (trojan): 1 = IPv4, 3 = domain+len, 4 = IPv6.
fn write_socks5_addr(out: &mut Vec<u8>, host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        out.push(0x04);
        out.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            bail!("probe host too long for a domain address");
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

/// Xray address atom (vless): 1 = IPv4, 2 = domain+len, 3 = IPv6.
fn write_xray_addr(out: &mut Vec<u8>, host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        out.push(0x03);
        out.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            bail!("probe host too long for a domain address");
        }
        out.push(0x02);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

/// Sends one GET through the tunnel and parses the response, consuming the
/// one-time protocol marker on the first exchange. `Err` means the
/// connection died (the caller re-establishes once and retries).
async fn exchange(
    mut stream: Box<dyn AsyncStream>,
    marker_consumed: &mut bool,
    spec: &OutboundSpec,
    target: &Target,
) -> Result<(Box<dyn AsyncStream>, u16, Vec<u8>)> {
    let request = socks::http_request_keepalive(&target.host, &target.path, "Accept: */*");
    stream.write_all(request.as_bytes()).await?;
    let mut stream = if *marker_consumed {
        stream
    } else {
        *marker_consumed = true;
        read_response_marker(stream, spec.protocol).await?
    };
    let (status, body) = read_http_response(&mut *stream).await?;
    Ok((stream, status, body))
}

/// Consumes the marker a server prepends to the FIRST response: vless
/// always sends `[version][addons_len][addons]` (xray sends `00 00`), and
/// some trojan implementations send a legacy `\r\n\x00` ack — xray itself
/// relays the origin's bytes raw. Bytes that turn out to be HTTP data are
/// replayed so the HTTP parser sees the raw response either way.
async fn read_response_marker(
    mut stream: Box<dyn AsyncStream>,
    protocol: Protocol,
) -> Result<Box<dyn AsyncStream>> {
    match protocol {
        Protocol::Vless => {
            let mut first = [0u8; 1];
            stream.read_exact(&mut first).await?;
            if first[0] != 0 {
                return Ok(Box::new(PrefixedReader::new(first.to_vec(), stream)));
            }
            let mut addons_len = [0u8; 1];
            stream.read_exact(&mut addons_len).await?;
            if addons_len[0] > 0 {
                let mut addons = vec![0u8; addons_len[0] as usize];
                stream.read_exact(&mut addons).await?;
            }
            Ok(stream)
        }
        Protocol::Trojan => {
            let mut peek = [0u8; 3];
            stream.read_exact(&mut peek).await?;
            if peek == *b"\r\n\x00" {
                Ok(stream)
            } else {
                Ok(Box::new(PrefixedReader::new(peek.to_vec(), stream)))
            }
        }
        _ => bail!("inline probe cannot read a marker for {protocol:?}"),
    }
}

/// Yields `prefix` before delegating to `inner`, so a peek that turned out
/// to be HTTP data is never lost.
struct PrefixedReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.pos);
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for PrefixedReader<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Parses one HTTP/1.1 response off a keep-alive stream: the head, then the
/// body sized by Content-Length / chunked / close-delimited. The xray path's
/// `send_http` cannot serve here — it reads to EOF, which never comes on a
/// connection that must survive the next URL.
async fn read_http_response<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> Result<(u16, Vec<u8>)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEADER_BYTES {
            bail!("response headers exceed the {MAX_HEADER_BYTES} cap");
        }
        stream
            .read_exact(&mut byte)
            .await
            .context("reading response headers")?;
        head.push(byte[0]);
    }
    let head = std::str::from_utf8(&head).context("response headers are not utf-8")?;
    let mut lines = head.lines();
    let status_line = lines.next().context("empty HTTP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed status line")?;
    let headers: Vec<String> = lines.map(str::to_owned).collect();
    let body = read_http_body(stream, &headers).await?;
    Ok((status, body))
}

async fn read_http_body<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    headers: &[String],
) -> Result<Vec<u8>> {
    let contains = |needle: &str| {
        headers
            .iter()
            .any(|h| h.to_ascii_lowercase().contains(needle))
    };
    if contains("transfer-encoding: chunked") {
        // Reassemble the raw chunked stream and hand it to the shared
        // decoder (bounded, proptested) instead of duplicating the grammar.
        let mut raw = Vec::new();
        loop {
            let size_line = read_line(stream, 256).await.context("reading chunk size")?;
            let text = std::str::from_utf8(&size_line).context("chunk size not utf-8")?;
            let size = usize::from_str_radix(text.split(';').next().unwrap_or("").trim(), 16)
                .context("malformed chunk size")?;
            if size == 0 {
                // Trailers up to the blank line.
                loop {
                    let line = read_line(stream, 4096).await?;
                    if line.is_empty() {
                        break;
                    }
                }
                raw.extend_from_slice(b"0\r\n\r\n");
                break;
            }
            if size > MAX_PROBE_BODY_BYTES.saturating_sub(raw.len()) {
                bail!("chunked body exceeds the {MAX_PROBE_BODY_BYTES} cap");
            }
            raw.extend_from_slice(format!("{size:x}\r\n").as_bytes());
            let mut data = vec![0u8; size];
            stream
                .read_exact(&mut data)
                .await
                .context("reading chunk data")?;
            raw.extend_from_slice(&data);
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await?;
            if crlf != *b"\r\n" {
                bail!("malformed chunk terminator");
            }
            raw.extend_from_slice(b"\r\n");
        }
        socks::decode_chunked(&raw)
    } else if let Some(cl) = headers
        .iter()
        .find(|h| h.to_ascii_lowercase().starts_with("content-length:"))
    {
        let n: usize = cl
            .split(':')
            .nth(1)
            .and_then(|s| s.trim().parse().ok())
            .context("malformed content-length")?;
        if n > MAX_PROBE_BODY_BYTES {
            bail!("response body exceeds the {MAX_PROBE_BODY_BYTES} cap");
        }
        let mut body = vec![0u8; n];
        stream
            .read_exact(&mut body)
            .await
            .context("reading content-length body")?;
        Ok(body)
    } else {
        // No framing: the connection closes the response.
        let mut body = Vec::new();
        stream
            .take(MAX_PROBE_BODY_BYTES as u64)
            .read_to_end(&mut body)
            .await
            .context("reading close-delimited body")?;
        Ok(body)
    }
}

/// Reads one CRLF-terminated line (the CRLF stripped), capped so a hostile
/// server cannot feed an unbounded line.
async fn read_line<S: AsyncRead + Unpin + ?Sized>(stream: &mut S, cap: usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= cap {
            bail!("line exceeds the {cap} cap");
        }
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
}

/// Parses a UUID string (dashes optional) into its 16 raw bytes, as VLESS
/// carries them on the wire. Shared with the hybrid router, which only
/// routes vless combos whose id parses.
pub(crate) fn parse_uuid(user_id: &str) -> Option<[u8; 16]> {
    let mut hex = String::with_capacity(32);
    for c in user_id.chars() {
        if c != '-' {
            hex.push(c);
        }
    }
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::parse_uri;
    use crate::verify::HybridTunnelProbe;
    use base64::Engine as _;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex};

    /// One fake server run: which credential the client actually sent (trojan:
    /// the 56-char hash; vless: the uuid hex) and how many TCP connections it
    /// accepted (keep-alive assertions live on the count staying at 1). The
    /// runtime is held so its worker threads keep driving the accept/serve
    /// tasks for the whole test (a dropped runtime would cancel them).
    struct FakeServer {
        addr: SocketAddr,
        sent_cred: Arc<Mutex<Option<String>>>,
        connections: Arc<AtomicUsize>,
        _rt: tokio::runtime::Runtime,
    }

    #[derive(Clone, Copy)]
    enum ServerBehavior {
        /// Every request answered 200 with a trace body.
        Pass,
        /// First request 200, second 403 (multi-URL failure path).
        First200Then403,
        /// Credential mismatch: close without a response.
        Reject,
        /// Sleep past any reasonable probe timeout.
        Stall,
        /// The legacy `\r\n\x00` trojan ack precedes the HTTP response.
        AcknowledgeThenPass,
        /// No vless response header (worker-style endpoints).
        NoVlessHeader,
    }

    /// Single shared test certificate (one rcgen generation, one rustls
    /// server config for every connection).
    static TLS_SERVER_CONFIG: LazyLock<rustls::ServerConfig> = LazyLock::new(|| {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        rustls::ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(certified.key_pair.serialize_der())
                    .expect("test key must be a pkcs8 private key"),
            )
            .expect("test cert/key must form a valid server config")
    });

    fn spawn_fake_server(
        protocol: Protocol,
        use_tls: bool,
        behavior: ServerBehavior,
    ) -> FakeServer {
        // Multi-thread: the accept/serve tasks must keep running while the
        // test drives the probe on its own current-thread runtime.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test server runtime");
        let (addr, sent_cred, connections) = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let sent_cred: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let connections = Arc::new(AtomicUsize::new(0));
            let sent_cred_task = sent_cred.clone();
            let connections_task = connections.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    connections_task.fetch_add(1, Ordering::SeqCst);
                    let sent_cred = sent_cred_task.clone();
                    tokio::spawn(async move {
                        let _ = serve_one(tcp, protocol, use_tls, behavior, sent_cred).await;
                    });
                }
            });
            (addr, sent_cred, connections)
        });
        FakeServer {
            addr,
            sent_cred,
            connections,
            _rt: rt,
        }
    }

    async fn serve_one(
        tcp: TcpStream,
        protocol: Protocol,
        use_tls: bool,
        behavior: ServerBehavior,
        sent_cred: Arc<Mutex<Option<String>>>,
    ) -> Result<()> {
        let mut conn: Box<dyn AsyncStream> = if use_tls {
            Box::new(
                tokio_rustls::TlsAcceptor::from(Arc::new(TLS_SERVER_CONFIG.clone()))
                    .accept(tcp)
                    .await
                    .context("test server tls handshake")?,
            )
        } else {
            Box::new(tcp)
        };
        let cred = read_client_header(&mut *conn, protocol).await?;
        *sent_cred.lock().unwrap_or_else(|e| e.into_inner()) = Some(cred);
        if matches!(behavior, ServerBehavior::Reject) {
            // Leave the connection unresponsive: the client must fail on EOF.
            return Ok(());
        }
        if matches!(behavior, ServerBehavior::Stall) {
            tokio::time::sleep(Duration::from_secs(10)).await;
            return Ok(());
        }
        if protocol == Protocol::Vless && !matches!(behavior, ServerBehavior::NoVlessHeader) {
            conn.write_all(b"\x00\x00").await?;
        }
        if protocol == Protocol::Trojan && matches!(behavior, ServerBehavior::AcknowledgeThenPass) {
            conn.write_all(b"\r\n\x00").await?;
        }
        let mut served = 0u32;
        loop {
            read_http_request(&mut *conn).await?; // Err = client closed: done
            let (status, body): (u16, &[u8]) = match behavior {
                ServerBehavior::First200Then403 if served >= 1 => (403, b"no"),
                _ => (200, b"ip=1.2.3.4\ncolo=AMS"),
            };
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                body.len()
            );
            conn.write_all(resp.as_bytes()).await?;
            conn.write_all(body).await?;
            served += 1;
        }
    }

    /// Server side of the vless/trojan client header: returns the credential
    /// the client sent (`hex(hash)` for trojan, hex uuid for vless).
    async fn read_client_header(conn: &mut dyn AsyncStream, protocol: Protocol) -> Result<String> {
        match protocol {
            Protocol::Trojan => {
                let mut hash = [0u8; 56];
                conn.read_exact(&mut hash).await?;
                let mut crlf = [0u8; 2];
                conn.read_exact(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    bail!("bad trojan hash crlf");
                }
                let mut cmd = [0u8; 1];
                conn.read_exact(&mut cmd).await?;
                if cmd[0] != 0x01 {
                    bail!("bad trojan command");
                }
                let mut atyp = [0u8; 1];
                conn.read_exact(&mut atyp).await?;
                read_socks_addr(conn, atyp[0]).await?;
                let mut port = [0u8; 2];
                conn.read_exact(&mut port).await?;
                let mut crlf = [0u8; 2];
                conn.read_exact(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    bail!("bad trojan tail crlf");
                }
                Ok(String::from_utf8(hash.to_vec()).expect("hash is hex"))
            }
            Protocol::Vless => {
                let mut ver = [0u8; 1];
                conn.read_exact(&mut ver).await?;
                let mut uuid = [0u8; 16];
                conn.read_exact(&mut uuid).await?;
                let mut addons_len = [0u8; 1];
                conn.read_exact(&mut addons_len).await?;
                if addons_len[0] > 0 {
                    let mut addons = vec![0u8; addons_len[0] as usize];
                    conn.read_exact(&mut addons).await?;
                }
                let mut cmd = [0u8; 1];
                conn.read_exact(&mut cmd).await?;
                if cmd[0] != 0x01 {
                    bail!("bad vless command");
                }
                let mut port = [0u8; 2];
                conn.read_exact(&mut port).await?;
                let mut atyp = [0u8; 1];
                conn.read_exact(&mut atyp).await?;
                read_xray_addr(conn, atyp[0]).await?;
                Ok(uuid.iter().map(|b| format!("{b:02x}")).collect())
            }
            _ => bail!("unsupported test protocol"),
        }
    }

    async fn read_socks_addr(conn: &mut dyn AsyncStream, atyp: u8) -> Result<()> {
        match atyp {
            0x01 => conn.read_exact(&mut [0u8; 4]).await.map(|_| ())?,
            0x04 => conn.read_exact(&mut [0u8; 16]).await.map(|_| ())?,
            0x03 => {
                let mut len = [0u8; 1];
                conn.read_exact(&mut len).await?;
                let mut addr = vec![0u8; len[0] as usize];
                conn.read_exact(&mut addr).await?;
            }
            _ => bail!("unknown trojan address type {atyp}"),
        }
        Ok(())
    }

    async fn read_xray_addr(conn: &mut dyn AsyncStream, atyp: u8) -> Result<()> {
        match atyp {
            0x01 => conn.read_exact(&mut [0u8; 4]).await.map(|_| ())?,
            0x03 => conn.read_exact(&mut [0u8; 16]).await.map(|_| ())?,
            0x02 => {
                let mut len = [0u8; 1];
                conn.read_exact(&mut len).await?;
                let mut addr = vec![0u8; len[0] as usize];
                conn.read_exact(&mut addr).await?;
            }
            _ => bail!("unknown vless address type {atyp}"),
        }
        Ok(())
    }

    async fn read_http_request(conn: &mut dyn AsyncStream) -> Result<()> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            conn.read_exact(&mut byte).await?;
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                return Ok(());
            }
            if bytes.len() > 64 * 1024 {
                bail!("request head too large");
            }
        }
    }

    const VLESS_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000";
    const TROJAN_PASSWORD: &str = "hunter2-secret";

    fn trojan_hash(password: &str) -> String {
        Sha224::digest(password.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn probe(spec: OutboundSpec, ports: &[&str], timeout_ms: u64) -> TunnelResult {
        let probe = InlineTunnelProbe::new();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                probe
                    .probe(ProbeRequest {
                        spec: &spec,
                        dial_ip: "127.0.0.1".parse().unwrap(),
                        preset: &crate::api::types::FragmentPreset::Off,
                        custom: None,
                        sni: None,
                        probe_urls: &ports.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                        timeout_ms,
                    })
                    .await
                    .expect("inline probe never errors")
            })
    }

    #[test]
    fn trojan_tls_pass_extracts_colo() {
        let server = spawn_fake_server(Protocol::Trojan, true, ServerBehavior::Pass);
        let mut spec = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=tls"
        ))
        .unwrap();
        spec.port = server.addr.port();
        let result = probe(spec, &["http://probe.test/trace"], 2_000);
        assert!(result.passed, "{result:?}");
        assert_eq!(result.verifier, Some("inline"));
        assert_eq!(result.colo.as_deref(), Some("AMS"));
        assert!(
            result.latency_ms.is_some(),
            "a pass must carry the attempt latency"
        );
        let sent = server.sent_cred.lock().unwrap().clone();
        assert_eq!(
            sent.as_deref(),
            Some(trojan_hash(TROJAN_PASSWORD).as_str()),
            "the client must send hex(SHA224(password)), never the raw password"
        );
    }

    #[test]
    fn vless_tls_pass() {
        let server = spawn_fake_server(Protocol::Vless, true, ServerBehavior::Pass);
        let mut spec = parse_uri(&format!(
            "vless://{VLESS_UUID}@127.0.0.1:443?security=tls&sni=example.com"
        ))
        .unwrap();
        spec.port = server.addr.port();
        let result = probe(spec, &["http://probe.test/trace"], 2_000);
        assert!(result.passed, "{result:?}");
        assert!(result.colo.is_some());
        assert_eq!(result.verifier, Some("inline"));
        let sent = server.sent_cred.lock().unwrap().clone();
        assert_eq!(sent.as_deref(), Some(VLESS_UUID.replace('-', "").as_str()));
    }

    #[test]
    fn wrong_trojan_password_fails() {
        let server = spawn_fake_server(Protocol::Trojan, true, ServerBehavior::Reject);
        let mut spec = parse_uri("trojan://wrong-password@127.0.0.1:443?security=tls").unwrap();
        spec.port = server.addr.port();
        let result = probe(spec, &["http://probe.test/trace"], 2_000);
        assert!(!result.passed, "{result:?}");
        assert_eq!(result.latency_ms, None);
        let sent = server.sent_cred.lock().unwrap().clone();
        assert_eq!(
            sent.as_deref(),
            Some(trojan_hash("wrong-password").as_str())
        );
    }

    #[test]
    fn vless_security_none_is_plain_tcp() {
        let server = spawn_fake_server(Protocol::Vless, false, ServerBehavior::Pass);
        let mut spec =
            parse_uri(&format!("vless://{VLESS_UUID}@127.0.0.1:443?security=none")).unwrap();
        spec.port = server.addr.port();
        assert!(probe(spec, &["http://probe.test/x"], 2_000).passed);
    }

    #[test]
    fn trojan_legacy_ack_prefix_is_skipped() {
        let server = spawn_fake_server(Protocol::Trojan, true, ServerBehavior::AcknowledgeThenPass);
        let mut spec = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=tls"
        ))
        .unwrap();
        spec.port = server.addr.port();
        let result = probe(spec, &["http://probe.test/x"], 2_000);
        assert!(
            result.passed,
            "the legacy `\\r\\n\\x00` ack must be skipped: {result:?}"
        );
    }

    #[test]
    fn vless_response_without_header_prefix_passes() {
        // Worker-style endpoints relay the origin's bytes without xray's
        // `[version][addons]` response header; the HTTP data must be replayed.
        let server = spawn_fake_server(Protocol::Vless, true, ServerBehavior::NoVlessHeader);
        let mut spec = parse_uri(&format!(
            "vless://{VLESS_UUID}@127.0.0.1:443?security=tls&sni=example.com"
        ))
        .unwrap();
        spec.port = server.addr.port();
        assert!(probe(spec, &["http://probe.test/x"], 2_000).passed);
    }

    #[test]
    fn multi_url_all_200_passes_on_one_tunnel() {
        let server = spawn_fake_server(Protocol::Vless, true, ServerBehavior::Pass);
        let mut spec =
            parse_uri(&format!("vless://{VLESS_UUID}@127.0.0.1:443?security=tls")).unwrap();
        spec.port = server.addr.port();
        let result = probe(
            spec,
            &["http://probe.test/one", "http://probe.test/two"],
            2_000,
        );
        assert!(result.passed, "{result:?}");
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            1,
            "two URLs on one target must share one tunnel (keep-alive)"
        );
    }

    #[test]
    fn multi_url_one_403_fails_the_candidate() {
        let server = spawn_fake_server(Protocol::Trojan, true, ServerBehavior::First200Then403);
        let mut spec = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=tls"
        ))
        .unwrap();
        spec.port = server.addr.port();
        let result = probe(
            spec,
            &["http://probe.test/one", "http://probe.test/two"],
            2_000,
        );
        assert!(!result.passed, "a 403 on any URL must fail the candidate");
        assert_eq!(result.verifier, Some("inline"));
    }

    #[test]
    fn timeout_is_a_failed_verdict_not_an_error() {
        let server = spawn_fake_server(Protocol::Trojan, true, ServerBehavior::Stall);
        let mut spec = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=tls"
        ))
        .unwrap();
        spec.port = server.addr.port();
        let result = probe(spec, &["http://probe.test/x"], 150);
        assert!(!result.passed);
        assert_eq!(result.latency_ms, None);
    }

    #[test]
    fn refused_connection_is_a_failed_verdict() {
        // Grab a port and release it: connecting there is refused.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut spec = parse_uri(&format!(
            "vless://{VLESS_UUID}@127.0.0.1:{port}?security=none"
        ))
        .unwrap();
        spec.port = port;
        let result = probe(spec, &["http://probe.test/x"], 2_000);
        assert!(!result.passed);
        assert_eq!(result.verifier, Some("inline"));
    }

    #[test]
    fn parse_uuid_accepts_dashes_and_plain_hex() {
        assert_eq!(
            parse_uuid(VLESS_UUID),
            Some([
                0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xff, 0xff,
                0x00, 0x00
            ])
        );
        assert_eq!(
            parse_uuid(&VLESS_UUID.replace('-', "")),
            parse_uuid(VLESS_UUID)
        );
        for bad in [
            "",
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
            "not-a-uuid",
            "abcd",
        ] {
            assert!(parse_uuid(bad).is_none(), "{bad:?}");
        }
    }

    /// Routing: combos the inline verifier cannot serve must fall through to
    /// the xray probe (observed via a recording stand-in); servable combos
    /// must never touch it.
    #[derive(Clone)]
    struct RecordingProbe {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingProbe {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn observed(&self) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl TunnelProbe for RecordingProbe {
        fn probe(
            &self,
            req: ProbeRequest<'_>,
        ) -> Pin<Box<dyn Future<Output = Result<TunnelResult>> + Send + '_>> {
            let calls = self.calls.clone();
            let proto = req.spec.protocol.as_str().to_owned();
            Box::pin(async move {
                calls.lock().unwrap_or_else(|e| e.into_inner()).push(proto);
                Ok(TunnelResult {
                    passed: false,
                    latency_ms: None,
                    colo: None,
                    verifier: Some("xray"),
                })
            })
        }
    }

    struct HybridHarness {
        hybrid: HybridTunnelProbe,
        xray: RecordingProbe,
    }

    impl HybridHarness {
        fn new() -> Self {
            let xray = RecordingProbe::new();
            let hybrid = HybridTunnelProbe::new(Arc::new(xray.clone()));
            Self { hybrid, xray }
        }

        fn result(
            &self,
            spec: OutboundSpec,
            preset: crate::api::types::FragmentPreset,
        ) -> TunnelResult {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    self.hybrid
                        .probe(ProbeRequest {
                            spec: &spec,
                            dial_ip: "127.0.0.1".parse().unwrap(),
                            preset: &preset,
                            custom: None,
                            sni: None,
                            probe_urls: &["http://probe.test/x".to_owned()],
                            timeout_ms: 250,
                        })
                        .await
                        .unwrap()
                })
        }

        fn result_with_custom(
            &self,
            spec: OutboundSpec,
            custom: crate::api::types::CustomFragment,
        ) -> TunnelResult {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    self.hybrid
                        .probe(ProbeRequest {
                            spec: &spec,
                            dial_ip: "127.0.0.1".parse().unwrap(),
                            preset: &crate::api::types::FragmentPreset::Custom,
                            custom: Some(&custom),
                            sni: None,
                            probe_urls: &["http://probe.test/x".to_owned()],
                            timeout_ms: 250,
                        })
                        .await
                        .unwrap()
                })
        }
    }

    fn vless_uri(extra: &str) -> OutboundSpec {
        parse_uri(&format!(
            "vless://{VLESS_UUID}@127.0.0.1:443?security=tls{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn hybrid_routes_ws_to_xray() {
        let harness = HybridHarness::new();
        let spec = vless_uri("&type=ws&path=/");
        let result = harness.result(spec.clone(), crate::api::types::FragmentPreset::Off);
        assert_eq!(harness.xray.observed(), vec!["vless"], "ws must use xray");
        assert_eq!(
            result.verifier,
            Some("xray"),
            "the xray result must pass through"
        );
    }

    #[test]
    fn hybrid_routes_fragment_presets_and_custom_to_xray() {
        let harness = HybridHarness::new();
        for preset in [
            crate::api::types::FragmentPreset::Light,
            crate::api::types::FragmentPreset::Medium,
            crate::api::types::FragmentPreset::Heavy,
        ] {
            harness.result(vless_uri(""), preset);
        }
        assert_eq!(
            harness.xray.observed().len(),
            3,
            "fragmenting a TLS ClientHello is xray's job"
        );
        let harness = HybridHarness::new();
        harness.result_with_custom(
            vless_uri(""),
            crate::api::types::CustomFragment {
                packets: "tlshello".to_owned(),
                length: "100-200".to_owned(),
                interval: "10-20".to_owned(),
            },
        );
        assert_eq!(
            harness.xray.observed(),
            vec!["vless"],
            "custom fragment must use xray"
        );
    }

    #[test]
    fn hybrid_routes_vmess_and_bad_uuid_to_xray() {
        let harness = HybridHarness::new();
        let vmess = parse_uri(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(
                r#"{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"tcp","tls":"none"}"#
            )
        ))
        .unwrap();
        harness.result(vmess, crate::api::types::FragmentPreset::Off);
        let bad_uuid = parse_uri("vless://not-a-uuid@127.0.0.1:443?security=tls").unwrap();
        let result = harness.result(bad_uuid, crate::api::types::FragmentPreset::Off);
        assert_eq!(
            harness.xray.observed(),
            vec!["vmess", "vless"],
            "vmess and unparseable-UUID vless must use xray"
        );
        assert_eq!(result.verifier, Some("xray"));
    }

    #[test]
    fn hybrid_routes_plain_vless_and_trojan_to_inline() {
        let harness = HybridHarness::new();
        let vless = vless_uri("");
        let result = harness.result(vless, crate::api::types::FragmentPreset::Off);
        assert!(
            harness.xray.observed().is_empty(),
            "plain vless with fragmentation off must never spawn xray"
        );
        assert_eq!(result.verifier, Some("inline"));
        let trojan = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=none"
        ))
        .unwrap();
        let result = harness.result(trojan, crate::api::types::FragmentPreset::Off);
        assert_eq!(result.verifier, Some("inline"));
        assert!(harness.xray.observed().is_empty());
    }

    #[test]
    fn supports_inline_matrix() {
        use crate::api::types::FragmentPreset as P;
        let ok = |spec: OutboundSpec, preset: P| {
            HybridTunnelProbe::supports_inline(&spec, &preset, None)
        };
        assert!(ok(vless_uri(""), P::Off));
        let trojan = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=tls"
        ))
        .unwrap();
        assert!(ok(trojan, P::Off));
        let trojan_none = parse_uri(&format!(
            "trojan://{TROJAN_PASSWORD}@127.0.0.1:443?security=none"
        ))
        .unwrap();
        assert!(ok(trojan_none, P::Off));
        assert!(!ok(vless_uri("&type=ws&path=/"), P::Off));
        assert!(!ok(vless_uri(""), P::Light));
        let ss = parse_uri(&format!(
            "ss://{}@1.2.3.4:8388",
            base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:p")
        ))
        .unwrap();
        assert!(!ok(ss, P::Off), "shadowsocks is xray's job");
        assert!(!ok(
            parse_uri("vless://not-a-uuid@127.0.0.1:443?security=tls").unwrap(),
            P::Off
        ));
    }
}
