//! Minimal SOCKS5 (no-auth) HTTP GET client: CONNECT through a socks
//! inbound, then the same TLS+HTTP GET leg as a direct fetch. Used for the
//! phase-2 tunnel probes (verify.rs); not a general-purpose client.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) fn http_request(host: &str, path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\nConnection: close\r\n\r\n")
}

/// Sends `request` over the stream and parses the reply: status line,
/// headers, and body (chunked transfer decoding applied). The body is capped
/// at [`MAX_BODY_BYTES`] so untrusted responses can't exhaust memory.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Same shape as [`http_request`] but without `Connection: close`, so one
/// tunneled connection can serve several probe URLs (the inline verifier's
/// keep-alive multi-URL loop). `http_request` itself stays close-delimited
/// for the socks path, whose reader drains to EOF.
pub(crate) fn http_request_keepalive(host: &str, path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n\r\n")
}

pub(crate) async fn send_http<S>(stream: S, request: &str) -> Result<(u16, Vec<String>, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    wr.write_all(request.as_bytes()).await?;

    let bytes: Vec<u8> = {
        let mut buf = Vec::new();
        let mut rd = rd.take(MAX_BODY_BYTES as u64 + 64 * 1024);
        let mut chunk = [0u8; 8192];
        loop {
            match rd.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                // HTTP/1.1 `Connection: close` ends the body at EOF; some
                // servers (and every tunneled hop that drops TLS close_notify,
                // e.g. Cloudflare Workers proxying) close without the TLS
                // goodbye. rustls reports that as UnexpectedEof; keep the
                // bytes already delivered instead of failing the fetch.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).context("failed reading HTTP response"),
            }
        }
        buf
    };
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let (head, body) = bytes.split_at(split);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();
    let status_line = lines.next().context("empty HTTP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed status line")?;
    let headers: Vec<String> = lines.map(str::to_owned).collect();
    let body = body[4..].to_vec();
    let body = if headers.iter().any(|h| {
        h.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    }) {
        decode_chunked(&body)?
    } else {
        body
    };
    Ok((status, headers, body))
}

/// Minimal HTTP/1.1 chunked decoder: `size\r\n data \r\n ... 0\r\n\r\n`.
pub(crate) fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("truncated chunk size line")?;
        let size_str = std::str::from_utf8(&input[..line_end])
            .context("chunk size line not utf-8")?
            .split(';')
            .next()
            .unwrap_or("");
        let size = usize::from_str_radix(size_str.trim(), 16).context("malformed chunk size")?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_BODY_BYTES - out.len() {
            bail!("chunked body exceeds the {MAX_BODY_BYTES} cap");
        }
        if input.len() < size + 2 {
            bail!("truncated chunk data");
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

pub(crate) fn tls_connector() -> tokio_rustls::TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

/// Phase-2 tunnel probe: SOCKS5 (no-auth) CONNECT to `url`'s host through the
/// socks inbound, then the same TLS+HTTP GET leg as a direct fetch. `Err`
/// means the tunnel did not deliver a 200.
pub async fn get_via_socks(url: &str, socks: SocketAddr, timeout_ms: u64) -> Result<Vec<u8>> {
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        get_via_socks_inner(url, socks),
    )
    .await
    .context("tunnel probe timed out")?
}

async fn get_via_socks_inner(url: &str, socks: SocketAddr) -> Result<Vec<u8>> {
    let parsed = url::Url::parse(url).context("bad probe URL")?;
    let use_tls = parsed.scheme() == "https";
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("probe URL has no host"))?
        .to_owned();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };

    let mut stream = TcpStream::connect(socks).await?;
    socks5_connect(&mut stream, &host, port).await?;
    let request = http_request(&host, &path, "Accept: */*");
    let (status, _, body) = if use_tls {
        let server_name =
            rustls::pki_types::ServerName::try_from(host).context("invalid hostname")?;
        let tls = tls_connector().connect(server_name, stream).await?;
        send_http(tls, &request).await?
    } else {
        send_http(stream, &request).await?
    };
    if status != 200 {
        bail!("tunnel probe got HTTP {status}");
    }
    Ok(body)
}

/// RFC 1928 no-auth handshake with a domain-based CONNECT.
async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        bail!("socks server refused no-auth: {method:02x?}");
    }
    let host = host.as_bytes();
    if host.len() > 255 {
        bail!("socks host too long");
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        bail!("socks CONNECT failed: {head:02x?}");
    }
    let addr_len = match head[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        0x04 => 16 + 2,
        other => bail!("socks reply has unknown addr type {other}"),
    };
    let mut rest = vec![0u8; addr_len];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays a minimal no-auth socks server that answers CONNECT and serves
    /// one `200 OK` body — enough to prove the client's wire format.
    async fn fake_socks_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                sock.read_exact(&mut byte).await.unwrap();
                req.push(byte[0]);
                if req.len() >= 5 && req[3] == 0x03 && req.len() >= 5 + req[4] as usize + 2 {
                    break;
                }
            }
            // VER REP RSV ATYP BND.ADDR BND.PORT (127.0.0.1:0)
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut http = Vec::new();
            while !http.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                sock.read_exact(&mut byte).await.unwrap();
                http.push(byte[0]);
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn tunnel_probe_gets_http_through_fake_socks() {
        let socks = fake_socks_server().await;
        let body = get_via_socks("http://example.test/check", socks, 5_000)
            .await
            .unwrap();
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn tunnel_probe_times_out_when_socks_never_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept the greeting and then stay silent: the client must give up.
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 3];
                let _ = sock.read_exact(&mut buf).await;
                let _ = tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let err = get_via_socks("http://example.test/", socks, 50)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    // --- decode_chunked bounds (review r6) -----------------------------------

    /// Chunk-encodes `data` (one or two chunks) the way real chunked
    /// responses do: `size\r\n data \r\n ... 0\r\n\r\n`.
    fn encode_chunked(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return b"0\r\n\r\n".to_vec();
        }
        let mut out = Vec::new();
        for chunk in [&data[..data.len() / 2], &data[data.len() / 2..]] {
            if chunk.is_empty() {
                continue;
            }
            out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            out.extend_from_slice(chunk);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    #[test]
    fn decode_chunked_empty_input_and_terminal_chunk() {
        // Empty input has no CRLF-terminated size line: the decoder must
        // reject it, not loop or panic (matches its actual semantics).
        assert!(decode_chunked(b"").is_err());
        // A lone terminal chunk decodes to nothing.
        assert_eq!(decode_chunked(b"0\r\n").unwrap(), b"");
        assert_eq!(decode_chunked(b"0\r\n\r\n").unwrap(), b"");
    }

    #[test]
    fn decode_chunked_single_chunk_and_concatenated_chunks() {
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"hello world");
        // Chunk-size extensions (`;ext`) and uneven chunk lengths are legal.
        assert_eq!(
            decode_chunked(b"5;ext=1\r\nhello\r\n0\r\n").unwrap(),
            b"hello"
        );
        assert_eq!(
            decode_chunked(b"1\r\na\r\n2\r\nbc\r\n0\r\n").unwrap(),
            b"abc"
        );
    }

    #[test]
    fn decode_chunked_rejects_huge_sizes_without_allocating() {
        // 0xffffffff overflows the 64 MiB cap on the FIRST chunk: the size
        // check runs before any buffer growth.
        assert!(decode_chunked(b"ffffffff\r\n").is_err());
        // A huge size mid-stream is rejected after the earlier chunks decode.
        assert!(decode_chunked(b"1\r\na\r\nffffffff\r\n").is_err());
        // A size that would cross the cap only when accumulated is rejected
        // by the same check (the first chunk decodes, then the cap binds).
        assert!(decode_chunked(&format!("1\r\na\r\n{MAX_BODY_BYTES:x}\r\n").into_bytes()).is_err());
    }

    #[test]
    fn decode_chunked_rejects_truncated_and_malformed_streams() {
        assert!(decode_chunked(b"5\r\nhel").is_err()); // body shorter than size
        assert!(decode_chunked(b"5\r\nhello\r").is_err()); // missing trailing CRLF
        assert!(decode_chunked(b"5\r\nhello\r\n0\r").is_err()); // truncated terminal
        assert!(decode_chunked(b"zz\r\n").is_err()); // non-hex chunk size
        assert!(decode_chunked(b"5z\r\n").is_err()); // hex digit followed by garbage
        assert!(decode_chunked(b"10\r\n0123456789").is_err()); // declared 16, got 10
        assert!(decode_chunked(&[0xff, 0xff, b'\r', b'\n']).is_err()); // non-UTF-8 size
    }

    #[test]
    fn decode_chunked_ignores_bytes_after_the_terminal_chunk() {
        // The decoder returns as soon as the 0-size line parses: HTTP
        // trailer lines (`X-foo: bar`) and the final CRLF are never read.
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n0\r\nX-Trail: yes\r\n\r\n").unwrap(),
            b"hello"
        );
    }

    proptest::proptest! {
        #[test]
        fn decode_chunked_round_trips_arbitrary_payloads(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let encoded = encode_chunked(&data);
            assert_eq!(decode_chunked(&encoded).unwrap(), data);
        }

        #[test]
        fn decode_chunked_never_panics_on_arbitrary_bytes(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = decode_chunked(&data);
        }
    }
}
