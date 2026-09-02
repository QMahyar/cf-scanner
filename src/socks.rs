use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) fn http_request(host: &str, path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\nConnection: close\r\n\r\n")
}

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

const MAX_HEADER_BYTES: usize = 64 * 1024;

pub(crate) fn http_request_keepalive(host: &str, path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n\r\n")
}

pub(crate) struct ParsedResponse {
    pub status: u16,
    pub headers: Vec<String>,
    pub body: Vec<u8>,
}

pub(crate) async fn read_response<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    max_body: usize,
) -> Result<ParsedResponse> {
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
    let head_str = std::str::from_utf8(&head).context("response headers are not utf-8")?;
    let mut lines = head_str.lines();
    let status_line = lines.next().context("empty HTTP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed status line")?;
    let headers: Vec<String> = lines.map(str::to_owned).collect();
    let body = read_body(stream, &headers, max_body).await?;
    Ok(ParsedResponse {
        status,
        headers,
        body,
    })
}

async fn read_body<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    headers: &[String],
    max_body: usize,
) -> Result<Vec<u8>> {
    let contains = |needle: &str| {
        headers
            .iter()
            .any(|h| h.to_ascii_lowercase().starts_with(needle))
    };
    if contains("transfer-encoding: chunked") {
        let mut raw = Vec::new();
        loop {
            let size_line = read_line(stream, 256).await.context("reading chunk size")?;
            let text = std::str::from_utf8(&size_line).context("chunk size not utf-8")?;
            let size = usize::from_str_radix(text.split(';').next().unwrap_or("").trim(), 16)
                .context("malformed chunk size")?;
            if size == 0 {
                loop {
                    let line = read_line(stream, 4096).await?;
                    if line.is_empty() {
                        break;
                    }
                }
                raw.extend_from_slice(b"0\r\n\r\n");
                break;
            }
            if size > max_body.saturating_sub(raw.len()) {
                bail!("chunked body exceeds the {max_body} cap");
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
        decode_chunked(&raw)
    } else if let Some(cl) = headers
        .iter()
        .find(|h| h.to_ascii_lowercase().starts_with("content-length:"))
    {
        let n: usize = cl
            .split(':')
            .nth(1)
            .and_then(|s| s.trim().parse().ok())
            .context("malformed content-length")?;
        if n > max_body {
            bail!("response body exceeds the {max_body} cap");
        }
        let mut body = vec![0u8; n];
        stream
            .read_exact(&mut body)
            .await
            .context("reading content-length body")?;
        Ok(body)
    } else {
        let mut body = Vec::new();
        stream
            .take(max_body as u64 + 1)
            .read_to_end(&mut body)
            .await
            .context("reading close-delimited body")?;
        if body.len() > max_body {
            bail!("response body exceeded the {max_body} byte cap");
        }
        Ok(body)
    }
}

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

pub(crate) async fn send_http<S>(stream: S, request: &str) -> Result<(u16, Vec<String>, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    wr.write_all(request.as_bytes()).await?;
    let _ = wr.shutdown().await;
    let resp = read_response(&mut rd, MAX_BODY_BYTES).await?;
    Ok((resp.status, resp.headers, resp.body))
}

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
    static CONNECTOR: std::sync::LazyLock<tokio_rustls::TlsConnector> =
        std::sync::LazyLock::new(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        });
    CONNECTOR.clone()
}

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
    let mut path = parsed.path().to_owned();
    if let Some(q) = parsed.query() {
        path.push('?');
        path.push_str(q);
    }
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
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

async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        bail!("socks server refused no-auth: {method:02x?}");
    }
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > 255 {
            bail!("socks host too long");
        }
        req.push(0x03);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
    }
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
    use proptest::prelude::*;

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
    async fn tunnel_probe_request_line_keeps_the_query_string() {
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
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
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut http = Vec::new();
            while !http.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                sock.read_exact(&mut byte).await.unwrap();
                http.push(byte[0]);
            }
            String::from_utf8_lossy(&http).into_owned()
        });
        get_via_socks("http://example.test/cdn-cgi/trace?flag=1", socks, 5_000)
            .await
            .unwrap_or_default();
        let request = server.await.unwrap();
        assert!(
            request.starts_with("GET /cdn-cgi/trace?flag=1 HTTP/1.1\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn tunnel_probe_times_out_when_socks_never_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        tokio::spawn(async move {
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

    #[tokio::test]
    async fn send_http_fails_explicitly_past_the_body_cap() {
        use tokio::io::AsyncWriteExt as _;
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        let writer = tokio::spawn(async move {
            let header = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
            if server.write_all(header).await.is_err() {
                return;
            }
            let chunk = vec![7u8; 64 * 1024];
            for _ in 0..2200 {
                if server.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        let err = send_http(client, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect_err("an over-cap body must fail explicitly");
        assert!(err.to_string().contains("exceeded"), "wrong failure: {err}");
        writer.await.unwrap();
    }

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
        assert!(decode_chunked(b"").is_err());
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
        assert!(decode_chunked(b"ffffffff\r\n").is_err());
        assert!(decode_chunked(b"1\r\na\r\nffffffff\r\n").is_err());
        assert!(decode_chunked(&format!("1\r\na\r\n{MAX_BODY_BYTES:x}\r\n").into_bytes()).is_err());
    }

    #[test]
    fn decode_chunked_rejects_truncated_and_malformed_streams() {
        assert!(decode_chunked(b"5\r\nhel").is_err());
        assert!(decode_chunked(b"5\r\nhello\r").is_err());
        assert!(decode_chunked(b"5\r\nhello\r\n0\r").is_err());
        assert!(decode_chunked(b"zz\r\n").is_err());
        assert!(decode_chunked(b"5z\r\n").is_err());
        assert!(decode_chunked(b"10\r\n0123456789").is_err());
        assert!(decode_chunked(&[0xff, 0xff, b'\r', b'\n']).is_err());
    }

    #[test]
    fn decode_chunked_ignores_bytes_after_the_terminal_chunk() {
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

        #[test]
        fn shared_read_response_agrees_with_inline_verifier(
            status in 200u16..599u16,
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
            framing in prop_oneof![
                Just(0usize),
                Just(1usize),
                Just(2usize),
            ]
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let resp_bytes = match framing {
                    0 => {
                        format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n", body.len())
                            .into_bytes()
                            .into_iter()
                            .chain(body)
                            .collect::<Vec<u8>>()
                    }
                    1 => {
                        let mut raw = Vec::new();
                        for chunk in body.chunks(64) {
                            raw.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                            raw.extend_from_slice(chunk);
                            raw.extend_from_slice(b"\r\n");
                        }
                        raw.extend_from_slice(b"0\r\n\r\n");
                        let encoded = decode_chunked(&raw).unwrap();
                        format!("HTTP/1.1 {status} X\r\nTransfer-Encoding: chunked\r\n\r\n")
                            .into_bytes()
                            .into_iter()
                            .chain(encoded)
                            .collect::<Vec<u8>>()
                    }
                    _ => {
                        format!("HTTP/1.1 {status} X\r\n\r\n")
                            .into_bytes()
                            .into_iter()
                            .chain(body)
                            .collect::<Vec<u8>>()
                    }
                };

                let socks_result = read_response(&mut &resp_bytes[..], MAX_BODY_BYTES).await;
                let inline_result = crate::inline_verify::read_http_response(&mut &resp_bytes[..]).await;

                match (&socks_result, &inline_result) {
                    (Ok(s), Ok((i_status, i_body))) => {
                        prop_assert_eq!(s.status, *i_status, "status mismatch");
                        prop_assert_eq!(&s.body, i_body, "body mismatch");
                    }
                    (Err(_), Err(_)) => {}
                    _ => {
                        prop_assert!(
                            false,
                            "disagreement: socks={:?}, inline={:?}",
                            socks_result.map(|r| (r.status, r.body.len())),
                            inline_result.map(|r| (r.0, r.1.len()))
                        );
                    }
                }
                Ok::<(), proptest::test_runner::TestCaseError>(())
            }).unwrap();
        }
    }
}
