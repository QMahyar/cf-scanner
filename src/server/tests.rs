use super::*;
use std::fs;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

use crate::api::types::{DEFAULT_WARP_PORTS, MAX_STOP_VALUE, Port};
use crate::api::types::{
    Mode, Phase2Config, ScanEvent, ScanSummary, ScanTarget, StopCondition, WarpConfig,
};
use crate::probe::FakeTransport;
use crate::ranges::BUNDLED_RANGES;
use crate::ranges::HttpGet;
use crate::server::sse::{MAX_SSE_CONNECTIONS, TerminalBounded, try_acquire_sse_slot};

const OFFICIAL_FIXTURE: &str =
    r#"{"success":true,"result":{"ipv4_cidrs":["10.1.0.0/16"]},"errors":[]}"#;

struct FakeHttp(&'static str);

impl HttpGet for FakeHttp {
    fn get<'a>(&'a self, _url: &'a str) -> ranges::HttpFuture<'a> {
        Box::pin(async move { Ok(self.0.to_owned()) })
    }
}

struct FailingHttp;

impl HttpGet for FailingHttp {
    fn get<'a>(&'a self, _url: &'a str) -> ranges::HttpFuture<'a> {
        Box::pin(async { Err(anyhow::anyhow!("network down")) })
    }
}

fn cfg(count: u32, found: u32) -> ScanConfig {
    ScanConfig {
        mode: Mode::Cdn,
        target: ScanTarget::Count(count),
        stop: StopCondition { found, cap: None },
        custom_cidrs: vec!["203.0.113.0/29".to_owned()],
        ports: vec![Port::new(443)],
        concurrency: 1,
        ..ScanConfig::default()
    }
}

async fn serve(t: FakeTransport) -> SocketAddr {
    serve_with_ranges(t, RangesState::load_text(BUNDLED_RANGES, None)).await
}

async fn serve_with_ranges(t: FakeTransport, ranges: Arc<RangesState>) -> SocketAddr {
    serve_with_registrar(t, ranges, canned_registrar()).await
}

async fn serve_with_registrar(
    t: FakeTransport,
    ranges: Arc<RangesState>,
    registrar: WarpRegistrar,
) -> SocketAddr {
    serve_with_dir(t, ranges, registrar, canned_xray_fetch()).await
}

async fn serve_with_dir(
    t: FakeTransport,
    ranges: Arc<RangesState>,
    registrar: WarpRegistrar,
    xray_fetch: XrayFetcher,
) -> SocketAddr {
    let controller = Arc::new(ScanController::new(Arc::new(t)));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router_with_dir(controller, ranges, registrar, addr.port(), xray_fetch),
        )
        .await
        .unwrap();
    });
    addr
}

fn canned_registrar() -> WarpRegistrar {
    Arc::new(|_| Ok("fake-wgconf".to_owned()))
}

fn canned_xray_fetch() -> XrayFetcher {
    Arc::new(|| Ok(std::path::PathBuf::from("/fake/xray")))
}

fn failing_registrar() -> WarpRegistrar {
    Arc::new(|_| Err(anyhow::anyhow!("upstream unreachable")))
}

fn isolate_identity_dir() -> impl Drop {
    let guard = crate::warpgen::tests::IDENTITY_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
    unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    struct Cleanup {
        _guard: std::sync::MutexGuard<'static, ()>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
            let _ = fs::remove_file(dir.join("identity.json"));
        }
    }
    Cleanup { _guard: guard }
}

fn identity_persisting_registrar() -> WarpRegistrar {
    let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
    Arc::new(move |_| {
        fs::write(
            dir.join("identity.json"),
            r#"{"id":"t","token":"t","private_key":"aGFo","client_id":"c","account_type":"free","created_at":0}"#,
        )
        .unwrap();
        Ok("fake-wgconf".to_owned())
    })
}

fn recording_registrar(wgconf: &'static str) -> (WarpRegistrar, Arc<Mutex<Option<String>>>) {
    let seen = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&seen);
    let registrar: WarpRegistrar = Arc::new(move |license| {
        *capture.lock().unwrap() = license;
        Ok(wgconf.to_owned())
    });
    (registrar, seen)
}

async fn request(addr: SocketAddr, req: &str, until: Option<&str>) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![];
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(deadline);
    loop {
        if until.is_some_and(|needle| String::from_utf8_lossy(&buf).contains(needle)) {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            read = stream.read(&mut chunk) => match read {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            },
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    (
        text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0),
        text,
    )
}

async fn post_scan(addr: SocketAddr, body: &str) -> u16 {
    post_scan_full(addr, body).await.0
}

pub(crate) const CSRF_MARKER: &str = "X-Requested-With: cf-scanner\r\n";

async fn post_scan_full(addr: SocketAddr, body: &str) -> (u16, String) {
    let req = format!(
        "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    request(addr, &req, None).await
}
async fn post_register(addr: SocketAddr, body: &str) -> (u16, String) {
    let req = format!(
        "POST /api/warp/register HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    request(addr, &req, None).await
}

fn script_all_hosts(t: &FakeTransport, latency: u32) {
    for i in 0..8u8 {
        t.insert(format!("203.0.113.{i}").parse().unwrap(), 443, Ok(latency));
    }
}

#[tokio::test]
async fn api_responses_carry_security_headers() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 200);
    let headers = text.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or("");
    let lower = headers.to_ascii_lowercase();
    assert!(
        lower.contains("referrer-policy: no-referrer"),
        "missing Referrer-Policy: {headers}"
    );
    assert!(
        lower.contains("x-content-type-options: nosniff"),
        "missing nosniff: {headers}"
    );
}

#[tokio::test]
async fn rejects_invalid_scan_config() {
    let addr = serve(FakeTransport::new()).await;
    let body = r#"{"mode":"Cdn","target":{"Preset":"Quick"},"ports":[0],"stop":{"found":1,"cap":null},"exclude":[],"custom_cidrs":[],"concurrency":1,"timeout_ms":3000,"phase2":null,"warp":null}"#;
    let (status, text) = post_scan_full(addr, body).await;
    assert_eq!(status, 422);
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "invalid_config");
}

#[tokio::test]
async fn accepts_include_v6_scan_config() {
    let addr = serve(FakeTransport::new()).await;
    let mut c = cfg(1, 1);
    c.include_v6 = true;
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        202
    );
}

#[tokio::test]
async fn scan_config_without_include_v6_field_still_posts() {
    let addr = serve(FakeTransport::new()).await;
    let c = cfg(1, 1);
    let mut json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"include_v6\":false"), "{json}");
    json = json.replacen("\"include_v6\":false,", "", 1);
    assert!(!json.contains("include_v6"), "{json}");
    assert_eq!(post_scan(addr, &json).await, 202);
}

#[tokio::test]
async fn scan_results_and_summary_roundtrip() {
    let t = FakeTransport::new();
    script_all_hosts(&t, 25);
    let addr = serve(t).await;
    let body = serde_json::to_string(&cfg(1, 1)).unwrap();
    assert_eq!(post_scan(addr, &body).await, 202);

    let results_body = async {
        for _ in 0..50 {
            let (status, text) = request(
                addr,
                "GET /api/results HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                None,
            )
            .await;
            if status == 200 && text.contains("\"latency_ms\":25") {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("scan did not produce results in time");
    }
    .await;
    assert!(results_body.contains("\"found\":1"), "{results_body}");
    assert!(results_body.contains("\"summary\""));
}

#[tokio::test]
async fn events_stream_ends_after_the_terminal_event() {
    let mut t = FakeTransport::new();
    for i in 0..8u8 {
        t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
    }
    let addr = serve(t).await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let started = Instant::now();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let deadline = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(deadline);
    tokio::select! {
        _ = &mut deadline => {}
        readable = stream.readable() => {
            readable.unwrap();
        }
    }
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&cfg(1, 1)).unwrap()).await,
        202
    );
    let mut buf = vec![];
    let mut chunk = [0u8; 4096];
    let eof = loop {
        if String::from_utf8_lossy(&buf).contains("event: finished") {
            break true;
        }
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        tokio::select! {
            _ = &mut deadline => break false,
            read = stream.read(&mut chunk) => match read {
                Ok(0) => break false,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break false,
            },
        }
    };
    assert!(eof, "no terminal event within 2 s");
    loop {
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        tokio::select! {
            _ = &mut deadline => panic!("stream did not end after the terminal event"),
            read = stream.read(&mut chunk) => match read {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            },
        }
    }
    assert!(started.elapsed() < Duration::from_millis(1500));
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("event: progress"), "{text}");
    assert!(text.contains("event: result"), "{text}");
    assert!(text.contains("event: finished"), "{text}");
}

#[tokio::test]
async fn concurrent_scan_starts_emit_no_phantom_failed() {
    let mut t = FakeTransport::new();
    for i in 0..8u8 {
        t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
    }
    let addr = serve(t).await;
    let ready_deadline = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(ready_deadline);
    loop {
        tokio::select! {
            _ = &mut ready_deadline => break,
            result = tokio::net::TcpStream::connect(addr) => {
                if result.is_ok() { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
    let events = tokio::spawn(request(
        addr,
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        Some("event: finished"),
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;
    let body = serde_json::to_string(&cfg(1, 1)).unwrap();
    let mut posts = Vec::new();
    for _ in 0..3 {
        let body = body.clone();
        posts.push(tokio::spawn(async move {
            let req = format!(
                "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            request(addr, &req, None).await.0
        }));
    }
    let mut codes: Vec<u16> = Vec::new();
    for post in posts {
        codes.push(post.await.unwrap());
    }
    codes.sort_unstable();
    assert_eq!(codes, vec![202, 409, 409], "exactly one start may win");
    let (_, text) = events.await.unwrap();
    assert!(text.contains("event: finished"), "{text}");
    assert!(
        !text.contains("event: failed"),
        "no phantom Failed may reach clients: {text}"
    );
}

#[tokio::test]
async fn terminal_bounded_stream_stops_after_finished() {
    let (tx, rx) = tokio::sync::broadcast::channel(8);
    let mut stream = TerminalBounded {
        rx: BroadcastStream::new(rx),
        _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
        done: false,
        replay: None,
        last_terminal: Arc::new(Mutex::new(None)),
        epoch: 0,
        controller: Arc::new(crate::engine::ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        ))),
        seen: std::collections::HashSet::new(),
        pending: std::collections::VecDeque::new(),
        last_resync: None,
    };
    tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
        scanned: 1,
        found: 0,
        total: Some(8),
    }))
    .unwrap();
    tx.send(ScanEvent::Finished(ScanSummary {
        scanned: 8,
        found: 1,
        duration_ms: 5,
        cancelled: false,
    }))
    .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert!(first.is_ok(), "progress item must arrive");
    let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert!(second.is_ok(), "finished item must arrive");
    let third = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
    assert!(
        matches!(&third, Err(_) | Ok(None)),
        "stream must end after the terminal event: {third:?}"
    );
}

#[tokio::test]
async fn replayed_terminal_does_not_close_the_stream() {
    let (tx, rx) = tokio::sync::broadcast::channel(8);
    let mut stream = TerminalBounded {
        rx: BroadcastStream::new(rx),
        _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
        done: false,
        replay: Some((
            ScanEvent::Finished(ScanSummary {
                scanned: 4,
                found: 2,
                duration_ms: 3,
                cancelled: false,
            }),
            false,
        )),
        last_terminal: Arc::new(Mutex::new(None)),
        epoch: 0,
        controller: Arc::new(crate::engine::ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        ))),
        seen: std::collections::HashSet::new(),
        pending: std::collections::VecDeque::new(),
        last_resync: None,
    };
    let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert!(first.is_ok(), "replayed finished item must arrive");
    let second = tokio::time::timeout(Duration::from_millis(150), stream.next()).await;
    assert!(
        second.is_err(),
        "the stream must stay open after a REPLAYED terminal: {second:?}"
    );
    tx.send(ScanEvent::Finished(ScanSummary {
        scanned: 8,
        found: 3,
        duration_ms: 9,
        cancelled: false,
    }))
    .unwrap();
    let third = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert!(third.is_ok(), "live finished item must arrive");
    let fourth = tokio::time::timeout(Duration::from_millis(150), stream.next()).await;
    assert!(
        matches!(&fourth, Err(_) | Ok(None)),
        "a LIVE terminal must end the stream: {fourth:?}"
    );
}

async fn wait_until_running(addr: SocketAddr) {
    for _ in 0..200 {
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        if status == 200 && text.contains("\"is_running\":true") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("scan did not reach the running guard in time");
}

async fn wait_until_idle(addr: SocketAddr) {
    for _ in 0..200 {
        let (status, text) = request(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        if status == 200 && text.contains("\"is_running\":false") {
            tokio::time::sleep(Duration::from_millis(10)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("scan did not finish in time");
}

#[tokio::test]
async fn events_replay_the_terminal_of_the_latest_finished_run() {
    let t = FakeTransport::new();
    for i in 0..8u8 {
        t.insert(format!("203.0.113.{i}").parse().unwrap(), 443, Ok(10));
    }
    let addr = serve(t).await;
    let body = cfg(1, 1);
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
        202
    );
    wait_until_idle(addr).await;
    let (status, text) = request(
        addr,
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        Some("event: finished"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(text.matches("event: finished").count(), 1, "{text}");
}

#[tokio::test]
async fn second_scan_while_running_is_conflict() {
    let mut t = FakeTransport::new();
    for i in 0..8u8 {
        t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
    }
    let addr = serve(t).await;
    let body = cfg(1, 1);
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
        202
    );
    wait_until_running(addr).await;
    let body = cfg(1, 1);
    let status = post_scan(addr, &serde_json::to_string(&body).unwrap()).await;
    assert_eq!(status, 409);
}

#[tokio::test]
async fn cancel_and_reset_are_noops_without_scan() {
    let addr = serve(FakeTransport::new()).await;
    let (status, _) = request(addr, &format!("POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1\r\n{CSRF_MARKER}Content-Length: 0\r\nConnection: close\r\n\r\n"), None).await;
    assert_eq!(status, 204);
    let (status, _) = request(addr, &format!("POST /api/reset HTTP/1.1\r\nHost: 127.0.0.1\r\n{CSRF_MARKER}Content-Length: 0\r\nConnection: close\r\n\r\n"), None).await;
    assert_eq!(status, 204);
}

async fn get_ranges(addr: SocketAddr) -> (u16, String) {
    request(
        addr,
        "GET /api/ranges HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await
}

fn json_body(text: &str) -> &str {
    text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(text)
}

#[tokio::test]
async fn ranges_endpoint_reports_bundled_pool() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = get_ranges(addr).await;
    assert_eq!(status, 200);
    assert!(text.contains("\"host_count\":"));
    assert!(text.contains("\"last_updated\":null"), "{text}");
}

#[tokio::test]
async fn ranges_endpoint_reports_last_updated() {
    let ranges = RangesState::load_text(BUNDLED_RANGES, Some("2026-08-13T12:34:56Z"));
    let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
    let (status, text) = get_ranges(addr).await;
    assert_eq!(status, 200);
    assert!(
        text.contains("\"last_updated\":\"2026-08-13T12:34:56Z\""),
        "{text}"
    );
}

#[tokio::test]
async fn background_refresh_populates_last_updated() {
    let ranges = RangesState::load_text(BUNDLED_RANGES, None);
    ranges.spawn_refresh(
        Some(Duration::from_millis(20)),
        Arc::new(FakeHttp(OFFICIAL_FIXTURE)),
    );
    let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        if status == 200 {
            let payload: serde_json::Value =
                serde_json::from_str(json_body(&text)).expect("ranges payload JSON");
            if let Some(ts) = payload["last_updated"].as_str() {
                assert!(ts.ends_with('Z'), "{ts}");
                assert!(payload["host_count"].as_u64().unwrap_or(0) > 0);
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("background refresh did not update the ranges payload");
}

#[tokio::test]
async fn background_refresh_failure_keeps_last_good_data() {
    let ranges = RangesState::load_text("203.0.113.0/24", Some("2026-01-01T00:00:00Z"));
    ranges.spawn_refresh(Some(Duration::from_millis(20)), Arc::new(FailingHttp));
    let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        assert!(
            text.contains("\"last_updated\":\"2026-01-01T00:00:00Z\""),
            "{text}"
        );
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn rejects_foreign_host_header() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403, "{text}");
    let parsed: serde_json::Value =
        serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
    assert_eq!(parsed["error"], "Forbidden");
}

#[tokio::test]
async fn accepts_localhost_case_insensitively_and_rejects_ipv6_host() {
    let addr = serve(FakeTransport::new()).await;
    for host in ["localhost:8765", "LOCALHOST:8765", "127.0.0.1:1"] {
        let (status, _) = request(
            addr,
            &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
            None,
        )
        .await;
        assert_eq!(status, 200, "host {host:?} must be allowed");
    }
    for host in ["[::1]:8765", "[::1]"] {
        let (status, _) = request(
            addr,
            &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
            None,
        )
        .await;
        assert_eq!(status, 403, "host {host:?} must be rejected");
    }
}

#[tokio::test]
async fn rejects_foreign_origin() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403, "{text}");
}

#[tokio::test]
async fn origin_must_carry_the_served_port() {
    let addr = serve(FakeTransport::new()).await;
    let req_for = |origin: &str| {
        format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n"
        )
    };
    let own = format!("http://127.0.0.1:{}", addr.port());
    let (status, text) = request(addr, &req_for(&own), None).await;
    assert_eq!(status, 200, "{text}");
    let (status, text) = request(addr, &req_for("http://127.0.0.1:9999"), None).await;
    assert_eq!(status, 403, "{text}");
    let (status, text) = request(addr, &req_for("http://localhost:9999"), None).await;
    assert_eq!(status, 403, "{text}");
    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 200, "{text}");
}

#[tokio::test]
async fn rejects_cross_site_fetch() {
    let addr = serve(FakeTransport::new()).await;
    let (status, _) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn rejects_missing_host_header() {
    let addr = serve(FakeTransport::new()).await;
    let (status, _) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn malformed_json_gets_uniform_error_envelope() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nX-Requested-With: cf-scanner\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{nojson",
        None,
    )
    .await;
    assert_eq!(status, 400, "{text}");
    let parsed: serde_json::Value =
        serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
    assert_eq!(parsed["error"], "Bad Request");
    assert!(parsed["message"].as_str().is_some_and(|m| !m.is_empty()));
}

#[tokio::test]
async fn phase2_file_paths_are_rejected_over_http() {
    let addr = serve(FakeTransport::new()).await;
    let mut c = cfg(1, 1);
    c.phase2 = Some(Phase2Config {
        configs: vec!["C:\\secret\\config.json".to_owned()],
        ..Phase2Config::default()
    });
    let status = post_scan(addr, &serde_json::to_string(&c).unwrap()).await;
    assert_eq!(status, 422);
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        ..Phase2Config::default()
    });
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        202
    );
}

#[tokio::test]
async fn concurrent_scan_starts_do_not_double_spawn() {
    let mut t = FakeTransport::new();
    for i in 0..8u8 {
        t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
    }
    let addr = serve(t).await;
    let body = serde_json::to_string(&cfg(1, 1)).unwrap();
    let a = tokio::spawn(async move {
        let req = format!(
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        request(addr, &req, None).await.0
    });
    let body = serde_json::to_string(&cfg(1, 1)).unwrap();
    let b = tokio::spawn(async move {
        let req = format!(
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        request(addr, &req, None).await.0
    });
    let (sa, sb) = (a.await.unwrap(), b.await.unwrap());
    let mut codes = [sa, sb];
    codes.sort_unstable();
    assert_eq!(codes, [202, 409], "one scan must win, one must 409");
}

#[tokio::test]
async fn sse_connection_cap_rejects_fifth_stream() {
    let addr = serve(FakeTransport::new()).await;
    let req = "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    use tokio::io::AsyncWriteExt;
    let mut streams = Vec::new();
    for _ in 0..MAX_SSE_CONNECTIONS {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        streams.push(s);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let status = loop {
        let (status, _) = request(addr, req, None).await;
        if status == 429 {
            break status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "SSE cap was not reached within 2 s"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(status, 429);
    drop(streams);
}

#[tokio::test]
async fn warp_register_with_null_license_returns_wgconf() {
    let _isolated = isolate_identity_dir();
    let (registrar, seen) = recording_registrar("fake-wgconf-text");
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        registrar,
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(json_body(&text), r#"{"wgconf":"fake-wgconf-text"}"#);
    assert_eq!(*seen.lock().unwrap(), None);
}

#[tokio::test]
async fn warp_register_forwards_the_license_string() {
    let _isolated = isolate_identity_dir();
    let (registrar, seen) = recording_registrar("fake-wgconf-text");
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        registrar,
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":"WARP-PLUS-ABC"}"#).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(seen.lock().unwrap().as_deref(), Some("WARP-PLUS-ABC"));
}

#[tokio::test]
async fn warp_register_absent_or_blank_license_is_none() {
    let _isolated = isolate_identity_dir();
    let (registrar, seen) = recording_registrar("fake-wgconf-text");
    for body in [
        r#"{}"#,
        r#"{"license":null}"#,
        r#"{"license":""}"#,
        r#"{"license":"   "}"#,
    ] {
        let addr = serve_with_registrar(
            FakeTransport::new(),
            RangesState::load_text(BUNDLED_RANGES, None),
            Arc::clone(&registrar),
        )
        .await;
        let (status, text) = post_register(addr, body).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(
            *seen.lock().unwrap(),
            None,
            "body {body} must pass license None"
        );
    }
}

#[tokio::test]
async fn warp_register_failure_returns_uniform_envelope() {
    let _isolated = isolate_identity_dir();
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        failing_registrar(),
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 502, "{text}");
    let parsed: serde_json::Value =
        serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
    assert_eq!(parsed["error"], "Bad Gateway");
    assert!(parsed["message"].as_str().is_some_and(|m| !m.is_empty()));
}

#[tokio::test]
async fn warp_register_malformed_body_gets_uniform_400() {
    let _isolated = isolate_identity_dir();
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        failing_registrar(),
    )
    .await;
    let (status, text) = post_register(addr, "{nope").await;
    assert_eq!(status, 400, "{text}");
    let parsed: serde_json::Value =
        serde_json::from_str(json_body(&text)).expect("error envelope is JSON");
    assert_eq!(parsed["error"], "Bad Request");
    assert!(parsed["message"].as_str().is_some_and(|m| !m.is_empty()));
}

#[tokio::test]
async fn register_is_rate_limited() {
    let _isolated = isolate_identity_dir();
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        canned_registrar(),
    )
    .await;
    let (status, _) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 200);
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 429, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["error"], "Too Many Requests");
}

#[tokio::test]
async fn register_refuses_overwrite_without_consent() {
    let _isolated = isolate_identity_dir();
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        identity_persisting_registrar(),
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 200, "{text}");
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 409, "{text}");
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        canned_registrar(),
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null,"overwrite":true}"#).await;
    assert_eq!(status, 200, "{text}");
}

fn slow_identity_registrar() -> (WarpRegistrar, Arc<Notify>) {
    let dir = std::env::temp_dir().join("cf-scanner-server-register-tests");
    let notify = Arc::new(Notify::new());
    let notify_clone = notify.clone();
    let registrar: WarpRegistrar = Arc::new(move |_| {
        notify_clone.notify_one();
        fs::write(
            dir.join("identity.json"),
            r#"{"id":"t","token":"t","private_key":"aGFo","client_id":"c","account_type":"free","created_at":0}"#,
        )
        .unwrap();
        Ok("fake-wgconf".to_owned())
    });
    (registrar, notify)
}

#[tokio::test]
async fn concurrent_registers_serialize_overwrite_consent() {
    let _isolated = isolate_identity_dir();
    let (registrar, notify) = slow_identity_registrar();
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        registrar,
    )
    .await;
    let notified = notify.notified();
    let (a, b) = tokio::join!(
        post_register(addr, r#"{"license":null}"#),
        post_register(addr, r#"{"license":null}"#),
    );
    tokio::time::timeout(Duration::from_secs(2), notified)
        .await
        .expect("registrar was not called within 2 s");
    let mut codes = [a.0, b.0];
    codes.sort_unstable();
    assert_eq!(
        codes,
        [200, 409],
        "the second register must see the identity the first wrote"
    );
}

#[tokio::test]
async fn register_rejects_oversized_license() {
    let _isolated = isolate_identity_dir();
    let (registrar, seen) = recording_registrar("fake-wgconf-text");
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        registrar,
    )
    .await;
    let big = "a".repeat(crate::api::types::MAX_LICENSE_BYTES + 1);
    let (status, text) = post_register(addr, &format!(r#"{{"license":"{big}"}}"#)).await;
    assert_eq!(status, 400, "{text}");
    assert!(
        text.contains(&format!(
            "at most {} bytes",
            crate::api::types::MAX_LICENSE_BYTES
        )),
        "{text}"
    );
    let at_cap = "a".repeat(crate::api::types::MAX_LICENSE_BYTES);
    let (status, text) = post_register(addr, &format!(r#"{{"license":"{at_cap}"}}"#)).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(seen.lock().unwrap().as_deref(), Some(at_cap.as_str()));
}

#[tokio::test]
async fn export_rejects_oversized_config() {
    let addr = serve(FakeTransport::new()).await;
    let big = format!(
        "vless://x@1.2.3.4:443?{}",
        "a".repeat(crate::api::types::MAX_EXPORT_CONFIG_BYTES)
    );
    let body = serde_json::json!({"config": big, "ip": "203.0.113.7", "port": 443});
    let (status, text) = post_export(addr, &body.to_string()).await;
    assert_eq!(status, 400, "{text}");
    assert!(
        text.contains(&format!(
            "at most {} bytes",
            crate::api::types::MAX_EXPORT_CONFIG_BYTES
        )),
        "{text}"
    );
}

#[tokio::test]
async fn scan_rejects_non_routable_custom_cidrs() {
    let addr = serve(FakeTransport::new()).await;
    for cidr in [
        "127.0.0.1/32",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.1.0/24",
        "::1/128",
        "::/128",
        "fc00::/7",
        "fe80::/10",
        "::ffff:127.0.0.1/128",
        "::ffff:169.254.0.1/128",
        "::ffff:10.0.0.0/104",
        "::ffff:192.168.1.0/120",
    ] {
        let mut c = cfg(1, 1);
        c.custom_cidrs = vec![cidr.to_owned()];
        let status = post_scan(addr, &serde_json::to_string(&c).unwrap()).await;
        assert_eq!(status, 422, "custom_cidrs {cidr} must be rejected");
    }
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&cfg(1, 1)).unwrap()).await,
        202
    );
    let mut c = cfg(1, 1);
    c.mode = Mode::Warp;
    c.custom_cidrs = vec![];
    c.ports = vec![Port::new(2408)];
    c.warp = Some(WarpConfig {
        custom_endpoints: vec!["127.0.0.1".to_owned()],
        ..WarpConfig::default()
    });
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        422
    );
    c.warp.as_mut().unwrap().custom_endpoints = vec!["203.0.113.1".to_owned()];
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        202
    );
}

#[tokio::test]
async fn scan_rejects_stop_values_above_the_frontend_cap() {
    let addr = serve(FakeTransport::new()).await;
    let mut c = cfg(1, 1);
    c.stop = StopCondition {
        found: MAX_STOP_VALUE + 1,
        cap: None,
    };
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        422,
        "found above the frontend cap must be rejected"
    );
    c.stop = StopCondition {
        found: 1,
        cap: Some(0),
    };
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        422,
        "cap 0 must be rejected"
    );
    c.stop = StopCondition {
        found: 1,
        cap: Some(MAX_STOP_VALUE),
    };
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        202,
        "cap at the frontend limit must be accepted"
    );
}

#[tokio::test]
async fn warp_scan_with_cdn_default_port_is_rejected_not_substituted() {
    let addr = serve(FakeTransport::new()).await;
    let mut c = cfg(1, 1);
    c.mode = Mode::Warp;
    c.custom_cidrs = vec![];
    c.warp = Some(WarpConfig {
        custom_endpoints: vec!["203.0.113.1".to_owned()],
        ..Default::default()
    });
    let (status, text) = post_scan_full(addr, &serde_json::to_string(&c).unwrap()).await;
    assert_eq!(status, 422, "{text}");
    c.ports = DEFAULT_WARP_PORTS.to_vec();
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        202
    );
    let cdn = serve(FakeTransport::new()).await;
    assert_eq!(
        post_scan(cdn, &serde_json::to_string(&cfg(1, 1)).unwrap()).await,
        202
    );
}

fn warp_cfg_with_wgconf() -> ScanConfig {
    let mut c = cfg(1, 1);
    c.mode = Mode::Warp;
    c.custom_cidrs = vec![];
    c.ports = vec![Port::new(2408)];
    c.warp = Some(WarpConfig {
        custom_endpoints: vec!["203.0.113.1".to_owned()],
        wgconf: Some(
            "PrivateKey = TOP-SECRET-WG-KEY\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                .to_owned(),
        ),
        verify_with_wgconf: true,
        ..WarpConfig::default()
    });
    c
}

#[tokio::test]
async fn scan_path_still_accepts_wgconf_configs() {
    let addr = serve(FakeTransport::new()).await;
    let mut c = warp_cfg_with_wgconf();
    c.warp.as_mut().unwrap().verify_with_wgconf = false;
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&c).unwrap()).await,
        202
    );
}

async fn post_export(addr: SocketAddr, body: &str) -> (u16, String) {
    let req = format!(
        "POST /api/config/export HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    request(addr, &req, None).await
}

const EXPORT_VLESS: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com&fp=chrome";

#[tokio::test]
async fn export_renders_a_ready_uri_for_a_verified_candidate() {
    let addr = serve(FakeTransport::new()).await;
    let body = serde_json::json!({
        "config": EXPORT_VLESS,
        "ip": "203.0.113.7",
        "port": 2096,
        "sni": "b.me"
    });
    let (status, text) = post_export(addr, &body.to_string()).await;
    assert_eq!(status, 200, "{text}");
    let payload: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    let uri = payload["uri"].as_str().unwrap();
    assert!(
        uri.starts_with("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@203.0.113.7:2096?"),
        "{uri}"
    );
    assert!(
        uri.contains("sni=b.me") && uri.contains("fp=chrome"),
        "{uri}"
    );
    let spec = crate::configs::parse_uri(uri).unwrap();
    assert_eq!(spec.server, "203.0.113.7");
    assert_eq!(spec.port, 2096);
    assert_eq!(spec.tls_server_name.as_deref(), Some("b.me"));
}

#[tokio::test]
async fn export_without_sni_keeps_the_configs_own_sni() {
    let addr = serve(FakeTransport::new()).await;
    let body = serde_json::json!({
        "config": EXPORT_VLESS,
        "ip": "203.0.113.7",
        "port": 2096
    });
    let (status, text) = post_export(addr, &body.to_string()).await;
    assert_eq!(status, 200, "{text}");
    let payload: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert!(
        payload["uri"]
            .as_str()
            .unwrap()
            .contains("sni=orig.example.com"),
        "{payload}"
    );
}

#[tokio::test]
async fn export_rejects_bad_ip_port_and_oversized_sni() {
    let addr = serve(FakeTransport::new()).await;
    let oversized_sni = "a".repeat(crate::api::types::MAX_SNI_BYTES + 1);
    for (body, expected) in [
        (
            serde_json::to_string(&serde_json::json!({
                "config": EXPORT_VLESS,
                "ip": "not-an-ip",
                "port": 443
            }))
            .unwrap(),
            "ip must be an IPv4 address",
        ),
        (
            serde_json::to_string(&serde_json::json!({
                "config": EXPORT_VLESS,
                "ip": "203.0.113.7",
                "port": 0
            }))
            .unwrap(),
            "port must be in 1..=65535",
        ),
        (
            serde_json::to_string(&serde_json::json!({
                "config": EXPORT_VLESS,
                "ip": "203.0.113.7",
                "port": 443,
                "sni": oversized_sni
            }))
            .unwrap(),
            "sni must be at most",
        ),
    ] {
        let (status, text) = post_export(addr, &body).await;
        assert_eq!(status, 400, "{text}");
        assert!(text.contains(expected), "{text}");
    }
}

#[tokio::test]
async fn export_rejects_malformed_sni() {
    let addr = serve(FakeTransport::new()).await;
    for bad in ["bad_sni", "-bad", "bad-", "a..b", "has space"] {
        let body = serde_json::json!({
            "config": EXPORT_VLESS,
            "ip": "203.0.113.7",
            "port": 443,
            "sni": bad
        });
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 400, "{bad}: {text}");
        assert!(text.contains("invalid SNI"), "{bad}: {text}");
    }
    for good in ["1.2.3.4", "2606:4700::1111", "front.example.com"] {
        let body = serde_json::json!({
            "config": EXPORT_VLESS,
            "ip": "203.0.113.7",
            "port": 443,
            "sni": good
        });
        let (status, text) = post_export(addr, &body.to_string()).await;
        assert_eq!(status, 200, "{good}: {text}");
    }
}

#[tokio::test]
async fn export_rejects_unsupported_configs_with_a_redacted_envelope() {
    let addr = serve(FakeTransport::new()).await;
    let body = serde_json::json!({
        "config": "hysteria2://secret-hy2-id@1.2.3.4:443",
        "ip": "203.0.113.7",
        "port": 443
    });
    let (status, text) = post_export(addr, &body.to_string()).await;
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("unsupported scheme"), "{text}");
    assert!(!text.contains("secret-hy2-id"), "{text}");
    let body = serde_json::json!({"config": "http://evil.example/x?id=sec", "ip": "203.0.113.7", "port": 443});
    let (status, text) = post_export(addr, &body.to_string()).await;
    assert_eq!(status, 400, "{text}");
    assert!(!text.contains("sec"), "the config must never echo: {text}");
}

#[tokio::test]
async fn bundle_endpoints_serve_subscription_and_metadata_formats() {
    let addr = serve(FakeTransport::new()).await;
    let client = reqwest::Client::new();
    for (path, expect) in [
        ("/api/bundle?format=base64", ""),
        ("/api/bundle?format=raw", ""),
        ("/api/results/export?format=csv", "ip,port,latency_ms"),
        ("/api/results/export?format=json", "\"count\":0"),
    ] {
        let res = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{path}");
        assert!(
            res.headers().get("cache-control").is_some(),
            "{path} must be no-store"
        );
        let body = res.text().await.unwrap();
        assert!(body.contains(expect), "{path}: {body}");
    }
}

#[tokio::test]
async fn bundle_endpoints_reject_unknown_formats_with_400() {
    let addr = serve(FakeTransport::new()).await;
    let client = reqwest::Client::new();
    for path in [
        "/api/bundle?format=yaml",
        "/api/bundle?format=",
        "/api/results/export?format=xml",
    ] {
        let res = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "{path}");
        let body = res.text().await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["code"], "bad_request", "{path}: {body}");
    }
}

#[tokio::test]
async fn bundle_and_export_serve_seeded_results_with_unique_tags() {
    let t = FakeTransport::new();
    for i in 0..8u8 {
        t.insert(format!("203.0.113.{i}").parse().unwrap(), 443, Ok(10));
    }
    let probe = crate::verify::PassAllProbe;
    let controller = Arc::new(ScanController::with_probes(
        Arc::new(t),
        Arc::new(crate::configs::RealSubFetch),
        Arc::new(probe),
    ));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router_with_dir(
                controller,
                RangesState::load_text(BUNDLED_RANGES, None),
                canned_registrar(),
                addr.port(),
                canned_xray_fetch(),
            ),
        )
        .await
        .unwrap();
    });
    let mut c = cfg(8, 100);
    c.phase2 = Some(Phase2Config {
        configs: vec![
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443".to_owned(),
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@5.6.7.8:443".to_owned(),
        ],
        ..Phase2Config::default()
    });
    let body = serde_json::to_string(&c).unwrap();
    let (status, _) = post_scan_full(addr, &body).await;
    assert_eq!(status, 202, "scan must start");
    wait_until_idle(addr).await;

    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{addr}/api/bundle?format=raw"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let raw = res.text().await.unwrap();
    let uris: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();
    assert!(!uris.is_empty(), "passing rows must produce URIs: {raw}");
    for uri in uris {
        assert!(uri.starts_with("vless://"), "{uri}");
        assert!(uri.contains("203.0.113."), "{uri}");
    }
    let res = client
        .get(format!("http://{addr}/api/bundle?format=clash"))
        .send()
        .await
        .unwrap();
    let clash = res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&clash).unwrap();
    let names: Vec<&str> = parsed["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(
        names.len(),
        unique.len(),
        "proxy names must be unique: {names:?}"
    );
    for p in parsed["proxies"].as_array().unwrap() {
        let has_uuid = p.get("uuid").is_some();
        let has_password = p.get("password").is_some();
        assert!(
            has_uuid ^ has_password || (!has_uuid && !has_password),
            "exactly one credential field per proxy: {p}"
        );
    }
    let res = client
        .get(format!("http://{addr}/api/bundle?format=singbox"))
        .send()
        .await
        .unwrap();
    let singbox: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    let tags: Vec<&str> = singbox["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags.len(),
        tags.iter().collect::<std::collections::HashSet<_>>().len()
    );

    let res = client
        .get(format!("http://{addr}/api/results/export?format=csv"))
        .send()
        .await
        .unwrap();
    let csv = res.text().await.unwrap();
    assert!(csv.contains("203.0.113."), "{csv}");
    assert_eq!(csv.lines().count() - 1, 8, "{csv}");
    let res = client
        .get(format!("http://{addr}/api/results/export?format=json"))
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(json["count"], 8);
}

#[test]
fn csv_export_quotes_fields_containing_separators() {
    use crate::server::export::csv_field;
    assert_eq!(csv_field("LAX"), "LAX");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
}

#[tokio::test]
async fn export_endpoints_keep_their_documented_no_param_defaults() {
    let addr = serve(FakeTransport::new()).await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{addr}/api/bundle"))
        .send()
        .await
        .unwrap();
    let disposition = res
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(disposition.contains("cf-scanner-sub.txt"), "{disposition}");
    let res = client
        .get(format!("http://{addr}/api/results/export"))
        .send()
        .await
        .unwrap();
    let body = res.text().await.unwrap();
    assert!(
        body.starts_with("ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms\n"),
        "{body}"
    );
}

#[tokio::test]
async fn mutating_requests_require_the_csrf_marker() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "forbidden");
    let (status, _) = request(
        addr,
        &format!(
            "POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1\r\n{CSRF_MARKER}Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn rejects_null_origin() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: null\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "forbidden");
    let (status, _) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 200);
    let own_origin = format!("http://127.0.0.1:{}", addr.port());
    let req = format!(
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {own_origin}\r\nConnection: close\r\n\r\n"
    );
    let (status, _) = request(addr, &req, None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn json_rejection_is_sanitized_and_truncated() {
    let addr = serve(FakeTransport::new()).await;
    let big = "x".repeat(2000);
    let body = format!(
        "{{\"mode\":\"Cdn\",\"target\":{{\"Preset\":\"Quick\"}},\"ports\":[443],\"bad\":\"{big}\"\nsecond line with control \x07 and https://user:pass@example.com/secret?token=abc#frag"
    );
    let req = format!(
        "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{CSRF_MARKER}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, text) = request(addr, &req, None).await;
    assert_eq!(status, 422, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    let msg = parsed["message"].as_str().unwrap();
    assert!(
        msg.chars().count() <= 512,
        "message must be truncated to 512 chars: {}",
        msg.chars().count()
    );
    assert!(!msg.contains('\x07'), "control chars must be stripped");
    assert!(
        !msg.contains("secret"),
        "query secrets must be redacted via sanitize"
    );
    assert_eq!(parsed["code"], "invalid_config");
}

#[tokio::test]
async fn error_responses_carry_machine_readable_codes() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "GET /api/nope HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 404);
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "not_found");

    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403);
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "forbidden");

    let mut t = FakeTransport::new();
    for i in 0..8u8 {
        t = t.ok_slow(format!("203.0.113.{i}").parse().unwrap(), 443, 25, 500);
    }
    let addr2 = serve(t).await;
    let body = serde_json::to_string(&cfg(1, 1)).unwrap();
    assert_eq!(post_scan(addr2, &body).await, 202);
    wait_until_running(addr2).await;
    let (status, text) = post_scan_full(addr2, &body).await;
    assert_eq!(status, 409);
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "conflict");

    let addr3 = serve(FakeTransport::new()).await;
    let mut bad = cfg(1, 1);
    bad.concurrency = 0;
    let (status, text) = post_scan_full(addr3, &serde_json::to_string(&bad).unwrap()).await;
    assert_eq!(status, 422);
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "invalid_config");

    let big = format!(
        "vless://x@1.2.3.4:443?{}",
        "a".repeat(crate::api::types::MAX_EXPORT_CONFIG_BYTES)
    );
    let body = serde_json::json!({"config": big, "ip": "203.0.113.7", "port": 443});
    let (status, text) = post_export(addr3, &body.to_string()).await;
    assert_eq!(status, 400);
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "bad_request");
}

#[test]
fn map_register_error_maps_variants() {
    use crate::warpgen::WarpRegisterError;
    let err = anyhow::Error::from(WarpRegisterError::Timeout);
    let api = map_register_error(err);
    assert_eq!(api.status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(api.code, "gateway_timeout");

    let err = anyhow::Error::from(WarpRegisterError::RateLimited);
    let api = map_register_error(err);
    assert_eq!(api.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(api.code, "rate_limited");

    let err = anyhow::Error::from(WarpRegisterError::Unauthorized { status: 401 });
    let api = map_register_error(err);
    assert_eq!(api.status, StatusCode::BAD_GATEWAY);
    assert_eq!(api.code, "upstream_error");
    assert!(api.message.contains("401"), "{}", api.message);

    let long_detail =
        "https://user:secret@example.com/x?token=abc ".to_string() + &"y".repeat(1000);
    let err = anyhow::Error::from(WarpRegisterError::Server {
        status: 500,
        detail: long_detail,
    });
    let api = map_register_error(err);
    assert_eq!(api.status, StatusCode::BAD_GATEWAY);
    assert!(api.message.contains("500"));
    assert!(!api.message.contains("secret"), "detail must be sanitized");
    assert!(
        api.message.chars().count() <= 600,
        "sanitized detail truncated"
    );

    let err = anyhow::Error::from(WarpRegisterError::Timeout).context("outer wrap");
    let api = map_register_error(err);
    assert_eq!(api.code, "gateway_timeout");

    let err = anyhow::anyhow!("some other network failure https://user:pass@example.com/q?x=1");
    let api = map_register_error(err);
    assert_eq!(api.code, "upstream_error");
    assert!(!api.message.contains("pass"), "fallback must sanitize");
}

#[tokio::test]
async fn warp_register_maps_typed_errors_over_http() {
    let _isolated = isolate_identity_dir();
    let timeout_reg: WarpRegistrar = Arc::new(|_| {
        Err(anyhow::Error::from(
            crate::warpgen::WarpRegisterError::Timeout,
        ))
    });
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        timeout_reg,
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 504, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "gateway_timeout");

    let rl_reg: WarpRegistrar = Arc::new(|_| {
        Err(anyhow::Error::from(
            crate::warpgen::WarpRegisterError::RateLimited,
        ))
    });
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        rl_reg,
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 429, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "rate_limited");
}

#[tokio::test]
async fn lagged_stream_stays_alive_with_terminal_snapshot() {
    let (tx, rx) = tokio::sync::broadcast::channel(2);
    let last = Arc::new(Mutex::new(Some((
        1u64,
        ScanEvent::Finished(ScanSummary {
            scanned: 8,
            found: 1,
            duration_ms: 5,
            cancelled: false,
        }),
    ))));
    let mut stream = TerminalBounded {
        rx: BroadcastStream::new(rx),
        _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
        done: false,
        replay: None,
        last_terminal: Arc::clone(&last),
        epoch: 1,
        controller: Arc::new(crate::engine::ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        ))),
        seen: std::collections::HashSet::new(),
        pending: std::collections::VecDeque::new(),
        last_resync: None,
    };
    tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
        scanned: 1,
        found: 0,
        total: Some(8),
    }))
    .unwrap();
    tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
        scanned: 2,
        found: 0,
        total: Some(8),
    }))
    .unwrap();
    tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
        scanned: 3,
        found: 0,
        total: Some(8),
    }))
    .unwrap();
    let item = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(item);
    let mut stayed_open = true;
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_millis(100), stream.next()).await {
            Err(_quiet) => break,
            Ok(None) => {
                stayed_open = false;
                break;
            }
            Ok(Some(_)) => continue,
        }
    }
    assert!(stayed_open, "stream must stay alive after Lagged replay");
}

async fn post_xray_download(addr: SocketAddr) -> (u16, String) {
    let req = format!(
        "POST /api/xray/download HTTP/1.1\r\nHost: 127.0.0.1\r\n{CSRF_MARKER}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    request(addr, &req, None).await
}

#[tokio::test]
async fn xray_download_is_rate_limited() {
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        canned_registrar(),
    )
    .await;
    let (status, _) = post_xray_download(addr).await;
    assert!(
        status == 200 || status == 502,
        "first download must pass the gate, got {status}"
    );
    let (status, text) = post_xray_download(addr).await;
    assert_eq!(
        status, 429,
        "second download within 60 s must be 429: {text}"
    );
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "rate_limited");
}

#[tokio::test]
async fn post_to_get_only_returns_405_with_code() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        &format!(
            "POST /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n{CSRF_MARKER}Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None,
    )
    .await;
    assert_eq!(status, 405, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "method_not_allowed");
}

#[tokio::test]
async fn post_scan_with_wrong_content_type_returns_415() {
    let addr = serve(FakeTransport::new()).await;
    let body = "{}";
    let (status, text) = request(
        addr,
        &format!(
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nX-Requested-With: cf-scanner\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
        None,
    )
    .await;
    assert_eq!(status, 415, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "unsupported_media_type");
}

#[tokio::test]
async fn forbidden_responses_carry_security_headers() {
    let addr = serve(FakeTransport::new()).await;
    let (status, text) = request(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
        None,
    )
    .await;
    assert_eq!(status, 403, "{text}");
    let headers = text.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or("");
    let lower = headers.to_ascii_lowercase();
    assert!(
        lower.contains("x-content-type-options: nosniff"),
        "missing nosniff on 403: {headers}"
    );
    assert!(
        lower.contains("referrer-policy: no-referrer"),
        "missing referrer-policy on 403: {headers}"
    );
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "forbidden");
}

#[tokio::test]
async fn warp_register_timeout_maps_to_504() {
    let _isolated = isolate_identity_dir();
    let timeout_reg: WarpRegistrar = Arc::new(|_| {
        Err(anyhow::Error::from(
            crate::warpgen::WarpRegisterError::Timeout,
        ))
    });
    let addr = serve_with_registrar(
        FakeTransport::new(),
        RangesState::load_text(BUNDLED_RANGES, None),
        timeout_reg,
    )
    .await;
    let (status, text) = post_register(addr, r#"{"license":null}"#).await;
    assert_eq!(status, 504, "{text}");
    let parsed: serde_json::Value = serde_json::from_str(json_body(&text)).unwrap();
    assert_eq!(parsed["code"], "gateway_timeout");
}

#[tokio::test]
async fn events_after_reset_does_not_replay_old_terminal() {
    let t = FakeTransport::new();
    for i in 0..8u8 {
        t.insert(format!("203.0.113.{i}").parse().unwrap(), 443, Ok(10));
    }
    let addr = serve(t).await;
    let body = cfg(1, 1);
    assert_eq!(
        post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
        202
    );
    wait_until_idle(addr).await;
    let (status, _) = request(
        addr,
        &format!(
            "POST /api/reset HTTP/1.1\r\nHost: 127.0.0.1\r\n{CSRF_MARKER}Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, text) = request(
        addr,
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        Some("event: finished"),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        !text.contains("event: finished"),
        "reset must not replay stale terminal: {text}"
    );
}

#[tokio::test]
async fn lagged_stream_with_cap_8_stays_alive_with_terminal() {
    let (tx, rx) = tokio::sync::broadcast::channel(8);
    let last = Arc::new(Mutex::new(Some((
        42u64,
        ScanEvent::Finished(ScanSummary {
            scanned: 8,
            found: 1,
            duration_ms: 5,
            cancelled: false,
        }),
    ))));
    let mut stream = TerminalBounded {
        rx: BroadcastStream::new(rx),
        _slot: try_acquire_sse_slot(&Arc::new(AtomicUsize::new(0))).unwrap(),
        done: false,
        replay: None,
        last_terminal: Arc::clone(&last),
        epoch: 42,
        controller: Arc::new(crate::engine::ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        ))),
        seen: std::collections::HashSet::new(),
        pending: std::collections::VecDeque::new(),
        last_resync: None,
    };
    for i in 0..16 {
        let _ = tx.send(ScanEvent::Progress(crate::api::types::ScanProgress {
            scanned: i,
            found: 0,
            total: Some(16),
        }));
    }
    let item = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(item);
    let mut stayed_open = true;
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_millis(100), stream.next()).await {
            Err(_) => break,
            Ok(None) => {
                stayed_open = false;
                break;
            }
            Ok(Some(_)) => continue,
        }
    }
    assert!(
        stayed_open,
        "stream must stay alive after Lagged with cap 8"
    );
}
