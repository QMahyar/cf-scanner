//! Localhost HTTP API + embedded browser UI, both thin clients of the one
//! ScanController. Routes map engine state into the `api::types` contract
//! directly (those types ARE the wire contract); no engine type is
//! serialized.

use std::convert::Infallible;
use std::fs;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::ServeDir;

use crate::api::types::{ScanConfig, ScanEvent, ScanSummary, Verdict};
use crate::engine::ScanController;
use crate::paths;
use crate::ranges::{self, CidrPool, HttpGet};

const EMBEDDED_INDEX: &str = include_str!("../embed/index.html");
const DEFAULT_RANGES_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

struct AppState {
    controller: Arc<ScanController>,
    ranges: Arc<RangesState>,
}

/// What /api/ranges serves: the current pool plus when it was last refreshed.
struct RangesInner {
    pool: CidrPool,
    last_updated: Option<String>,
}

type Persist = Box<dyn Fn(&CidrPool, &str) -> anyhow::Result<()> + Send + Sync>;

struct RangesState {
    inner: RwLock<RangesInner>,
    persist: Persist,
}

impl RangesState {
    /// Production state: the refreshed data-dir file when present, else the
    /// bundled list; the embedded-list load time stands in for last_updated
    /// until the first successful refresh.
    fn load() -> Arc<Self> {
        let text = paths::refreshed_ranges_path()
            .ok()
            .and_then(|p| fs::read_to_string(p).ok());
        let now = ranges::rfc3339_utc(ranges::unix_now());
        let (pool, last_updated) = match text {
            Some(text) => (
                CidrPool::parse(&text).unwrap_or_else(|_| CidrPool::bundled()),
                ranges::last_updated_of(&text).or(Some(now)),
            ),
            None => (CidrPool::bundled(), Some(now)),
        };
        Arc::new(Self {
            inner: RwLock::new(RangesInner { pool, last_updated }),
            persist: Box::new(ranges::write_pool),
        })
    }

    /// Test constructor: persistence is a no-op so background-refresh tests
    /// never touch the data dir.
    #[cfg(test)]
    fn load_text(text: &str, last_updated: Option<&str>) -> Arc<Self> {
        let pool = CidrPool::parse(text).unwrap_or_else(|_| CidrPool::bundled());
        Arc::new(Self {
            inner: RwLock::new(RangesInner {
                pool,
                last_updated: last_updated.map(str::to_owned),
            }),
            persist: Box::new(|_, _| Ok(())),
        })
    }

    /// One refresh cycle: fetch + validate, persist (best-effort, logged),
    /// then swap the in-memory snapshot. Errors leave the last good data.
    async fn refresh(&self, http: &impl HttpGet) -> anyhow::Result<()> {
        let pool = ranges::fetch_official(http).await?;
        let last_updated = ranges::rfc3339_utc(ranges::unix_now());
        if let Err(err) = (self.persist)(&pool, &last_updated) {
            tracing::warn!("ranges refresh: could not persist to disk: {err:#}");
        }
        let mut inner = self.inner.write().expect("ranges state lock");
        inner.pool = pool;
        inner.last_updated = Some(last_updated);
        Ok(())
    }

    /// Spawns the refresh loop; `interval` overrides the 24h default (tests
    /// use a short one). Never ends; a failed cycle is logged and the last
    /// good data stays in place. The first tick fires immediately.
    fn spawn_refresh<H>(self: &Arc<Self>, interval: Option<Duration>, http: Arc<H>)
    where
        H: HttpGet + Send + Sync + 'static,
    {
        let interval = interval.unwrap_or(DEFAULT_RANGES_REFRESH_INTERVAL);
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(err) = this.refresh(http.as_ref()).await {
                    tracing::warn!(
                        "ranges background refresh failed (keeping last good data): {err:#}"
                    );
                }
            }
        });
    }
}

pub fn router(controller: Arc<ScanController>) -> Router {
    let ranges = RangesState::load();
    ranges.spawn_refresh(None, Arc::new(ranges::RealHttp));
    router_with(controller, ranges)
}

/// Router with an injected ranges state (tests).
fn router_with(controller: Arc<ScanController>, ranges_state: Arc<RangesState>) -> Router {
    let state = Arc::new(AppState {
        controller,
        ranges: ranges_state,
    });
    Router::new()
        .route("/", get(index))
        .route("/api/scan", post(start_scan))
        .route("/api/events", get(events))
        .route("/api/results", get(results))
        .route("/api/cancel", post(cancel))
        .route("/api/reset", post(reset))
        .route("/api/ranges", get(ranges))
        // Task 7 iterates on `embed/` without rebuilding; release builds fall
        // back to nothing (the UI is embedded above), which 404s non-UI paths.
        .fallback_service(ServeDir::new("embed"))
        .with_state(state)
}

/// 202 with no body; the run's progress is observable on /api/events. 409
/// when another scan is already running (the engine rejects double-runs).
async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<ScanConfig>,
) -> Result<StatusCode, ApiError> {
    cfg.validate().map_err(ApiError::bad_request)?;
    if state.controller.is_running() {
        return Err(ApiError::conflict("a scan is already running"));
    }
    let controller = state.controller.clone();
    tokio::spawn(async move {
        if let Err(err) = controller.run(cfg).await {
            tracing::error!("scan failed: {err:#}");
        }
    });
    Ok(StatusCode::ACCEPTED)
}

async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.controller.subscribe()).filter_map(|event| {
        match event {
            Ok(ScanEvent::Progress(p)) => Event::default().event("progress").json_data(p).ok(),
            Ok(ScanEvent::Result(v)) => Event::default().event("result").json_data(*v).ok(),
            Ok(ScanEvent::Finished(s)) => Event::default().event("finished").json_data(s).ok(),
            Ok(ScanEvent::Failed(msg)) => Event::default().event("failed").json_data(msg).ok(),
            Err(_lagged) => None,
        }
        .map(Ok)
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Serialize)]
struct ResultsPayload {
    results: Vec<Verdict>,
    summary: Option<ScanSummary>,
}

async fn results(State(state): State<Arc<AppState>>) -> Json<ResultsPayload> {
    Json(ResultsPayload {
        results: state.controller.results(),
        summary: state.controller.summary(),
    })
}

async fn cancel(State(state): State<Arc<AppState>>) -> StatusCode {
    state.controller.cancel();
    StatusCode::NO_CONTENT
}

async fn reset(State(state): State<Arc<AppState>>) -> StatusCode {
    state.controller.reset();
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct RangesPayload {
    bundled: Vec<String>,
    host_count: u64,
    /// RFC3339 UTC of the last successful refresh (or the embedded-list load
    /// time); None before anything has been loaded.
    last_updated: Option<String>,
}

async fn ranges(State(state): State<Arc<AppState>>) -> Json<RangesPayload> {
    let inner = state.ranges.inner.read().expect("ranges state lock");
    Json(RangesPayload {
        bundled: inner.pool.ranges().iter().map(|c| format!("{c}")).collect(),
        host_count: inner.pool.host_count(),
        last_updated: inner.last_updated.clone(),
    })
}

async fn index() -> impl IntoResponse {
    Html(EMBEDDED_INDEX)
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use crate::api::types::{Mode, ScanTarget, StopCondition};
    use crate::probe::FakeTransport;
    use crate::ranges::BUNDLED_RANGES;

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
            // Explicit pool input keeps tests off the filesystem ranges.
            custom_cidrs: vec!["10.0.0.0/29".to_owned()],
            ports: vec![443],
            concurrency: 1,
            ..ScanConfig::default()
        }
    }

    /// Spawns the router on an ephemeral port with a scripted transport and
    /// returns its address. Ranges are the bundled list with no timestamp.
    async fn serve(t: FakeTransport) -> SocketAddr {
        serve_with_ranges(t, RangesState::load_text(BUNDLED_RANGES, None)).await
    }

    async fn serve_with_ranges(t: FakeTransport, ranges: Arc<RangesState>) -> SocketAddr {
        let controller = Arc::new(ScanController::new(Arc::new(t)));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router_with(controller, ranges))
                .await
                .unwrap();
        });
        addr
    }

    /// Raw HTTP/1.1 over a throwaway TCP connection. Reads until EOF or
    /// `until` (for endless streams like SSE) or a 2 s deadline, and returns
    /// the status code plus what was read. The write half is NOT shutdown:
    /// hyper closes the connection without responding when the client FINs
    /// immediately after the request.
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
                    Ok(0) => break, // EOF
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
        let req = format!(
            "POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        request(addr, &req, None).await.0
    }

    /// Scripts every host of the /29 so count-sampled runs are deterministic
    /// regardless of which hosts the seeded RNG draws.
    fn script_all_hosts(t: &FakeTransport, latency: u32) {
        for i in 0..8u8 {
            t.insert(format!("10.0.0.{i}").parse().unwrap(), 443, Ok(latency));
        }
    }

    #[tokio::test]
    async fn serves_index_html() {
        let addr = serve(FakeTransport::new()).await;
        let (status, body) = request(
            addr,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("CF-Scanner"));
    }

    #[tokio::test]
    async fn rejects_invalid_scan_config() {
        let addr = serve(FakeTransport::new()).await;
        let body = r#"{"mode":"Cdn","target":{"Preset":"Quick"},"ports":[0],"stop":{"found":1,"cap":null},"exclude":[],"custom_cidrs":[],"concurrency":1,"timeout_ms":3000,"phase2":null,"warp":null}"#;
        let status = post_scan(addr, body).await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn scan_results_and_summary_roundtrip() {
        let t = FakeTransport::new();
        script_all_hosts(&t, 25);
        let addr = serve(t).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        assert_eq!(post_scan(addr, &body).await, 202);

        // The scan runs in a background task; poll until it finishes.
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
    async fn events_stream_emits_progress_and_finished() {
        // A slow probe keeps the scan alive long enough for the SSE
        // subscription to attach before the run finishes.
        let t = FakeTransport::new();
        script_all_hosts(&t, 25);
        let addr = serve(t).await;
        let events = tokio::spawn(request(
            addr,
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            Some("event: finished"),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let body = cfg(1, 1);
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
            202
        );
        let (_, text) = events.await.unwrap();
        assert!(text.contains("event: progress"), "{text}");
        assert!(text.contains("event: result"), "{text}");
        assert!(text.contains("event: finished"), "{text}");
    }

    #[tokio::test]
    async fn second_scan_while_running_is_conflict() {
        // All /29 hosts probe slowly so the count-sampled plan keeps the run
        // alive while the second POST arrives.
        let mut t = FakeTransport::new();
        for i in 0..8u8 {
            t = t.ok_slow(format!("10.0.0.{i}").parse().unwrap(), 443, 25, 500);
        }
        let addr = serve(t).await;
        let body = cfg(1, 1);
        assert_eq!(
            post_scan(addr, &serde_json::to_string(&body).unwrap()).await,
            202
        );
        // Give the spawned run task time to reach the running guard.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let body = cfg(1, 1);
        let status = post_scan(addr, &serde_json::to_string(&body).unwrap()).await;
        assert_eq!(status, 409);
    }

    #[tokio::test]
    async fn cancel_and_reset_are_noops_without_scan() {
        let addr = serve(FakeTransport::new()).await;
        let (status, _) = request(addr, "POST /api/cancel HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", None).await;
        assert_eq!(status, 204);
        let (status, _) = request(addr, "POST /api/reset HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", None).await;
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

    /// The JSON body after the HTTP header block.
    fn json_body(text: &str) -> &str {
        text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(text)
    }

    #[tokio::test]
    async fn ranges_endpoint_reports_bundled_pool() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        assert!(text.contains("\"bundled\":["), "{text}");
        assert!(text.contains("\"host_count\":"));
        assert!(text.contains("\"last_updated\":null"), "{text}");
        assert!(text.contains("173.245.48.0/20"), "{text}");
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
        let ranges = RangesState::load_text("10.0.0.0/8", None);
        ranges.spawn_refresh(
            Some(Duration::from_millis(20)),
            Arc::new(FakeHttp(OFFICIAL_FIXTURE)),
        );
        let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
        for _ in 0..50 {
            let (status, text) = get_ranges(addr).await;
            if status == 200 && text.contains("10.1.0.0/16") {
                let payload: serde_json::Value =
                    serde_json::from_str(json_body(&text)).expect("ranges payload JSON");
                let ts = payload["last_updated"].as_str().expect("last_updated set");
                assert!(ts.ends_with('Z'), "{ts}");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("background refresh did not update the ranges payload");
    }

    #[tokio::test]
    async fn background_refresh_failure_keeps_last_good_data() {
        let ranges = RangesState::load_text("10.0.0.0/8", Some("2026-01-01T00:00:00Z"));
        ranges.spawn_refresh(Some(Duration::from_millis(20)), Arc::new(FailingHttp));
        let addr = serve_with_ranges(FakeTransport::new(), ranges).await;
        // Let several failed cycles elapse; the state must not move.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let (status, text) = get_ranges(addr).await;
        assert_eq!(status, 200);
        assert!(text.contains("10.0.0.0/8"), "{text}");
        assert!(!text.contains("10.1.0.0/16"), "{text}");
        assert!(
            text.contains("\"last_updated\":\"2026-01-01T00:00:00Z\""),
            "{text}"
        );
    }
}
