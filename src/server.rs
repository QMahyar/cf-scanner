//! Localhost HTTP API + embedded browser UI, both thin clients of the one
//! ScanController. Routes map engine state into the `api::types` contract
//! directly (those types ARE the wire contract); no engine type is
//! serialized.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Serialize;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::ServeDir;

use crate::api::types::{ScanConfig, ScanEvent, ScanSummary, Verdict};
use crate::engine::ScanController;

const EMBEDDED_INDEX: &str = include_str!("../embed/index.html");

/// A named ScanConfig held for the current session only. Never persisted.
#[derive(Serialize)]
struct ProfilePayload {
    name: String,
    config: ScanConfig,
}

struct AppState {
    controller: Arc<ScanController>,
    profiles: RwLock<HashMap<String, ScanConfig>>,
}

pub fn router(controller: Arc<ScanController>) -> Router {
    let state = Arc::new(AppState {
        controller,
        profiles: RwLock::new(HashMap::new()),
    });
    Router::new()
        .route("/", get(index))
        .route("/api/scan", post(start_scan))
        .route("/api/events", get(events))
        .route("/api/results", get(results))
        .route("/api/cancel", post(cancel))
        .route("/api/reset", post(reset))
        .route("/api/ranges", get(ranges))
        .route("/api/profiles", get(list_profiles))
        .route(
            "/api/profiles/{name}",
            put(put_profile).delete(delete_profile),
        )
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
}

async fn ranges() -> Json<RangesPayload> {
    let pool = crate::ranges::CidrPool::bundled();
    Json(RangesPayload {
        bundled: pool.ranges().iter().map(|c| format!("{}", c)).collect(),
        host_count: pool.host_count().min(u64::MAX as u128) as u64,
    })
}

/// Session-lifetime profiles in name order (inert data; the UI decides how to
/// load them into the scan form).
async fn list_profiles(State(state): State<Arc<AppState>>) -> Json<Vec<ProfilePayload>> {
    let profiles = state.profiles.read().await;
    let mut out: Vec<ProfilePayload> = profiles
        .iter()
        .map(|(name, config)| ProfilePayload {
            name: name.clone(),
            config: config.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Json(out)
}

/// Upsert: 201 when the name is new, 200 when it replaces an existing
/// profile; the body is always the stored profile.
async fn put_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(cfg): Json<ScanConfig>,
) -> Result<(StatusCode, Json<ProfilePayload>), ApiError> {
    validate_profile_name(&name).map_err(ApiError::bad_request)?;
    cfg.validate().map_err(ApiError::bad_request)?;
    let mut profiles = state.profiles.write().await;
    let created = profiles.insert(name.clone(), cfg.clone()).is_none();
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(ProfilePayload { name, config: cfg })))
}

async fn delete_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let removed = state.profiles.write().await.remove(&name).is_some();
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "profile {name:?} does not exist"
        )))
    }
}

fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("profile name must not be empty".to_owned());
    }
    if name.chars().count() > 64 {
        return Err("profile name must be at most 64 characters".to_owned());
    }
    if name.chars().any(char::is_control) {
        return Err("profile name must not contain control characters".to_owned());
    }
    Ok(())
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

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
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
    /// returns its address.
    async fn serve(t: FakeTransport) -> SocketAddr {
        let controller = Arc::new(ScanController::new(Arc::new(t)));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(controller)).await.unwrap();
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

    async fn get_profiles(addr: SocketAddr) -> (u16, String) {
        request(
            addr,
            "GET /api/profiles HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await
    }

    /// Response body without the HTTP header block.
    fn response_body(text: &str) -> &str {
        text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(text)
    }

    async fn put_profile(addr: SocketAddr, name: &str, body: &str) -> (u16, String) {
        let req = format!(
            "PUT /api/profiles/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            name,
            body.len(),
            body
        );
        request(addr, &req, None).await
    }

    async fn delete_profile(addr: SocketAddr, name: &str) -> (u16, String) {
        let req = format!(
            "DELETE /api/profiles/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            name
        );
        request(addr, &req, None).await
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
        // The field is serde-defaulted so older clients keep working.
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

    #[tokio::test]
    async fn ranges_endpoint_reports_bundled_pool() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = request(
            addr,
            "GET /api/ranges HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            None,
        )
        .await;
        assert_eq!(status, 200);
        assert!(text.contains("\"bundled\":["), "{text}");
        assert!(text.contains("\"host_count\":"));
        assert!(text.contains("173.245.48.0/20"), "{text}");
    }

    #[tokio::test]
    async fn profiles_list_starts_empty() {
        let addr = serve(FakeTransport::new()).await;
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        assert_eq!(response_body(&text).trim(), "[]", "{text}");
    }

    #[tokio::test]
    async fn put_creates_profile_with_201() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let (status, text) = put_profile(addr, "quick", &body).await;
        assert_eq!(status, 201, "{text}");
        assert!(text.contains("\"name\":\"quick\""), "{text}");
        assert!(text.contains("\"mode\":\"Cdn\""), "{text}");
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        assert!(text.contains("\"name\":\"quick\""), "{text}");
    }

    #[tokio::test]
    async fn put_upserts_existing_profile_with_200() {
        let addr = serve(FakeTransport::new()).await;
        let first = serde_json::to_string(&cfg(1, 1)).unwrap();
        let second = serde_json::to_string(&cfg(2, 1)).unwrap();
        assert_eq!(put_profile(addr, "quick", &first).await.0, 201);
        let (status, text) = put_profile(addr, "quick", &second).await;
        assert_eq!(status, 200, "{text}");
        assert!(text.contains("\"Count\":2"), "{text}");
        let (_, text) = get_profiles(addr).await;
        assert!(text.contains("\"Count\":2"), "{text}");
    }

    #[tokio::test]
    async fn delete_removes_profile_then_404s() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        assert_eq!(put_profile(addr, "quick", &body).await.0, 201);
        let (status, _) = delete_profile(addr, "quick").await;
        assert_eq!(status, 204);
        let (_, text) = get_profiles(addr).await;
        assert_eq!(response_body(&text).trim(), "[]", "{text}");
        let (status, _) = delete_profile(addr, "quick").await;
        assert_eq!(status, 404);
    }
    #[tokio::test]
    async fn put_rejects_invalid_config() {
        let addr = serve(FakeTransport::new()).await;
        let mut bad = cfg(1, 1);
        bad.ports = vec![0];
        let body = serde_json::to_string(&bad).unwrap();
        let (status, _) = put_profile(addr, "quick", &body).await;
        assert_eq!(status, 400);
        let (_, text) = get_profiles(addr).await;
        assert_eq!(
            response_body(&text).trim(),
            "[]",
            "invalid config must not be stored"
        );
    }

    #[tokio::test]
    async fn put_rejects_invalid_names() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        // 65 characters.
        let long = "a".repeat(65);
        assert_eq!(put_profile(addr, &long, &body).await.0, 400);
        // Percent-encoded control character.
        assert_eq!(put_profile(addr, "bad%01name", &body).await.0, 400);
        let (_, text) = get_profiles(addr).await;
        assert_eq!(
            response_body(&text).trim(),
            "[]",
            "invalid names must not be stored"
        );
    }

    #[test]
    fn profile_name_validation() {
        assert!(validate_profile_name("quick").is_ok());
        assert!(validate_profile_name(&"a".repeat(64)).is_ok());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name(&"a".repeat(65)).is_err());
        assert!(validate_profile_name("has\tcontrol").is_err());
    }

    #[tokio::test]
    async fn concurrent_profile_access_is_safe() {
        let addr = serve(FakeTransport::new()).await;
        let body = serde_json::to_string(&cfg(1, 1)).unwrap();
        let mut writers = Vec::new();
        for i in 0..50 {
            let body = body.clone();
            writers.push(tokio::spawn(async move {
                let name = format!("profile-{i:02}");
                let (status, _) = put_profile(addr, &name, &body).await;
                assert_eq!(status, 201);
            }));
        }
        let reader = tokio::spawn(async move {
            for _ in 0..20 {
                let (status, text) = get_profiles(addr).await;
                assert_eq!(status, 200);
                let parsed: Vec<serde_json::Value> =
                    serde_json::from_str(response_body(&text)).unwrap();
                assert!(parsed.len() <= 50, "{text}");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        for writer in writers {
            writer.await.unwrap();
        }
        reader.await.unwrap();
        let (status, text) = get_profiles(addr).await;
        assert_eq!(status, 200);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(response_body(&text)).unwrap();
        assert_eq!(parsed.len(), 50, "{text}");
        for i in 0..50 {
            let name = format!("profile-{i:02}");
            assert!(
                parsed.iter().any(|p| p["name"] == name),
                "missing {name}: {text}"
            );
        }
    }
}
