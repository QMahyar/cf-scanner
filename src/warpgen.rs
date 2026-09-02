use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paths;
use crate::ranges::unix_now;
use crate::wgconf::{WgConfig, WgPeer, render_wgconf};

const DEFAULT_API_BASE: &str = "https://api.cloudflareclient.com";
pub const DEFAULT_ENDPOINT: &str = "engage.cloudflareclient.com:2408";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, thiserror::Error)]
pub enum WarpRegisterError {
    #[error("registration timed out")]
    Timeout,
    #[error("registration rate limited")]
    RateLimited,
    #[error("registration rejected ({status})")]
    Unauthorized { status: u16 },
    #[error("registration server error ({status})")]
    Server { status: u16, detail: String },
}
const MAX_ATTEMPTS: u32 = 3;
const RETRY_SLEEP: Duration = Duration::from_millis(300);
const DNS: &str = "1.1.1.1, 1.0.0.1";

pub fn keygen() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

#[derive(Clone, Debug, Deserialize)]
struct Device {
    id: String,
    token: Option<String>,
    account: Account,
    config: DeviceConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct Account {
    #[serde(rename = "account_type")]
    account_type: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeviceConfig {
    client_id: String,
    interface: InterfaceConfig,
    peers: Vec<DevicePeer>,
}

#[derive(Clone, Debug, Deserialize)]
struct InterfaceConfig {
    addresses: NetworkAddress,
}

#[derive(Clone, Debug, Deserialize)]
struct NetworkAddress {
    v4: String,
    v6: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DevicePeer {
    public_key: String,
    endpoint: PeerEndpoint,
    #[serde(default)]
    allowed_ips: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PeerEndpoint {
    host: String,
}

struct WarpClient {
    base: String,
    timeout: Duration,
}

impl WarpClient {
    fn new(base: String, timeout: Duration) -> Self {
        Self { base, timeout }
    }

    fn http_client(timeout: Duration) -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error("too many redirects");
                }
                if let Err(err) = crate::ranges::validate_fetch_url(attempt.url().as_str()) {
                    return attempt.error(err.to_string());
                }
                attempt.follow()
            }))
            .build()?)
    }

    async fn attempt(
        &self,
        label: &str,
        retryable_transport: bool,
        build: impl Fn(reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<String> {
        let mut last: Option<WarpRegisterError> = None;
        let mut next_delay = RETRY_SLEEP;
        let mut tried = 0u32;
        for _ in 0..MAX_ATTEMPTS {
            if tried > 0 {
                tokio::time::sleep(next_delay).await;
                next_delay = RETRY_SLEEP;
            }
            tried += 1;
            let result = build(Self::http_client(self.timeout)?).send().await;
            let resp = match result {
                Ok(resp) => resp,
                Err(err) => {
                    last = Some(if err.is_timeout() {
                        WarpRegisterError::Timeout
                    } else {
                        let detail = crate::configs::sanitize_error_text(&format!("{err}"));
                        WarpRegisterError::Server { status: 0, detail }
                    });
                    if !retryable_transport {
                        break;
                    }
                    continue;
                }
            };
            let status_code = resp.status();
            let status = status_code.as_u16();
            let retry_after = parse_retry_after(resp.headers());
            let text = match resp.text().await {
                Ok(t) => t,
                Err(err) => {
                    last = Some(if err.is_timeout() {
                        WarpRegisterError::Timeout
                    } else {
                        let detail = crate::configs::sanitize_error_text(&format!("{err}"));
                        WarpRegisterError::Server { status, detail }
                    });
                    if !retryable_transport {
                        break;
                    }
                    continue;
                }
            };
            if status_code.is_success() {
                return Ok(text);
            }
            let sanitized = crate::configs::sanitize_error_text(&text);
            if status == 429 {
                last = Some(WarpRegisterError::RateLimited);
                next_delay = retry_delay(retry_after, RETRY_SLEEP, self.timeout);
                continue;
            }
            if status == 401 || status == 403 {
                return Err(WarpRegisterError::Unauthorized { status }.into());
            }
            if status_code.is_server_error() {
                last = Some(WarpRegisterError::Server {
                    status,
                    detail: sanitized,
                });
                continue;
            }
            return Err(WarpRegisterError::Server {
                status,
                detail: sanitized,
            }
            .into());
        }
        let err = last.unwrap_or(WarpRegisterError::Timeout);
        Err(err).context(format!("v0a884 {label} failed after {tried} attempt(s)"))
    }

    async fn post_json(&self, path: &str, body: impl Serialize) -> Result<String> {
        let body = serde_json::to_value(body)?;
        self.attempt(path, false, |http| {
            http.post(format!("{}/{}", self.base, path))
                .header("User-Agent", "okhttp/3.12.1")
                .json(&body)
        })
        .await
    }

    async fn authed(
        &self,
        token: &str,
        method: reqwest::Method,
        path: String,
        body: Option<serde_json::Value>,
    ) -> Result<String> {
        let url = format!("{}/{}", self.base, path);
        self.attempt(&path, true, |http| {
            let mut req = http
                .request(method.clone(), url.clone())
                .header("User-Agent", "okhttp/3.12.1")
                .header("Authorization", format!("Bearer {token}"));
            if let Some(body) = &body {
                req = req.json(body);
            }
            req
        })
        .await
    }

    async fn register(&self, public_b64: &str) -> Result<Device> {
        let body = serde_json::json!({
            "install_id": "",
            "fcm_token": "",
            "key": public_b64,
            "locale": "en_US",
            "model": "PC",
            "tos": tos_timestamp(),
            "type": "Android",
        });
        let text = self.post_json("v0a884/reg", body).await?;
        serde_json::from_str(&text).context("malformed registration response")
    }

    async fn enable_warp(&self, id: &str, token: &str) -> Result<()> {
        self.authed(
            token,
            reqwest::Method::PATCH,
            format!("v0a884/reg/{id}"),
            Some(serde_json::json!({"warp_enabled": true})),
        )
        .await
        .map(|_| ())
    }

    async fn bind_license(&self, id: &str, token: &str, license: &str) -> Result<()> {
        self.authed(
            token,
            reqwest::Method::PUT,
            format!("v0a884/reg/{id}/account"),
            Some(serde_json::json!({"license": license})),
        )
        .await
        .map(|_| ())
    }

    async fn fetch(&self, id: &str, token: &str) -> Result<Device> {
        let text = self
            .authed(
                token,
                reqwest::Method::GET,
                format!("v0a884/reg/{id}"),
                None,
            )
            .await?;
        serde_json::from_str(&text).context("malformed config response")
    }
}

fn retry_delay(retry_after: Option<Duration>, fallback: Duration, cap: Duration) -> Duration {
    retry_after.unwrap_or(fallback).min(cap)
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    Some(Duration::from_secs(raw.trim().parse().ok()?))
}

#[derive(Serialize, Deserialize)]
struct Identity {
    id: String,
    token: String,
    private_key: String,
    client_id: String,
    account_type: String,
    license: Option<String>,
    created_at: u64,
    #[serde(default)]
    peer_public_key: Option<String>,
}

fn identity_path() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CF_SCANNER_DATA_DIR") {
        return Ok(PathBuf::from(dir).join("identity.json"));
    }
    Ok(paths::data_dir()?.join("identity.json"))
}

fn save_identity(identity: &Identity) -> Result<()> {
    let path = identity_path()?;
    let json = serde_json::to_string_pretty(identity)?;
    let _gate = crate::paths::data_write_guard();
    write_private_replace(&path, &json).with_context(|| format!("writing {}", path.display()))
}

fn load_identity() -> Result<Identity> {
    let json = fs::read_to_string(identity_path()?)?;
    serde_json::from_str(&json).context("corrupt identity file")
}

pub fn has_identity() -> bool {
    load_identity().is_ok()
}

pub fn persisted_server_public_key() -> Option<String> {
    let identity = match load_identity() {
        Ok(identity) => identity,
        Err(err) => {
            if identity_path().map(|p| p.exists()).unwrap_or(false) {
                tracing::warn!(
                    "persisted WARP identity unreadable; falling back to the bundled server key: {err:#}"
                );
            }
            return None;
        }
    };
    let key = identity.peer_public_key;
    if key.as_deref().map(str::is_empty) != Some(false) {
        return None;
    }
    let raw = key.as_deref().unwrap_or_default();
    match crate::wgconf::decode_key(raw) {
        Ok(_) => Some(key.unwrap_or_default()),
        Err(_) => {
            tracing::warn!("persisted WARP server key invalid; falling back to bundled");
            None
        }
    }
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(text.as_bytes())?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        crate::paths::write_secret(path, text.as_bytes())?;
    }
    Ok(())
}

fn write_private_replace(dest: &Path, text: &str) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_owned());
    let tmp = dest.with_file_name(format!(
        "{name}.tmp-{}-{:08x}",
        std::process::id(),
        random_u32()
    ));
    write_private(&tmp, text)?;
    fs::rename(&tmp, dest)?;
    Ok(())
}

fn random_u32() -> u32 {
    RngCore::next_u32(&mut OsRng)
}

fn build_wgconf(
    secret: &StaticSecret,
    dev: &Device,
    endpoint_override: Option<&str>,
) -> Result<WgConfig> {
    let private_key = base64::engine::general_purpose::STANDARD.encode(secret.to_bytes());
    let peer = dev
        .config
        .peers
        .first()
        .ok_or_else(|| anyhow!("registration response carried no peer"))?;
    let addresses = &dev.config.interface.addresses;
    let address = [addresses.v4.as_str(), addresses.v6.as_str()]
        .into_iter()
        .filter(|a| !a.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    let allowed_ips = if peer.allowed_ips.is_empty() {
        vec!["0.0.0.0/0".into(), "::/0".into()]
    } else {
        peer.allowed_ips.clone()
    };
    Ok(WgConfig {
        private_key,
        address,
        dns: Some(DNS.to_owned()),
        mtu: Some(1420),
        amnezia: Default::default(),
        peer: WgPeer {
            public_key: peer.public_key.clone(),
            allowed_ips,
            endpoint: Some(
                endpoint_override
                    .map(str::to_owned)
                    .unwrap_or_else(|| peer_endpoint(&peer.endpoint)),
            ),
            persistent_keepalive: None,
            preshared_key: None,
        },
    })
}

fn peer_endpoint(endpoint: &PeerEndpoint) -> String {
    let host = endpoint.host.trim();
    if host.is_empty() {
        return DEFAULT_ENDPOINT.to_owned();
    }
    if host.contains(':') {
        host.to_owned()
    } else {
        format!("{host}:2408")
    }
}

async fn register_flow(
    base: &str,
    license: Option<&str>,
    endpoint_override: Option<&str>,
) -> Result<String> {
    let client = WarpClient::new(base.to_owned(), DEFAULT_TIMEOUT);
    let (secret, public) = keygen();
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    let reg = client.register(&public_b64).await?;
    let token = reg
        .token
        .clone()
        .context("registration response carried no token")?;
    client.enable_warp(&reg.id, &token).await?;
    if let Some(license) = license.filter(|l| !l.trim().is_empty()) {
        client.bind_license(&reg.id, &token, license).await?;
    }
    let reg = client.fetch(&reg.id, &token).await?;
    let wgconf = build_wgconf(&secret, &reg, endpoint_override)?;
    let text = render_wgconf(&wgconf);
    let identity = Identity {
        id: reg.id.clone(),
        token,
        private_key: wgconf.private_key.clone(),
        client_id: reg.config.client_id.clone(),
        account_type: reg.account.account_type.clone(),
        license: license.map(str::to_owned),
        created_at: unix_now(),
        peer_public_key: reg.config.peers.first().map(|p| p.public_key.clone()),
    };
    save_identity(&identity)?;
    Ok(text)
}

pub async fn generate(
    out: Option<&Path>,
    license: Option<&str>,
    endpoint_override: Option<&str>,
) -> Result<String> {
    let text = register_flow(DEFAULT_API_BASE, license, endpoint_override).await?;
    write_out(out, &text)?;
    Ok(text)
}

pub async fn register(license: Option<&str>) -> Result<String> {
    register_flow(DEFAULT_API_BASE, license, None).await
}

#[cfg(test)]
async fn register_with_base(base: String, license: Option<&str>) -> Result<String> {
    register_flow(&base, license, None).await
}

pub async fn export(out: Option<&Path>, endpoint_override: Option<&str>) -> Result<String> {
    let identity = load_identity().context("no saved identity; run `warpconfig generate` first")?;
    let client = WarpClient::new(DEFAULT_API_BASE.into(), DEFAULT_TIMEOUT);
    let reg = client.fetch(&identity.id, &identity.token).await?;
    let secret = StaticSecret::from(crate::wgconf::decode_key(&identity.private_key)?);
    let text = render_wgconf(&build_wgconf(&secret, &reg, endpoint_override)?);
    write_out(out, &text)?;
    Ok(text)
}

fn write_out(out: Option<&Path>, text: &str) -> Result<()> {
    match out {
        Some(path) => {
            write_private(path, text).with_context(|| format!("writing {}", path.display()))?;
        }
        None => write_stdout(text),
    }
    Ok(())
}

fn write_stdout(text: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

fn tos_timestamp() -> String {
    let base = crate::ranges::rfc3339_utc(crate::ranges::unix_now());
    let without_z = base.strip_suffix('Z').unwrap_or(&base);
    format!("{without_z}.00+00:00")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::Mutex;

    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode},
        routing::{get, patch, post, put},
    };

    type MockSeen = std::sync::Arc<Mutex<Vec<(String, String, String)>>>;

    fn mock_registration() -> serde_json::Value {
        serde_json::json!({
            "id": "reg-1",
            "token": "tok-1",
            "warp_enabled": true,
            "account": {
                "account_type": "free",
                "license": "",
                "warp_plus": false
            },
            "config": {
                "client_id": "cid-1",
                "interface": {
                    "addresses": {
                        "v4": "172.16.0.2/32",
                        "v6": "2606:4700::1/128"
                    }
                },
                "peers": [{
                    "public_key": "kkk",
                    "endpoint": {
                        "host": "engage.cloudflareclient.com",
                        "v4": "162.159.192.5",
                        "v6": "2606:4700:d0::a29f:c005"
                    },
                    "allowed_ips": ["0.0.0.0/0", "::/0"]
                }]
            }
        })
    }

    fn mock_authorized(headers: &HeaderMap) -> bool {
        headers.get("authorization") == Some(&HeaderValue::from_static("Bearer tok-1"))
    }

    async fn mock_register(
        State(seen): State<MockSeen>,
        body: Bytes,
    ) -> (StatusCode, Json<serde_json::Value>) {
        seen.lock().unwrap().push((
            "POST".into(),
            "/v0a884/reg".into(),
            String::from_utf8_lossy(&body).into_owned(),
        ));
        (StatusCode::OK, Json(mock_registration()))
    }

    async fn mock_patch(
        State(seen): State<MockSeen>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
        if !mock_authorized(&headers) {
            return Err((StatusCode::UNAUTHORIZED, "no bearer".into()));
        }
        seen.lock().unwrap().push((
            "PATCH".into(),
            "/v0a884/reg/reg-1".into(),
            String::from_utf8_lossy(&body).into_owned(),
        ));
        Ok((StatusCode::OK, Json(mock_registration())))
    }

    async fn mock_put_account(
        State(seen): State<MockSeen>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
        if !mock_authorized(&headers) {
            return Err((StatusCode::UNAUTHORIZED, "no bearer".into()));
        }
        seen.lock().unwrap().push((
            "PUT".into(),
            "/v0a884/reg/reg-1/account".into(),
            String::from_utf8_lossy(&body).into_owned(),
        ));
        Ok((StatusCode::OK, Json(mock_registration())))
    }

    async fn mock_fetch(
        State(seen): State<MockSeen>,
        headers: HeaderMap,
    ) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
        if !mock_authorized(&headers) {
            return Err((StatusCode::UNAUTHORIZED, "no bearer".into()));
        }
        seen.lock()
            .unwrap()
            .push(("GET".into(), "/v0a884/reg/reg-1".into(), String::new()));
        Ok(Json(mock_registration()))
    }

    fn mock_app(seen: MockSeen) -> Router {
        Router::new()
            .route("/v0a884/reg", post(mock_register))
            .route("/v0a884/reg/{id}", patch(mock_patch))
            .route("/v0a884/reg/{id}", get(mock_fetch))
            .route("/v0a884/reg/{id}/account", put(mock_put_account))
            .with_state(seen)
    }

    #[test]
    fn keygen_produces_valid_distinct_keys() {
        let (a, pa) = keygen();
        let (_, pb) = keygen();
        assert_eq!(a.to_bytes().len(), 32);
        assert_ne!(pa.as_bytes(), pb.as_bytes());
    }

    #[test]
    fn tos_timestamp_is_rfc3339_and_sane() {
        let t = tos_timestamp();
        assert_eq!(t.len(), 28);
        assert_eq!(&t[10..11], "T");
        assert_eq!(&t[19..28], ".00+00:00");
        let year: u32 = t[..4].parse().unwrap();
        assert!((2020..=2035).contains(&year));
    }

    #[test]
    fn wgconf_builder_renders_expected_fields() {
        let (secret, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let dev = Device {
            id: "abc".into(),
            token: Some("tok".into()),
            account: Account {
                account_type: "free".into(),
            },
            config: DeviceConfig {
                client_id: public_b64,
                interface: InterfaceConfig {
                    addresses: NetworkAddress {
                        v4: "172.16.0.2/32".into(),
                        v6: "2606:4700:110:8b1f:abcd/128".into(),
                    },
                },
                peers: vec![DevicePeer {
                    public_key: "AAAA".into(),
                    endpoint: PeerEndpoint {
                        host: "engage.cloudflareclient.com".into(),
                    },
                    allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                }],
            },
        };
        let wg = build_wgconf(&secret, &dev, None).unwrap();
        assert_eq!(wg.peer.public_key, "AAAA");
        assert_eq!(
            wg.peer.endpoint.as_deref(),
            Some("engage.cloudflareclient.com:2408")
        );
        let ported = DevicePeer {
            endpoint: PeerEndpoint {
                host: "engage.cloudflareclient.com:2408".into(),
            },
            ..dev.config.peers[0].clone()
        };
        assert_eq!(
            peer_endpoint(&ported.endpoint),
            "engage.cloudflareclient.com:2408"
        );
        assert_eq!(wg.peer.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert!(wg.address.contains("172.16.0.2/32"));
        let over = build_wgconf(&secret, &dev, Some("1.2.3.4:2408")).unwrap();
        assert_eq!(over.peer.endpoint.as_deref(), Some("1.2.3.4:2408"));
        let text = render_wgconf(&wg);
        assert!(text.contains("PrivateKey"));
        assert!(text.contains("DNS = 1.1.1.1, 1.0.0.1"));
        assert!(text.contains("AllowedIPs"));
    }

    pub(crate) static IDENTITY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn isolated_identity_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("cf-scanner-warpgen-tests");
        unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn identity_round_trips_through_the_data_dir() {
        let _guard = IDENTITY_LOCK.lock().unwrap();
        isolated_identity_dir();
        let (secret, _) = keygen();
        let identity = Identity {
            id: "id-1".into(),
            token: "token-1".into(),
            private_key: base64::engine::general_purpose::STANDARD.encode(secret.to_bytes()),
            client_id: "cid".into(),
            account_type: "free".into(),
            license: None,
            created_at: 1,
            peer_public_key: None,
        };
        save_identity(&identity).unwrap();
        let loaded = load_identity().unwrap();
        assert_eq!(loaded.id, "id-1");
        assert_eq!(loaded.private_key, identity.private_key);
        let _ = fs::remove_file(identity_path().unwrap());
    }

    #[test]
    fn export_without_an_identity_fails_fast() {
        let _guard = IDENTITY_LOCK.lock().unwrap();
        isolated_identity_dir();
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(export(None, None))
            .unwrap_err();
        assert!(err.to_string().contains("no saved identity"));
    }

    #[test]
    fn corrupt_persisted_public_key_degrades_to_none() {
        let _guard = IDENTITY_LOCK.lock().unwrap();
        isolated_identity_dir();
        let enc = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        let short_key = enc(&[1u8; 16]);
        for bad in ["not-valid-base64!!!", short_key.as_str()] {
            let identity = format!(
                r#"{{"id":"t","token":"t","private_key":"{}","client_id":"c","account_type":"free","license":null,"created_at":0,"peer_public_key":"{bad}"}}"#,
                enc(&[1u8; 32])
            );
            std::fs::write(identity_path().unwrap(), identity).unwrap();
            assert!(
                persisted_server_public_key().is_none(),
                "corrupt peer key {bad:?} must degrade to None"
            );
        }
    }

    #[tokio::test]
    async fn client_flow_against_a_loopback_mock() {
        let seen: MockSeen = Default::default();
        let app = mock_app(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(5));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let reg = client.register(&public_b64).await.unwrap();
        assert_eq!(reg.id, "reg-1");
        client
            .enable_warp(&reg.id, &reg.token.clone().unwrap())
            .await
            .unwrap();
        client
            .bind_license(&reg.id, &reg.token.clone().unwrap(), "LICENSE-1")
            .await
            .unwrap();
        let fetched = client
            .fetch(&reg.id, &reg.token.clone().unwrap())
            .await
            .unwrap();
        assert_eq!(fetched.config.interface.addresses.v4, "172.16.0.2/32");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 4);
        let (_, _, register_body) = &seen[0];
        let body: serde_json::Value =
            serde_json::from_str::<serde_json::Value>(register_body).unwrap();
        assert_eq!(
            body.get("key").and_then(|k| k.as_str()),
            Some(public_b64.as_str())
        );
        assert_eq!(body.get("type").and_then(|t| t.as_str()), Some("Android"));
        let tos = body.get("tos").and_then(|t| t.as_str()).unwrap();
        assert!(tos.contains('T') && tos.ends_with("+00:00"));
        let (_, _, enable_body) = &seen[1];
        assert_eq!(enable_body, &"{\"warp_enabled\":true}".to_owned());
        let (method, path, license_body) = &seen[2];
        assert_eq!(method, "PUT");
        assert_eq!(path, "/v0a884/reg/reg-1/account");
        assert_eq!(license_body, &"{\"license\":\"LICENSE-1\"}".to_owned());
        let (method, path, _) = &seen[3];
        assert_eq!(method, "GET");
        assert_eq!(path, "/v0a884/reg/reg-1");
    }

    #[test]
    fn register_returns_a_rendered_wgconf_and_persists_identity() {
        let _guard = IDENTITY_LOCK.lock().unwrap();
        isolated_identity_dir();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let seen: MockSeen = Default::default();
            let app = mock_app(seen.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let text = register_with_base(format!("http://{addr}"), Some("LIC-9"))
                .await
                .unwrap();
            assert!(text.contains("PrivateKey"), "{text}");
            assert!(text.contains("172.16.0.2/32"), "{text}");
            assert!(text.contains("AllowedIPs"), "{text}");
            assert!(
                !text.contains("LIC-9"),
                "the license must not leak into the config"
            );
            let identity = load_identity().unwrap();
            assert_eq!(identity.id, "reg-1");
            assert_eq!(identity.license.as_deref(), Some("LIC-9"));
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 4, "register must emit reg/enable/license/fetch");
        });
    }

    #[tokio::test]
    async fn warp_register_maps_429_to_rate_limited_with_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let app = axum::Router::new().route(
            "/v0a884/reg",
            axum::routing::post(move || {
                let hits = hits_c.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::TOO_MANY_REQUESTS, "rate limited")
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(2));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        assert!(
            err.chain().any(|e| matches!(
                e.downcast_ref::<WarpRegisterError>(),
                Some(WarpRegisterError::RateLimited)
            )),
            "429 must map to RateLimited, got {err:#}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn warp_register_maps_401_to_unauthorized_immediate() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let app = axum::Router::new().route(
            "/v0a884/reg",
            axum::routing::post(move || {
                let hits = hits_c.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::UNAUTHORIZED, "unauthorized")
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(2));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        let found = err
            .chain()
            .find_map(|e| e.downcast_ref::<WarpRegisterError>());
        assert!(
            matches!(found, Some(WarpRegisterError::Unauthorized { status: 401 })),
            "got {err:#} {found:?}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1, "401 must not retry");
    }

    #[tokio::test]
    async fn warp_register_maps_403_to_unauthorized() {
        let app = axum::Router::new().route(
            "/v0a884/reg",
            axum::routing::post(async || (StatusCode::FORBIDDEN, "forbidden")),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(2));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        assert!(
            err.chain().any(|e| matches!(
                e.downcast_ref::<WarpRegisterError>(),
                Some(WarpRegisterError::Unauthorized { status: 403 })
            )),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn warp_register_maps_5xx_to_server_with_sanitized_detail_and_retries() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let body = "error https://user:secret@example.com/path?token=abc#frag";
        let body_owned = body.to_owned();
        let app = axum::Router::new().route(
            "/v0a884/reg",
            axum::routing::post(move || {
                let hits = hits_c.clone();
                let body_owned = body_owned.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::INTERNAL_SERVER_ERROR, body_owned)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(2));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        let found = err
            .chain()
            .find_map(|e| e.downcast_ref::<WarpRegisterError>().cloned());
        match found {
            Some(WarpRegisterError::Server { status, detail }) => {
                assert_eq!(status, 500);
                assert!(
                    !detail.contains("secret"),
                    "detail must be sanitized: {detail}"
                );
                assert!(
                    !detail.contains("token"),
                    "detail must be sanitized: {detail}"
                );
            }
            other => panic!("expected Server, got {other:?} {err:#}"),
        }
        assert_eq!(hits.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn warp_register_maps_4xx_other_to_server_immediate() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let app = axum::Router::new().route(
            "/v0a884/reg",
            axum::routing::post(move || {
                let hits = hits_c.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::BAD_REQUEST, "bad request")
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(2));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        assert!(
            err.chain().any(|e| matches!(
                e.downcast_ref::<WarpRegisterError>(),
                Some(WarpRegisterError::Server { status: 400, .. })
            )),
            "{err:#}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn warp_register_maps_timeout_to_timeout() {
        let app = axum::Router::new().route(
            "/v0a884/reg",
            axum::routing::post(async || {
                tokio::time::sleep(Duration::from_millis(500)).await;
                (StatusCode::OK, axum::Json(mock_registration()))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_millis(80));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        assert!(
            err.chain().any(|e| matches!(
                e.downcast_ref::<WarpRegisterError>(),
                Some(WarpRegisterError::Timeout)
            )),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn reg_is_never_retried_on_transport_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                drop(sock);
            }
        });
        let client = WarpClient::new(format!("http://{addr}"), Duration::from_secs(2));
        let (_, public) = keygen();
        let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
        let err = client.register(&public_b64).await.unwrap_err();
        assert!(
            err.to_string().contains("after 1 attempt"),
            "exactly one attempt expected, got {err:#}"
        );
        assert!(
            err.chain().any(|e| matches!(
                e.downcast_ref::<WarpRegisterError>(),
                Some(WarpRegisterError::Server { status: 0, .. })
            )),
            "transport error must map to Server {{ status: 0 }}, got {err:#}"
        );
    }

    #[test]
    fn retry_after_is_honored() {
        const FALLBACK: Duration = Duration::from_millis(300);
        const CAP: Duration = Duration::from_secs(15);
        assert_eq!(
            retry_delay(Some(Duration::from_secs(2)), FALLBACK, CAP),
            Duration::from_secs(2)
        );
        assert_eq!(
            retry_delay(None, FALLBACK, CAP),
            FALLBACK,
            "absent header falls back to the fixed delay"
        );
        assert_eq!(
            retry_delay(Some(Duration::from_secs(3_600)), FALLBACK, CAP),
            CAP,
            "a hostile Retry-After is capped at the request timeout"
        );
    }

    #[test]
    fn save_replaces_existing_identity() {
        let _guard = IDENTITY_LOCK.lock().unwrap();
        isolated_identity_dir();
        let enc = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        let identity = |id: &str, key: &[u8; 32]| Identity {
            id: id.into(),
            token: "t".into(),
            private_key: enc(key),
            client_id: "c".into(),
            account_type: "free".into(),
            license: None,
            created_at: 1,
            peer_public_key: None,
        };
        save_identity(&identity("id-a", &[1u8; 32])).unwrap();
        save_identity(&identity("id-b", &[2u8; 32])).unwrap();
        let loaded = load_identity().unwrap();
        assert_eq!(loaded.id, "id-b");
        assert_eq!(loaded.private_key, enc(&[2u8; 32]));
        let _ = fs::remove_file(identity_path().unwrap());
    }
}
