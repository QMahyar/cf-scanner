//! Phase-2 config parsers: vless/trojan/vmess/ss URIs, subscription text, and
//! Xray JSON -> one normalized `OutboundSpec`. Input here is UNTRUSTED
//! (subscriptions + user paste), so parsing never panics and never touches
//! the network unless explicitly fetching a sub URL.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde::Deserialize;
use url::Url;

use crate::ranges;

const SUB_UA: &str = "cf-scanner/0.1.0";
const WS: &str = "ws";

/// One normalized outbound after IP swap the engine can rebuild as Xray JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundSpec {
    pub protocol: Protocol,
    /// Hostname or IP the client dials (phase 2 swaps this per candidate).
    pub server: String,
    pub port: u16,
    /// vless/vmess UUID or trojan password.
    pub user_id: String,
    /// Shadowsocks cipher (e.g. `aes-128-gcm`).
    pub method: Option<String>,
    /// `none`, `tls`, or `reality`.
    pub security: String,
    pub tls_server_name: Option<String>,
    /// Client fingerprint, e.g. `chrome`.
    pub fingerprint: Option<String>,
    pub ws: Option<WsSettings>,
    pub tag: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsSettings {
    pub path: String,
    /// `Host` header override (often a fronting domain).
    pub host: Option<String>,
    /// e.g. `xudp` (empty when absent).
    pub packet_encoding: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Trojan,
    Vmess,
    Shadowsocks,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Trojan => "trojan",
            Protocol::Vmess => "vmess",
            Protocol::Shadowsocks => "shadowsocks",
        }
    }
}

/// Result of parsing subscription text: good specs plus how many lines were
/// skipped (ads, comments, corrupt entries).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SubscriptionParse {
    pub specs: Vec<OutboundSpec>,
    pub ignored: usize,
}

/// Full HTTPS GET with a subscription-friendly User-Agent.
#[allow(async_fn_in_trait)] // internal seam; send bounds are irrelevant here
pub trait SubFetch {
    async fn fetch(&self, url: &str) -> Result<String>;
}

pub struct RealSubFetch;

impl SubFetch for RealSubFetch {
    async fn fetch(&self, url: &str) -> Result<String> {
        ranges::fetch_tls_with_headers(url, &format!("User-Agent: {SUB_UA}\r\nAccept: */*")).await
    }
}

/// Fetches a subscription URL and parses every line.
pub async fn fetch_subscription(fetch: &impl SubFetch, url: &str) -> Result<SubscriptionParse> {
    let body = fetch.fetch(url).await?;
    Ok(parse_subscription(&body))
}

/// Parses one imported config entry: a vless/trojan/vmess/ss URI.
pub fn parse_uri(entry: &str) -> Result<OutboundSpec> {
    let entry = entry.trim();
    let scheme = entry
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("'{entry}' has no scheme"))?;
    match scheme.as_str() {
        "vless" | "trojan" => parse_sip002(entry),
        "vmess" => parse_vmess(entry),
        "ss" => parse_ss(entry),
        other => bail!("unsupported scheme '{other}'"),
    }
}

/// Parses subscription text (one URI per line; blank lines and `#` comments
/// are skipped, unparseable lines are counted, never errors the batch).
pub fn parse_subscription(body: &str) -> SubscriptionParse {
    let mut out = SubscriptionParse::default();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_uri(line) {
            Ok(spec) => out.specs.push(spec),
            Err(_) => out.ignored += 1,
        }
    }
    out
}

/// vless:// and trojan:// follow the SIP002 shape:
/// `scheme://userinfo@host:port?params#tag`. Id/password may also arrive in
/// the query (`id=`, `password=`) when the generator omits userinfo.
fn parse_sip002(entry: &str) -> Result<OutboundSpec> {
    let url = Url::parse(entry).map_err(|e| anyhow!("bad URL: {e}"))?;
    let protocol = match url.scheme() {
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        s => bail!("unexpected scheme '{s}'"),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url.port().ok_or_else(|| anyhow!("missing port"))?;
    let q = query_map(&url);

    let userinfo = percent_decode(url.username());
    let user_id = match q.get("id").or_else(|| q.get("password")) {
        Some(id) if userinfo.is_empty() || id.is_empty() => id.clone(),
        _ if userinfo.is_empty() => bail!("missing user id or password"),
        _ => userinfo,
    };

    let security = q.get("security").cloned().unwrap_or_else(|| {
        if protocol == Protocol::Trojan {
            "tls".to_owned()
        } else {
            "none".to_owned()
        }
    });
    let ws = match q.get("type").map(String::as_str) {
        Some(WS) => Some(WsSettings {
            path: q.get("path").cloned().unwrap_or_else(|| "/".to_owned()),
            host: q.get("host").cloned(),
            packet_encoding: q.get("packetencoding").filter(|v| !v.is_empty()).cloned(),
        }),
        _ => None,
    };

    Ok(OutboundSpec {
        protocol,
        server: host,
        port,
        user_id,
        method: None,
        security,
        tls_server_name: q.get("sni").cloned(),
        fingerprint: q.get("fp").cloned(),
        ws,
        tag: url.fragment().map(percent_decode),
    })
}

/// vmess://BASE64(JSON) where the JSON carries everything, e.g.
/// `{"v":"2","ps":"tag","add":"host","port":"443","id":"uuid","net":"ws",
///  "host":"h","path":"/","tls":"tls","sni":"s","fp":"chrome"}`.
fn parse_vmess(entry: &str) -> Result<OutboundSpec> {
    let (b64, tag) = match entry.split_once('#') {
        Some((b, t)) => (b, Some(t.to_owned())),
        None => (entry, None),
    };
    let b64 = b64
        .strip_prefix("vmess://")
        .ok_or_else(|| anyhow!("bad vmess prefix"))?;
    let decoded = base64_any(b64).map_err(|_| anyhow!("bad vmess base64"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("vmess payload is not JSON: {e}"))?;
    let o = json
        .as_object()
        .ok_or_else(|| anyhow!("vmess payload is not an object"))?;
    let get = |k: &str| o.get(k).and_then(|v| v.as_str());

    let server = get("add")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("vmess missing add"))?;
    let port: u16 = get("port")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow!("vmess missing/invalid port"))?;
    let user_id = get("id")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("vmess missing id"))?;
    let ws = match get("net") {
        Some(WS) => Some(WsSettings {
            path: get("path").unwrap_or("/").to_owned(),
            host: get("host").filter(|h| !h.is_empty()).map(str::to_owned),
            packet_encoding: None,
        }),
        _ => None,
    };
    Ok(OutboundSpec {
        protocol: Protocol::Vmess,
        server: server.to_owned(),
        port,
        user_id: user_id.to_owned(),
        method: None,
        security: get("tls").unwrap_or("none").to_owned(),
        tls_server_name: get("sni").filter(|s| !s.is_empty()).map(str::to_owned),
        fingerprint: get("fp").filter(|s| !s.is_empty()).map(str::to_owned),
        ws,
        tag: tag.as_deref().map(percent_decode),
    })
}

/// Shadowsocks URIs come in two forms:
/// `ss://BASE64(method:password)@host:port#tag` (SIP002 userinfo) or
/// `ss://BASE64(method:password@host:port)#tag` (full envelope).
fn parse_ss(entry: &str) -> Result<OutboundSpec> {
    let (b64, tag) = match entry.split_once('#') {
        Some((b, t)) => (b, Some(t.to_owned())),
        None => (entry, None),
    };
    let b64 = b64
        .strip_prefix("ss://")
        .ok_or_else(|| anyhow!("bad ss prefix"))?;

    let (userinfo, host_port) = if let Some((u, hp)) = b64.split_once('@') {
        // SIP002 userinfo form; userinfo may be base64 or plain `m:p`.
        let decoded = base64_any(u).unwrap_or_else(|_| u.as_bytes().to_vec());
        (decoded, hp.to_owned())
    } else {
        // Full envelope: base64 of `method:password@host:port`.
        let decoded = base64_any(b64).map_err(|_| anyhow!("bad ss base64"))?;
        let text = String::from_utf8_lossy(&decoded);
        let (u, hp) = text
            .split_once('@')
            .ok_or_else(|| anyhow!("ss envelope has no @"))?;
        (u.as_bytes().to_vec(), hp.to_owned())
    };

    let userinfo_text = String::from_utf8_lossy(&userinfo);
    let (method, password) = userinfo_text
        .split_once(':')
        .ok_or_else(|| anyhow!("ss userinfo is not method:password"))?;

    let (host, port) =
        split_host_port(&host_port).ok_or_else(|| anyhow!("ss missing host:port"))?;
    let port: u16 = port.parse().map_err(|_| anyhow!("ss bad port"))?;

    Ok(OutboundSpec {
        protocol: Protocol::Shadowsocks,
        server: host.to_owned(),
        port,
        user_id: password.to_owned(),
        method: Some(method.to_owned()),
        security: "none".to_owned(),
        tls_server_name: None,
        fingerprint: None,
        ws: None,
        tag: tag.as_deref().map(percent_decode),
    })
}

/// Extracts one usable outbound from xray-style JSON:
/// `{"outbounds":[{...}]}`. The first outbound with a known protocol wins.
pub fn parse_xray_json(text: &str) -> Result<OutboundSpec> {
    let cfg: XrayConfig = serde_json::from_str(text).map_err(|e| anyhow!("bad xray JSON: {e}"))?;
    for out in &cfg.outbounds {
        let protocol = match out.protocol.as_str() {
            "vless" => Protocol::Vless,
            "trojan" => Protocol::Trojan,
            "vmess" => Protocol::Vmess,
            "shadowsocks" => Protocol::Shadowsocks,
            _ => continue,
        };

        let (server, port, user_id, method) = match protocol {
            Protocol::Vless | Protocol::Vmess => {
                let v = out
                    .settings
                    .vnext
                    .first()
                    .ok_or_else(|| anyhow!("outbound has no vnext"))?;
                let user = v
                    .users
                    .first()
                    .ok_or_else(|| anyhow!("vnext has no users"))?;
                (v.address.clone(), v.port, user.id.clone(), None)
            }
            Protocol::Trojan | Protocol::Shadowsocks => {
                let s = out
                    .settings
                    .servers
                    .first()
                    .ok_or_else(|| anyhow!("outbound has no servers"))?;
                let password = s
                    .password
                    .clone()
                    .ok_or_else(|| anyhow!("server has no password"))?;
                (s.address.clone(), s.port, password, s.method.clone())
            }
        };

        let stream = out.stream_settings.as_ref();
        let network = stream.map(|s| s.network.as_str()).unwrap_or("");
        let security = stream
            .map(|s| s.security.clone())
            .unwrap_or_else(|| "none".to_owned());
        let ws = if network == WS {
            let w = stream.and_then(|s| s.ws_settings.as_ref());
            Some(WsSettings {
                path: w.map(|w| w.path.clone()).unwrap_or_else(|| "/".to_owned()),
                host: w
                    .and_then(|w| w.headers.as_ref())
                    .and_then(|h| h.host.clone()),
                packet_encoding: w
                    .and_then(|w| w.packet_encoding.as_ref())
                    .and_then(value_to_string),
            })
        } else {
            None
        };

        return Ok(OutboundSpec {
            protocol,
            server,
            port,
            user_id,
            method,
            security,
            tls_server_name: stream
                .and_then(|s| s.tls_settings.as_ref())
                .and_then(|t| t.server_name.clone()),
            fingerprint: stream
                .and_then(|s| s.tls_settings.as_ref())
                .and_then(|t| t.fingerprint.clone()),
            ws,
            tag: out.tag.clone(),
        });
    }
    bail!("no usable outbound found")
}

// --- helpers ---------------------------------------------------------------

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned().to_ascii_lowercase(), v.into_owned()))
        .collect()
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn base64_any(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|_| anyhow!("invalid base64"))
}

fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        return Some((host, rest.strip_prefix(':')?));
    }
    s.rsplit_once(':')
}

fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[derive(Deserialize)]
struct XrayConfig {
    outbounds: Vec<XrayOutbound>,
}

#[derive(Deserialize)]
struct XrayOutbound {
    protocol: String,
    tag: Option<String>,
    #[serde(default)]
    settings: XraySettings,
    #[serde(default, rename = "streamSettings")]
    stream_settings: Option<XrayStreamSettings>,
}

#[derive(Deserialize, Default)]
struct XraySettings {
    #[serde(default)]
    vnext: Vec<XrayVnext>,
    #[serde(default)]
    servers: Vec<XrayServer>,
}

#[derive(Deserialize)]
struct XrayVnext {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<XrayUser>,
}

#[derive(Deserialize)]
struct XrayUser {
    id: String,
}

#[derive(Deserialize)]
struct XrayServer {
    address: String,
    port: u16,
    method: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize, Default)]
struct XrayStreamSettings {
    #[serde(default)]
    network: String,
    #[serde(default)]
    security: String,
    #[serde(default, rename = "tlsSettings")]
    tls_settings: Option<XrayTlsSettings>,
    #[serde(default, rename = "wsSettings")]
    ws_settings: Option<XrayWsSettings>,
}

#[derive(Deserialize)]
struct XrayTlsSettings {
    #[serde(default, rename = "serverName")]
    server_name: Option<String>,
    fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct XrayWsSettings {
    #[serde(default)]
    path: String,
    headers: Option<XrayWsHeaders>,
    #[serde(default, rename = "packetEncoding")]
    packet_encoding: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct XrayWsHeaders {
    #[serde(default, rename = "Host")]
    host: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/vless-worker.txt");

    struct FakeSub(String);

    impl SubFetch for FakeSub {
        async fn fetch(&self, _url: &str) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn parses_the_cloudflare_worker_vless_fixture() {
        let spec = parse_uri(FIXTURE).unwrap();
        assert_eq!(spec.protocol, Protocol::Vless);
        assert_eq!(spec.server, "104.17.160.217");
        assert_eq!(spec.port, 2096);
        assert_eq!(spec.user_id, "6086b6d5-6874-4299-8ef9-33b01a2125aa");
        assert_eq!(spec.security, "tls");
        assert_eq!(
            spec.tls_server_name.as_deref(),
            Some("edgetunnel-8.edgetunnel-92fc86.workers.dev")
        );
        assert_eq!(spec.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            spec.ws,
            Some(WsSettings {
                path: "/".to_owned(),
                host: Some("edgetunnel-8.edgetunnel-92fc86.workers.dev".to_owned()),
                packet_encoding: Some("xudp".to_owned()),
            })
        );
        assert_eq!(spec.tag.as_deref(), Some("CF官方优选5"));
    }

    #[test]
    fn parses_plain_vless_without_ws() {
        let spec = parse_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=example.com",
        )
        .unwrap();
        assert_eq!(spec.server, "1.2.3.4");
        assert_eq!(spec.port, 443);
        assert_eq!(spec.security, "tls");
        assert_eq!(spec.tls_server_name.as_deref(), Some("example.com"));
        assert_eq!(spec.ws, None);
    }

    #[test]
    fn trojan_defaults_to_tls_security() {
        let spec = parse_uri("trojan://secret@example.com:443?type=ws&path=/api").unwrap();
        assert_eq!(spec.protocol, Protocol::Trojan);
        assert_eq!(spec.user_id, "secret");
        assert_eq!(spec.security, "tls");
        assert_eq!(spec.ws.unwrap().path, "/api");
    }

    #[test]
    fn id_may_come_from_query_when_userinfo_is_missing() {
        let spec = parse_uri(
            "vless://example.com:443?id=aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000&security=none",
        )
        .unwrap();
        assert_eq!(spec.user_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000");
        assert_eq!(spec.server, "example.com");
    }

    #[test]
    fn accepts_ipv6_host_in_brackets() {
        let spec =
            parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@[2606:4700::1]:443").unwrap();
        assert_eq!(spec.server, "2606:4700::1");
        assert_eq!(spec.port, 443);
    }

    #[test]
    fn parses_vmess_base64_json() {
        let json = r#"{"v":"2","ps":"vmess-tag","add":"5.6.7.8","port":"8443","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/warp","tls":"tls","sni":"cdn.example.com","fp":"firefox"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let url = format!("vmess://{b64}#My%20tag");
        let spec = parse_uri(&url).unwrap();
        assert_eq!(spec.protocol, Protocol::Vmess);
        assert_eq!(spec.server, "5.6.7.8");
        assert_eq!(spec.port, 8443);
        assert_eq!(spec.user_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000");
        assert_eq!(spec.security, "tls");
        assert_eq!(spec.ws.unwrap().host.as_deref(), Some("cdn.example.com"));
        assert_eq!(spec.tag.as_deref(), Some("My tag"));
    }

    #[test]
    fn parses_ss_sip002_userinfo_form() {
        let creds = base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:secret123");
        let spec = parse_uri(&format!("ss://{creds}@9.9.9.9:8388#ss-tag")).unwrap();
        assert_eq!(spec.protocol, Protocol::Shadowsocks);
        assert_eq!(spec.method.as_deref(), Some("aes-128-gcm"));
        assert_eq!(spec.user_id, "secret123");
        assert_eq!(spec.server, "9.9.9.9");
        assert_eq!(spec.port, 8388);
        assert_eq!(spec.tag.as_deref(), Some("ss-tag"));
    }

    #[test]
    fn parses_ss_full_envelope_form() {
        let env = base64::engine::general_purpose::STANDARD
            .encode("chacha20-ietf-poly1305:pass@1.2.3.4:443");
        let spec = parse_uri(&format!("ss://{env}#envelope")).unwrap();
        assert_eq!(spec.method.as_deref(), Some("chacha20-ietf-poly1305"));
        assert_eq!(spec.user_id, "pass");
        assert_eq!(spec.server, "1.2.3.4");
        assert_eq!(spec.port, 443);
        assert_eq!(spec.tag.as_deref(), Some("envelope"));
    }

    #[test]
    fn parses_plaintext_ss_userinfo() {
        let spec = parse_uri("ss://aes-256-gcm:plain@2.2.2.2:9000").unwrap();
        assert_eq!(spec.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(spec.user_id, "plain");
    }

    #[test]
    fn subscription_text_skips_comments_and_bad_lines() {
        let body = format!(
            "{FIXTURE}\n\n# a comment\nnot-a-uri\nvless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443"
        );
        let parsed = parse_subscription(&body);
        assert_eq!(parsed.specs.len(), 2);
        assert_eq!(parsed.ignored, 1);
        assert_eq!(parsed.specs[0].tag.as_deref(), Some("CF官方优选5"));
    }

    #[tokio::test]
    async fn fetch_subscription_parses_over_injectable_fetch() {
        let body = format!("{FIXTURE}\nss://aaa@bad\n");
        let parsed = fetch_subscription(&FakeSub(body), "https://example.invalid/sub")
            .await
            .unwrap();
        assert_eq!(parsed.specs.len(), 1);
        assert_eq!(parsed.ignored, 1);
    }

    #[test]
    fn parses_xray_json_ws_tls_outbound() {
        let json = r#"{
          "outbounds": [
            {"tag": "xray-tag", "protocol": "vless",
             "settings": {"vnext": [{"address": "104.17.160.217", "port": 2096,
               "users": [{"id": "6086b6d5-6874-4299-8ef9-33b01a2125aa", "encryption": "none"}]}]},
             "streamSettings": {"network": "ws", "security": "tls",
               "tlsSettings": {"serverName": "edgetunnel.workers.dev", "fingerprint": "chrome"},
               "wsSettings": {"path": "/", "headers": {"Host": "edgetunnel.workers.dev"},
                              "packetEncoding": "xudp"}}}
          ]
        }"#;
        let spec = parse_xray_json(json).unwrap();
        assert_eq!(spec.protocol, Protocol::Vless);
        assert_eq!(spec.server, "104.17.160.217");
        assert_eq!(spec.port, 2096);
        assert_eq!(spec.user_id, "6086b6d5-6874-4299-8ef9-33b01a2125aa");
        assert_eq!(spec.security, "tls");
        assert_eq!(
            spec.tls_server_name.as_deref(),
            Some("edgetunnel.workers.dev")
        );
        assert_eq!(spec.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            spec.ws,
            Some(WsSettings {
                path: "/".to_owned(),
                host: Some("edgetunnel.workers.dev".to_owned()),
                packet_encoding: Some("xudp".to_owned()),
            })
        );
        assert_eq!(spec.tag.as_deref(), Some("xray-tag"));
    }

    #[test]
    fn parses_xray_json_shadowsocks_outbound() {
        let json = r#"{"outbounds":[{"protocol":"shadowsocks",
          "settings":{"servers":[{"address":"1.2.3.4","port":8388,
            "method":"aes-128-gcm","password":"pw"}]}}]}"#;
        let spec = parse_xray_json(json).unwrap();
        assert_eq!(spec.protocol, Protocol::Shadowsocks);
        assert_eq!(spec.method.as_deref(), Some("aes-128-gcm"));
        assert_eq!(spec.user_id, "pw");
    }

    #[test]
    fn skips_unknown_outbounds_in_xray_json() {
        let json = r#"{"outbounds":[{"protocol":"dns"},{"protocol":"vless",
          "settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"u"}]}]}}]}"#;
        let spec = parse_xray_json(json).unwrap();
        assert_eq!(spec.protocol, Protocol::Vless);
        assert_eq!(spec.server, "1.2.3.4");
    }

    #[test]
    fn rejects_garbage_and_missing_parts() {
        for bad in [
            "",
            "garbage",
            "ftp://x",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4",
            "vless://@1.2.3.4:443",
            "vmess://!!!not-base64!!!",
            "vmess://",
            "ss://",
        ] {
            assert!(parse_uri(bad).is_err(), "expected '{bad}' to be rejected");
        }
        assert!(parse_xray_json("{}").is_err());
        assert!(parse_xray_json("not json").is_err());
    }

    #[test]
    fn query_key_case_does_not_matter() {
        let spec = parse_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?Security=TLS&Type=ws&Path=/x",
        )
        .unwrap();
        assert_eq!(spec.security, "TLS");
        assert_eq!(spec.ws.unwrap().path, "/x");
    }
}
