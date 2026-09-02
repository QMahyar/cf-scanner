use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Deserialize;
use url::Url;

use crate::api::types::MAX_CONFIG_ENTRY_BYTES;
use crate::util::percent_decode;

use crate::ranges;

const SUB_UA: &str = "cf-scanner/0.1.0";
const WS: &str = "ws";
const MAX_ERROR_LINE_BYTES: usize = 512;
const MAX_USER_ID_BYTES: usize = 1024;
const MAX_SERVER_BYTES: usize = 1024;
const MAX_FIELD_VALUE_BYTES: usize = 2048;
const MAX_SUB_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXPORT_CONFIG_BYTES: usize = 64 * 1024;

const USERINFO_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'@');

const QUERY_VALUE_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'=')
    .add(b'<')
    .add(b'>')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub fn sanitize_error_text(text: &str) -> String {
    text.lines()
        .map(|line| {
            let line: String = line.chars().filter(|c| !c.is_control()).collect();
            let redacted = redact_line(&line);
            if redacted.chars().count() > MAX_ERROR_LINE_BYTES {
                let mut truncated: String = redacted.chars().take(MAX_ERROR_LINE_BYTES).collect();
                truncated.push('…');
                truncated
            } else {
                redacted
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    loop {
        let Some(scheme_end) = rest.find("://") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..scheme_end + 3]);
        let seg = &rest[scheme_end + 3..];
        let seg_end = seg.find("://").unwrap_or(seg.len());
        let seg = &seg[..seg_end];
        let cut = seg.find(['?', '#']).unwrap_or(seg.len());
        let head = &seg[..cut];
        let at = head.find('@').or_else(|| head.find("%40"));
        match at.filter(|at| !head[..*at].contains(' ')) {
            Some(at) => {
                let sep_len = if head[at..].starts_with('@') { 1 } else { 4 };
                out.push_str("***@");
                out.push_str(&head[at + sep_len..]);
            }
            None => {
                let prefix = &rest[..scheme_end];
                let scheme_start = prefix
                    .rfind(|c: char| {
                        c.is_whitespace() || matches!(c, '"' | '\'' | '(' | '<' | '[' | '=')
                    })
                    .map_or(0, |i| i + 1);
                let scheme = &prefix[scheme_start..];
                let opaque_blob = !head.is_empty()
                    && (scheme.eq_ignore_ascii_case("vmess") || scheme.eq_ignore_ascii_case("ss"));
                if opaque_blob {
                    let token_end = head.find(char::is_whitespace).unwrap_or(head.len());
                    out.push_str("***");
                    out.push_str(&head[token_end..]);
                } else {
                    out.push_str(head);
                }
            }
        }
        rest = &rest[scheme_end + 3 + seg_end..];
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundSpec {
    pub protocol: Protocol,
    pub server: String,
    pub port: u16,
    pub user_id: String,
    pub method: Option<String>,
    pub security: String,
    pub tls_server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub ws: Option<WsSettings>,
    pub tag: Option<String>,
    pub alter_id: u16,
    pub vmess_security: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsSettings {
    pub path: String,
    pub host: Option<String>,
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SubscriptionParse {
    pub specs: Vec<OutboundSpec>,
    pub ignored: usize,
    pub errors: Vec<String>,
}

pub trait SubFetch: Send + Sync {
    fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>>;
}

pub struct RealSubFetch;

impl SubFetch for RealSubFetch {
    fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
        let url = url.to_owned();
        Box::pin(async move {
            ranges::fetch_tls_with_headers(&url, &format!("User-Agent: {SUB_UA}\r\nAccept: */*"))
                .await
        })
    }
}

pub async fn fetch_subscription(fetch: &impl SubFetch, url: &str) -> Result<SubscriptionParse> {
    let body = fetch.fetch(url).await?;
    Ok(parse_subscription(&body))
}

fn check_len(field: &str, value: &str, max: usize) -> Result<()> {
    let actual = value.len();
    if actual > max {
        bail!("{field} exceeds {max} bytes");
    }
    Ok(())
}

pub fn parse_uri(entry: &str) -> Result<OutboundSpec> {
    let entry = entry.trim();
    if entry.len() > MAX_CONFIG_ENTRY_BYTES {
        bail!("config entry exceeds {MAX_CONFIG_ENTRY_BYTES} bytes");
    }
    let scheme = entry
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("config entry has no scheme"))?;
    match scheme.as_str() {
        "vless" | "trojan" => parse_sip002(entry),
        "vmess" => parse_vmess(entry),
        "ss" => parse_ss(entry),
        other => bail!("unsupported scheme '{other}'"),
    }
}

fn fragment(remark: Option<&str>) -> String {
    match remark {
        Some(r) if !r.trim().is_empty() => {
            let encoded = utf8_percent_encode(r, QUERY_VALUE_ENCODE_SET).to_string();
            format!("#{encoded}")
        }
        _ => String::new(),
    }
}

fn render_sip002(
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni_override: Option<&str>,
    remark: Option<&str>,
    extras: &[(String, String)],
) -> Result<String> {
    let mut out = String::with_capacity(160);
    out.push_str(spec.protocol.as_str());
    out.push_str("://");
    out.push_str(&utf8_percent_encode(&spec.user_id, USERINFO_ENCODE_SET).to_string());
    out.push('@');
    out.push_str(&dial_ip.to_string());
    out.push(':');
    out.push_str(&spec.port.to_string());
    let mut params: Vec<String> = Vec::new();
    let mut add = |key: &str, value: &str| {
        params.push(format!(
            "{key}={}",
            utf8_percent_encode(value, QUERY_VALUE_ENCODE_SET)
        ));
    };
    add("security", &spec.security);
    let sni = sni_override
        .map(str::to_owned)
        .or_else(|| spec.tls_server_name.clone());
    if let Some(sni) = sni {
        add("sni", &sni);
    }
    if let Some(fp) = &spec.fingerprint {
        add("fp", fp);
    }
    if let Some(ws) = &spec.ws {
        add("type", WS);
        add("path", &ws.path);
        if let Some(host) = &ws.host {
            add("host", host);
        }
        if let Some(packet_encoding) = &ws.packet_encoding {
            add("packetencoding", packet_encoding);
        }
    }
    for (key, value) in extras {
        params.push(format!(
            "{}={}",
            utf8_percent_encode(key, QUERY_VALUE_ENCODE_SET),
            utf8_percent_encode(value, QUERY_VALUE_ENCODE_SET)
        ));
    }
    out.push('?');
    out.push_str(&params.join("&"));
    out.push_str(&fragment(remark));
    Ok(out)
}

const MANAGED_SIP002_KEYS: &[&str] = &[
    "security",
    "sni",
    "fp",
    "type",
    "path",
    "host",
    "packetencoding",
    "id",
    "password",
];

fn sip002_passthrough_params(original_config: &str) -> Vec<(String, String)> {
    let Ok(url) = Url::parse(original_config) else {
        return Vec::new();
    };
    if !matches!(url.scheme(), "vless" | "trojan") {
        return Vec::new();
    }
    url.query_pairs()
        .filter(|(k, _)| {
            let key = k.to_ascii_lowercase();
            !MANAGED_SIP002_KEYS.contains(&key.as_str())
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn render_uri(
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni_override: Option<&str>,
    remark: Option<&str>,
) -> Result<String> {
    match spec.protocol {
        Protocol::Vless | Protocol::Trojan => {
            render_sip002(spec, dial_ip, sni_override, remark, &[])
        }
        Protocol::Vmess => render_vmess(spec, dial_ip, sni_override, remark),
        Protocol::Shadowsocks => render_ss(spec, dial_ip, remark),
    }
}

fn render_vmess(
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni_override: Option<&str>,
    remark: Option<&str>,
) -> Result<String> {
    let mut payload = serde_json::Map::new();
    payload.insert("v".into(), serde_json::json!("2"));
    payload.insert(
        "ps".into(),
        serde_json::json!(remark.unwrap_or("").to_string()),
    );
    payload.insert("add".into(), serde_json::json!(dial_ip.to_string()));
    payload.insert("port".into(), serde_json::json!(spec.port.to_string()));
    payload.insert("id".into(), serde_json::json!(spec.user_id));
    payload.insert("aid".into(), serde_json::json!(spec.alter_id.to_string()));
    if let Some(scy) = &spec.vmess_security {
        payload.insert("scy".into(), serde_json::json!(scy));
    }
    let net = if spec.ws.is_some() { "ws" } else { "tcp" };
    payload.insert("net".into(), serde_json::json!(net));
    payload.insert("type".into(), serde_json::json!("none"));
    if let Some(ws) = &spec.ws {
        payload.insert("path".into(), serde_json::json!(ws.path));
        if let Some(host) = &ws.host {
            payload.insert("host".into(), serde_json::json!(host));
        }
    }
    let tls = if spec.security == "tls" {
        "tls"
    } else {
        "none"
    };
    payload.insert("tls".into(), serde_json::json!(tls));
    let sni = sni_override
        .map(str::to_owned)
        .or_else(|| spec.tls_server_name.clone());
    if let Some(sni) = sni {
        payload.insert("sni".into(), serde_json::json!(sni));
    }
    if let Some(fp) = &spec.fingerprint {
        payload.insert("fp".into(), serde_json::json!(fp));
    }
    let json = serde_json::Value::Object(payload);
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string());
    Ok(format!("vmess://{b64}"))
}

fn render_ss(spec: &OutboundSpec, dial_ip: Ipv4Addr, remark: Option<&str>) -> Result<String> {
    let method = spec.method.as_deref().unwrap_or("aes-128-gcm");
    let userinfo = format!("{method}:{}", spec.user_id);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(userinfo);
    let mut out = format!("ss://{b64}@{dial_ip}:{}", spec.port);
    out.push_str(&fragment(remark));
    Ok(out)
}

pub fn export_config_uri(
    original_config: &str,
    dial_ip: Ipv4Addr,
    port: u16,
    sni_override: Option<&str>,
    remark: Option<&str>,
) -> Result<String> {
    if original_config.len() > MAX_EXPORT_CONFIG_BYTES {
        bail!("config exceeds {MAX_EXPORT_CONFIG_BYTES} bytes");
    }
    let mut spec = parse_uri(original_config)?;
    spec.server = dial_ip.to_string();
    spec.port = port;
    let extras = sip002_passthrough_params(original_config);
    match spec.protocol {
        Protocol::Vless | Protocol::Trojan => {
            render_sip002(&spec, dial_ip, sni_override, remark, &extras)
        }
        Protocol::Vmess => render_vmess(&spec, dial_ip, sni_override, remark),
        Protocol::Shadowsocks => render_ss(&spec, dial_ip, remark),
    }
}

pub fn parse_subscription(body: &str) -> SubscriptionParse {
    let text = decode_subscription_body(body);
    let mut out = SubscriptionParse::default();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > MAX_CONFIG_ENTRY_BYTES {
            out.errors.push(format!(
                "line {}: entry exceeds {MAX_CONFIG_ENTRY_BYTES} bytes",
                idx + 1
            ));
            out.ignored += 1;
            continue;
        }
        match parse_uri(line) {
            Ok(spec) => out.specs.push(spec),
            Err(err) => {
                let reason = sanitize_error_text(&format!("{err:#}"));
                out.errors.push(format!("line {}: {reason}", idx + 1));
                out.ignored += 1;
            }
        }
    }
    out
}

fn decode_subscription_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.lines().count() != 1 {
        return body.to_owned();
    }
    if trimmed.len() > MAX_SUB_BLOB_BYTES {
        return body.to_owned();
    }
    let line = trimmed;
    let looks_like_uri = line
        .split_once("://")
        .map(|(s, _)| {
            matches!(
                s.to_ascii_lowercase().as_str(),
                "vless" | "trojan" | "vmess" | "ss"
            )
        })
        .unwrap_or(false);
    if looks_like_uri {
        return body.to_owned();
    }
    let Ok(decoded) = base64_any(line) else {
        return body.to_owned();
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return body.to_owned();
    };
    if text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("vless://")
            || l.starts_with("trojan://")
            || l.starts_with("vmess://")
            || l.starts_with("ss://")
    }) {
        text
    } else {
        body.to_owned()
    }
}

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
    let port = url.port().unwrap_or(443);
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
    reject_unsupported_security(&security)?;
    let ws = match q.get("type").map(String::as_str) {
        Some(WS) => Some(WsSettings {
            path: q.get("path").cloned().unwrap_or_else(|| "/".to_owned()),
            host: q.get("host").cloned(),
            packet_encoding: q.get("packetencoding").filter(|v| !v.is_empty()).cloned(),
        }),
        _ => None,
    };

    finish_spec(OutboundSpec {
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
        alter_id: 0,
        vmess_security: None,
    })
}

fn parse_vmess(entry: &str) -> Result<OutboundSpec> {
    let (b64, tag) = match entry.split_once('#') {
        Some((b, t)) => (b, Some(t.to_owned())),
        None => (entry, None),
    };
    let b64 = strip_scheme(b64, "vmess").ok_or_else(|| anyhow!("bad vmess prefix"))?;
    let decoded = base64_any(b64).map_err(|_| anyhow!("bad vmess base64"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("vmess payload is not JSON: {e}"))?;
    let o = json
        .as_object()
        .ok_or_else(|| anyhow!("vmess payload is not an object"))?;
    let get = |k: &str| o.get(k).and_then(|v| v.as_str());
    let get_flex = |k: &str| o.get(k).and_then(value_to_string);

    let server = get("add")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("vmess missing add"))?;
    let port: u16 = get_flex("port")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow!("vmess missing/invalid port"))?;
    let user_id = get("id")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("vmess missing id"))?;
    let security = get("tls")
        .filter(|s| !s.is_empty())
        .unwrap_or("none")
        .to_owned();
    reject_unsupported_security(&security)?;
    let alter_id: u16 = get_flex("aid").and_then(|a| a.parse().ok()).unwrap_or(0);
    let vmess_security = get("scy").filter(|s| !s.is_empty()).map(str::to_owned);
    let ws = match get("net") {
        Some(WS) => Some(WsSettings {
            path: get("path").unwrap_or("/").to_owned(),
            host: get("host").filter(|h| !h.is_empty()).map(str::to_owned),
            packet_encoding: None,
        }),
        _ => None,
    };
    finish_spec(OutboundSpec {
        protocol: Protocol::Vmess,
        server: server.to_owned(),
        port,
        user_id: user_id.to_owned(),
        method: None,
        security,
        tls_server_name: get("sni").filter(|s| !s.is_empty()).map(str::to_owned),
        fingerprint: get("fp").filter(|s| !s.is_empty()).map(str::to_owned),
        ws,
        tag: tag.as_deref().map(percent_decode),
        alter_id,
        vmess_security,
    })
}

fn parse_ss(entry: &str) -> Result<OutboundSpec> {
    let (b64, tag) = match entry.split_once('#') {
        Some((b, t)) => (b, Some(t.to_owned())),
        None => (entry, None),
    };
    let b64 = strip_scheme(b64, "ss").ok_or_else(|| anyhow!("bad ss prefix"))?;

    let (userinfo, host_port) = if let Some((u, hp)) = b64.split_once('@') {
        let decoded = base64_any(u).unwrap_or_else(|_| u.as_bytes().to_vec());
        (decoded, hp.to_owned())
    } else {
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
    if method.is_empty() {
        bail!("ss method is empty");
    }

    let (host, port) =
        split_host_port(&host_port).ok_or_else(|| anyhow!("ss missing host:port"))?;
    let port: u16 = port.parse().map_err(|_| anyhow!("ss bad port"))?;
    if host.is_empty() {
        bail!("ss host is empty");
    }

    finish_spec(OutboundSpec {
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
        alter_id: 0,
        vmess_security: None,
    })
}

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
        let vmess_meta = match protocol {
            Protocol::Vmess => {
                let user = out.settings.vnext.first().and_then(|v| v.users.first());
                (
                    user.and_then(|u| u.alter_id).unwrap_or(0),
                    user.and_then(|u| u.security.as_ref())
                        .filter(|s| !s.is_empty())
                        .cloned(),
                )
            }
            _ => (0, None),
        };

        let stream = out.stream_settings.as_ref();
        let network = stream.map(|s| s.network.as_str()).unwrap_or("");
        let security = stream
            .map(|s| s.security.clone())
            .unwrap_or_else(|| "none".to_owned());
        reject_unsupported_security(&security)?;
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

        return finish_spec(OutboundSpec {
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
            alter_id: vmess_meta.0,
            vmess_security: vmess_meta.1,
        });
    }
    bail!("no usable outbound found")
}

fn finish_spec(spec: OutboundSpec) -> Result<OutboundSpec> {
    if spec.user_id.is_empty() {
        bail!("user id is empty");
    }
    check_len("user id", &spec.user_id, MAX_USER_ID_BYTES)?;
    if spec.server.is_empty() {
        bail!("server is empty");
    }
    if spec.server.bytes().any(|b| {
        b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'@' | b'/' | b'?' | b'#')
    }) {
        bail!("server has invalid characters");
    }
    check_len("server", &spec.server, MAX_SERVER_BYTES)?;
    if spec.security.trim().is_empty() {
        bail!("security is empty");
    }
    check_len("security", &spec.security, MAX_FIELD_VALUE_BYTES)?;
    if let Some(sni) = &spec.tls_server_name {
        check_len("sni", sni, MAX_FIELD_VALUE_BYTES)?;
    }
    if let Some(fp) = &spec.fingerprint {
        check_len("fp", fp, MAX_FIELD_VALUE_BYTES)?;
    }
    if let Some(method) = &spec.method {
        check_len("ss method", method, MAX_FIELD_VALUE_BYTES)?;
    }
    if let Some(tag) = &spec.tag {
        check_len("tag", tag, MAX_FIELD_VALUE_BYTES)?;
    }
    if let Some(ws) = &spec.ws {
        check_len("ws path", &ws.path, MAX_FIELD_VALUE_BYTES)?;
        if let Some(host) = &ws.host {
            check_len("ws host", host, MAX_FIELD_VALUE_BYTES)?;
        }
        if let Some(pe) = &ws.packet_encoding {
            check_len("ws packetencoding", pe, MAX_FIELD_VALUE_BYTES)?;
        }
    }
    if let Some(scy) = &spec.vmess_security {
        check_len("vmess security", scy, MAX_FIELD_VALUE_BYTES)?;
    }
    Ok(spec)
}

fn strip_scheme<'a>(s: &'a str, scheme: &str) -> Option<&'a str> {
    let prefix = format!("{scheme}://");
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(&prefix))
        .then(|| &s[prefix.len()..])
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned().to_ascii_lowercase(), v.into_owned()))
        .collect()
}

fn reject_unsupported_security(security: &str) -> Result<()> {
    if security.eq_ignore_ascii_case("reality") {
        bail!("security 'reality' is not supported; use tls or none")
    }
    Ok(())
}

fn base64_any(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
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
    #[serde(default, rename = "alterId")]
    alter_id: Option<u16>,
    #[serde(default)]
    security: Option<String>,
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
        fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    #[test]
    fn parses_the_cloudflare_worker_vless_fixture() {
        let spec = parse_uri(FIXTURE).unwrap();
        assert_eq!(spec.protocol, Protocol::Vless);
        assert_eq!(spec.server, "104.17.160.217");
        assert_eq!(spec.port, 2096);
        assert_eq!(spec.user_id, "00000000-0000-0000-0000-000000000000");
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
    fn sip002_defaults_port_to_443() {
        let spec = parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@example.com").unwrap();
        assert_eq!(spec.port, 443);
        let trojan = parse_uri("trojan://secret@example.com").unwrap();
        assert_eq!(trojan.port, 443);
        let explicit =
            parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@host.example:8443").unwrap();
        assert_eq!(explicit.port, 8443);
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
        assert_eq!(parsed.errors.len(), 1);
        assert!(
            parsed.errors[0].starts_with("line 4:") && parsed.errors[0].contains("no scheme"),
            "{:?}",
            parsed.errors
        );
    }

    #[test]
    fn subscription_whole_body_base64_blob_is_decoded() {
        let lines = format!("{FIXTURE}\nss://aaa@bad\n");
        let blob = base64::engine::general_purpose::STANDARD.encode(lines);
        let parsed = parse_subscription(&blob);
        assert_eq!(parsed.specs.len(), 1);
        assert_eq!(parsed.ignored, 1);
        let prose = base64::engine::general_purpose::STANDARD.encode("just some random text");
        assert_eq!(parse_subscription(&prose).specs.len(), 0);
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
               "users": [{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}]}]},
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
        assert_eq!(spec.user_id, "00000000-0000-0000-0000-000000000000");
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
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@",
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

    #[test]
    fn schemes_are_case_insensitive() {
        let spec = parse_uri("VLESS://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443").unwrap();
        assert_eq!(spec.protocol, Protocol::Vless);
        let creds = base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:secret");
        let spec = parse_uri(&format!("SS://{creds}@1.2.3.4:8388")).unwrap();
        assert_eq!(spec.protocol, Protocol::Shadowsocks);
        let json = r#"{"v":"2","add":"5.6.7.8","port":"8443","id":"u","net":"tcp","tls":"none"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let spec = parse_uri(&format!("VMESS://{b64}")).unwrap();
        assert_eq!(spec.protocol, Protocol::Vmess);
    }

    #[test]
    fn ss_envelope_accepts_url_safe_base64() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut payload = b"chacha20-ietf-poly1305:p".to_vec();
        payload.extend_from_slice(&[0xFF, 0x73, 0x73]);
        payload.extend_from_slice(b"@1.2.3.4:443");
        let env = URL_SAFE_NO_PAD.encode(&payload);
        let spec = parse_uri(&format!("ss://{env}")).unwrap();
        assert_eq!(spec.method.as_deref(), Some("chacha20-ietf-poly1305"));
        assert_eq!(spec.server, "1.2.3.4");
        assert_eq!(spec.port, 443);
    }

    #[test]
    fn vmess_accepts_url_safe_base64() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let json = r#"{"v":"2","add":"5.6.7.8","port":"8443","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000","net":"tcp","tls":"none"}"#;
        let b64 = URL_SAFE_NO_PAD.encode(json);
        let spec = parse_uri(&format!("vmess://{b64}")).unwrap();
        assert_eq!(spec.server, "5.6.7.8");
        assert_eq!(spec.port, 8443);
    }

    #[test]
    fn base64_accepts_all_variants() {
        use base64::engine::general_purpose::{
            STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
        };
        let json =
            r#"{"v":"2","z":"ÿÿ","add":"5.6.7.8","port":"443","id":"u","net":"tcp","tls":"none"}"#;
        let variants = [
            STANDARD.encode(json),
            STANDARD_NO_PAD.encode(json),
            URL_SAFE.encode(json),
            URL_SAFE_NO_PAD.encode(json),
        ];
        assert_eq!(
            variants
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4,
            "the four encodings must be distinct inputs"
        );
        for b64 in &variants {
            let spec = parse_uri(&format!("vmess://{b64}")).unwrap();
            assert_eq!(spec.server, "5.6.7.8");
            assert_eq!(spec.port, 443);
            assert_eq!(spec.user_id, "u");
        }
    }

    #[test]
    fn vmess_accepts_numeric_port_and_aid() {
        let json = r#"{"v":"2","ps":"t","add":"h","port":8443,"id":"u","aid":64,"scy":"auto"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let spec = parse_uri(&format!("vmess://{b64}")).unwrap();
        assert_eq!(spec.port, 8443);
        assert_eq!(spec.alter_id, 64);
        assert_eq!(spec.vmess_security.as_deref(), Some("auto"));
    }

    #[test]
    fn ss_sip002_accepts_bracketed_ipv6_host() {
        let creds = base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:secret");
        let spec = parse_uri(&format!("ss://{creds}@[2606:4700::1]:8388")).unwrap();
        assert_eq!(spec.server, "2606:4700::1");
        assert_eq!(spec.port, 8388);
    }

    #[test]
    fn userinfo_is_percent_decoded() {
        let spec = parse_uri("trojan://p%40ss%3Aword@1.2.3.4:443").unwrap();
        assert_eq!(spec.user_id, "p@ss:word");
    }

    #[test]
    fn userinfo_wins_over_query_id() {
        let spec = parse_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?id=query-id&security=none",
        )
        .unwrap();
        assert_eq!(spec.user_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000");
    }

    #[test]
    fn rejects_ports_out_of_range() {
        assert!(parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:70000").is_err());
        let json = r#"{"add":"1.2.3.4","port":"abc","id":"u"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        assert!(parse_uri(&format!("vmess://{b64}")).is_err());
    }

    #[test]
    fn every_parser_caps_the_decoded_credential_with_one_error() {
        let oversized = "x".repeat(MAX_USER_ID_BYTES + 1);
        let want = format!("user id exceeds {MAX_USER_ID_BYTES} bytes");
        let std = base64::engine::general_purpose::STANDARD;
        let err = parse_uri(&format!("vless://{oversized}@1.2.3.4:443")).unwrap_err();
        assert_eq!(err.to_string(), want);
        let json = format!(r#"{{"add":"h","port":"443","id":"{oversized}","net":"tcp"}}"#);
        let err = parse_uri(&format!("vmess://{}", std.encode(json))).unwrap_err();
        assert_eq!(err.to_string(), want);
        let creds = std.encode(format!("aes-128-gcm:{oversized}"));
        let err = parse_uri(&format!("ss://{creds}@1.2.3.4:8388")).unwrap_err();
        assert_eq!(err.to_string(), want);
        let json = format!(
            r#"{{"outbounds":[{{"protocol":"vless","settings":{{"vnext":[{{"address":"1.2.3.4","port":443,"users":[{{"id":"{oversized}"}}]}}]}}}}]}}"#
        );
        let err = parse_xray_json(&json).unwrap_err();
        assert_eq!(err.to_string(), want);
        let at_cap = "x".repeat(MAX_USER_ID_BYTES);
        assert!(
            parse_uri(&format!("vless://{at_cap}@1.2.3.4:443"))
                .unwrap()
                .user_id
                .len()
                == MAX_USER_ID_BYTES
        );
        let creds = std.encode(format!("aes-128-gcm:{at_cap}"));
        assert!(parse_uri(&format!("ss://{creds}@1.2.3.4:8388")).is_ok());
    }

    #[test]
    fn sanitize_error_text_redacts_secret_shapes() {
        let cases: &[(&str, &str)] = &[
            (
                "fetch failed: https://user:pass@example.com/x",
                "fetch failed: https://***@example.com/x",
            ),
            (
                "fetch failed: https://user%40pass@example.com/x",
                "fetch failed: https://***@example.com/x",
            ),
            (
                "https://user:pass@example.com/x?id=secret&token=abc#frag",
                "https://***@example.com/x",
            ),
            (
                "email me at admin@example.com or use https://example.com",
                "email me at admin@example.com or use https://example.com",
            ),
            ("user:pass@example.com/x", "user:pass@example.com/x"),
        ];
        for (input, want) in cases {
            assert_eq!(
                sanitize_error_text(input),
                *want,
                "input {input:?} must redact to {want:?}"
            );
        }
    }

    #[test]
    fn redact_line_masks_every_url_on_a_line() {
        let input = "dial failed: vless://user:pass@host1/x retry vless://user:pass@host2/y";
        let out = sanitize_error_text(input);
        assert!(!out.contains("user:pass"), "credentials leaked: {out}");
        assert_eq!(
            out,
            "dial failed: vless://***@host1/x retry vless://***@host2/y"
        );
        let input = "https://u:p@a.com/x?q=1 and https://u:p@b.com/y#frag";
        let out = sanitize_error_text(input);
        assert!(!out.contains("u:p"), "credentials leaked: {out}");
        let input = "see https://a.com/p then mail admin@x.com or vless://u2:p2@b.com/q";
        let out = sanitize_error_text(input);
        assert!(out.contains("then mail admin@x.com or "), "{out}");
        assert!(!out.contains("u2:p2"), "{out}");
    }

    #[test]
    fn sanitize_error_text_strips_control_characters() {
        let input = "line one\x07 with bell\x1b[31m and escape\u{0085}newline";
        let out = sanitize_error_text(input);
        assert!(!out.contains('\x07') && !out.contains('\x1b') && !out.contains('\u{0085}'));
        assert!(out.contains("line one") && out.contains("escape") && out.contains("newline"));
    }

    #[test]
    fn sanitize_error_text_truncates_over_long_lines() {
        let long = format!("https://example.com/{}", "a".repeat(600));
        let out = sanitize_error_text(&long);
        assert!(out.ends_with('…'), "truncation marker missing: {out}");
        assert_eq!(out.chars().count(), MAX_ERROR_LINE_BYTES + 1);
        let two = format!(
            "https://example.com/{}\nhttps://example.com/{}",
            "a".repeat(600),
            "b".repeat(600)
        );
        let both = sanitize_error_text(&two);
        let lines: Vec<&str> = both.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.ends_with('…')));
    }

    const DIAL_IP: &str = "203.0.113.7";

    fn assert_round_trips(original: &str, sni_override: Option<&str>) {
        let spec = parse_uri(original).unwrap();
        let uri = render_uri(&spec, DIAL_IP.parse().unwrap(), sni_override, None).unwrap();
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.protocol, spec.protocol);
        assert_eq!(back.user_id, spec.user_id);
        assert_eq!(back.server, DIAL_IP);
        assert_eq!(back.port, spec.port);
        assert_eq!(back.security, spec.security);
        assert_eq!(
            back.tls_server_name.as_deref(),
            sni_override.or(spec.tls_server_name.as_deref()),
            "{uri}"
        );
        assert_eq!(back.fingerprint, spec.fingerprint);
        assert_eq!(back.ws, spec.ws);
    }

    #[test]
    fn render_uri_round_trips_vless() {
        for uri in [
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&sni=edgetunnel.workers.dev&fp=chrome",
            "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&type=ws&path=/&host=front.example.com&fp=chrome&sni=front.example.com&packetencoding=xudp",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&sni=orig.example.com",
        ] {
            let override_sni = uri.contains("override").then_some("b.me");
            assert_round_trips(uri, override_sni);
        }
    }

    #[test]
    fn render_uri_round_trips_trojan() {
        for uri in [
            "trojan://secret-password@example.com:443?security=tls",
            "trojan://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&sni=front.example.com&fp=chrome",
        ] {
            assert_round_trips(uri, None);
        }
    }

    #[test]
    fn render_uri_percent_encodes_hostile_passwords() {
        for password in ["p@ss:word", "p a s s#1", "päss/word?x"] {
            let encoded = utf8_percent_encode(password, USERINFO_ENCODE_SET);
            let spec = parse_uri(&format!("trojan://{encoded}@1.2.3.4:443")).unwrap();
            assert_eq!(spec.user_id, password, "parse must decode the input");
            let uri = render_uri(&spec, DIAL_IP.parse().unwrap(), None, None).unwrap();
            let back = parse_uri(&uri).unwrap();
            assert_eq!(back.user_id, password, "{uri}");
            assert_eq!(back.server, DIAL_IP);
            assert_eq!(back.protocol, Protocol::Trojan);
        }
    }

    #[test]
    fn render_uri_round_trips_vmess_ss_trojan_ws() {
        let vmess = parse_uri(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(
                r#"{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"tcp","tls":"none"}"#
            )
        ))
        .unwrap();
        let uri = render_uri(&vmess, DIAL_IP.parse().unwrap(), None, None).unwrap();
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.protocol, Protocol::Vmess);
        assert_eq!(back.server, DIAL_IP);
        assert_eq!(back.user_id, "u");

        let ss = parse_uri(&format!(
            "ss://{}@1.2.3.4:8388",
            base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:secret")
        ))
        .unwrap();
        let uri = render_uri(&ss, DIAL_IP.parse().unwrap(), None, None).unwrap();
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.protocol, Protocol::Shadowsocks);
        assert_eq!(back.server, DIAL_IP);
        assert_eq!(back.user_id, "secret");
        assert_eq!(back.method.as_deref(), Some("aes-128-gcm"));

        let trojan_ws = parse_uri("trojan://secret@1.2.3.4:443?type=ws&path=/api").unwrap();
        let uri = render_uri(&trojan_ws, DIAL_IP.parse().unwrap(), None, None).unwrap();
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.protocol, Protocol::Trojan);
        assert_eq!(back.server, DIAL_IP);
        assert_eq!(back.ws.as_ref().unwrap().path, "/api");

        let uri = render_uri(&ss, DIAL_IP.parse().unwrap(), None, Some("CF-LAX-42ms")).unwrap();
        assert!(uri.ends_with("#CF-LAX-42ms"), "{uri}");
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.tag.as_deref(), Some("CF-LAX-42ms"));
    }

    #[test]
    fn export_config_uri_swaps_the_dial_endpoint() {
        let uri = export_config_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com&fp=chrome",
            DIAL_IP.parse().unwrap(),
            2096,
            Some("b.me"),
            None,
        )
        .unwrap();
        assert!(
            uri.starts_with("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@203.0.113.7:2096?"),
            "{uri}"
        );
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.user_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000");
        assert_eq!(back.server, DIAL_IP);
        assert_eq!(back.port, 2096);
        assert_eq!(back.tls_server_name.as_deref(), Some("b.me"));
        assert_eq!(back.fingerprint.as_deref(), Some("chrome"));
        let uri = export_config_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com",
            DIAL_IP.parse().unwrap(),
            443,
            None,
            None,
        )
        .unwrap();
        assert!(uri.contains("sni=orig.example.com"), "{uri}");
        assert!(export_config_uri("not a uri", DIAL_IP.parse().unwrap(), 443, None, None).is_err());
    }

    #[test]
    fn oversized_entries_are_rejected_up_front() {
        let base = "vless://u@1.2.3.4:443?pad=";
        let at_cap = format!("{base}{}", "a".repeat(MAX_CONFIG_ENTRY_BYTES - base.len()));
        assert!(
            parse_uri(&at_cap).is_ok(),
            "8KiB boundary must stay inclusive"
        );
        let over = format!("{at_cap}a");
        let err = parse_uri(&over).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("config entry exceeds {MAX_CONFIG_ENTRY_BYTES} bytes")
        );
    }

    #[test]
    fn subscription_lines_over_the_entry_cap_are_counted_and_not_parsed() {
        let body = format!("{}\n", "x".repeat(MAX_CONFIG_ENTRY_BYTES + 1));
        let parsed = parse_subscription(&body);
        assert_eq!(parsed.specs.len(), 0);
        assert_eq!(parsed.ignored, 1);
        assert!(parsed.errors[0].contains("exceeds"), "{:?}", parsed.errors);
    }

    #[test]
    fn finish_spec_caps_every_field() {
        let sni = format!(
            "vless://u@1.2.3.4:443?sni={}",
            "a".repeat(MAX_FIELD_VALUE_BYTES + 1)
        );
        assert!(parse_uri(&sni).is_err());
        let at_cap = format!(
            "vless://u@1.2.3.4:443?sni={}",
            "a".repeat(MAX_FIELD_VALUE_BYTES)
        );
        assert!(parse_uri(&at_cap).is_ok());
        let path = format!("vless://u@1.2.3.4:443?type=ws&path=/{}", "a".repeat(2048));
        assert!(parse_uri(&path).is_err());
        let tag = format!(
            "vless://u@1.2.3.4:443#{}",
            "t".repeat(MAX_FIELD_VALUE_BYTES + 1)
        );
        assert!(parse_uri(&tag).is_err());
        let host = format!("vless://u@1.2.3.4:443?type=ws&host={}", "h".repeat(2049));
        assert!(parse_uri(&host).is_err());
    }

    #[test]
    fn finish_spec_rejects_empty_ids_and_empty_or_hostile_servers() {
        let err = parse_uri("vless://1.2.3.4:443?id=&security=none").unwrap_err();
        assert_eq!(err.to_string(), "user id is empty");
        let creds = base64::engine::general_purpose::STANDARD.encode(":pw");
        let err = parse_uri(&format!("ss://{creds}@1.2.3.4:8388")).unwrap_err();
        assert_eq!(err.to_string(), "ss method is empty");
        let json = r#"{"add":"1.2.3.4/hax","port":"443","id":"u"}"#;
        let err = parse_uri(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        ))
        .unwrap_err();
        assert_eq!(err.to_string(), "server has invalid characters");
    }

    #[test]
    fn vmess_empty_tls_is_normalized_to_none() {
        let json = r#"{"add":"1.2.3.4","port":"443","id":"u","tls":""}"#;
        let spec = parse_uri(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        ))
        .unwrap();
        assert_eq!(spec.security, "none");
    }

    #[test]
    fn export_config_uri_keeps_unmanaged_query_params() {
        let uri = export_config_uri(
            "vless://u@1.2.3.4:443?security=tls&flow=xtls-rprx-vision&headerType=http&sni=orig.example.com",
            DIAL_IP.parse().unwrap(),
            2096,
            Some("b.me"),
            None,
        )
        .unwrap();
        assert!(uri.contains("flow=xtls-rprx-vision"), "{uri}");
        assert!(uri.contains("headerType=http"), "{uri}");
        assert!(uri.contains("sni=b.me"), "{uri}");
        assert!(!uri.contains("orig.example.com"), "{uri}");
        assert_eq!(uri.matches("security=").count(), 1, "{uri}");
        assert_eq!(uri.matches("sni=").count(), 1, "{uri}");
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.server, DIAL_IP);
        assert_eq!(back.tls_server_name.as_deref(), Some("b.me"));
    }

    #[test]
    fn export_config_uri_encodes_hostile_remarks() {
        let remark = "evil#frag?x\nline";
        let uri = export_config_uri(
            "vless://u@1.2.3.4:443?security=none",
            DIAL_IP.parse().unwrap(),
            443,
            None,
            Some(remark),
        )
        .unwrap();
        assert!(!uri.contains('\n'), "{uri}");
        assert_eq!(uri.matches('#').count(), 1, "{uri}");
        let back = parse_uri(&uri).unwrap();
        assert_eq!(back.tag.as_deref(), Some(remark));
    }

    #[test]
    fn sanitize_error_text_masks_vmess_and_ss_payload_blobs() {
        let vmess = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD
                .encode(r#"{"add":"1.2.3.4","id":"secret-id"}"#)
        );
        let out = sanitize_error_text(&format!("config failed: {vmess}"));
        assert!(!out.contains("secret-id"), "{out}");
        assert!(out.contains("vmess://***"), "{out}");
        let ss_env = format!(
            "ss://{}",
            base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:secretpw")
        );
        let out = sanitize_error_text(&format!("config failed: {ss_env}"));
        assert!(!out.contains("secretpw"), "{out}");
        assert!(out.contains("ss://***"), "{out}");
        let prose = sanitize_error_text("plain https://example.com/docs stays visible");
        assert!(prose.contains("https://example.com/docs"), "{prose}");
    }

    #[test]
    fn parse_ss_rejects_empty_host() {
        let creds = base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:pw");
        assert!(parse_uri(&format!("ss://{creds}@:8388")).is_err());
    }

    #[test]
    fn oversized_subscription_blob_is_not_decoded() {
        let blob = "A".repeat(MAX_SUB_BLOB_BYTES + 1);
        let parsed = parse_subscription(&blob);
        assert_eq!(parsed.specs.len(), 0);
        assert_eq!(parsed.ignored, 1);
    }
}
