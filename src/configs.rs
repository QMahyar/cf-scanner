//! Phase-2 config parsers: vless/trojan/vmess/ss URIs, subscription text, and
//! Xray JSON -> one normalized `OutboundSpec`. Input here is UNTRUSTED
//! (subscriptions + user paste), so parsing never panics and never touches
//! the network unless explicitly fetching a sub URL.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Deserialize;
use url::Url;

use crate::ranges;

const SUB_UA: &str = "cf-scanner/0.1.0";
const WS: &str = "ws";
/// Error lines longer than this are truncated (e.g. xray stderr tails).
const MAX_ERROR_LINE_BYTES: usize = 512;
/// Decoded UUID/password cap; ids are embedded verbatim into xray configs.
const MAX_USER_ID_BYTES: usize = 1024;

/// Chars percent-encoded in a rendered URI's userinfo segment. RFC 3986
/// allows raw unreserved + sub-delims + ':' there, but our parser (like most
/// clients') reads a single username up to the first '@': ':' must be
/// encoded or a "user:pass" password would split, and '@' would corrupt the
/// host.
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

/// Chars percent-encoded in a rendered URI's query values: '&'/'=' would
/// split a parameter, '+' reads as a space to form-style clients, and '%'
/// must never double-encode. '/' and '?' stay raw (the query grammar allows
/// them); everything else reserved is encoded.
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

/// Best-effort redaction of error text before it reaches logs, the wire, or
/// the UI: URL-bearing lines lose their query/fragment (the usual carrier of
/// ids/passwords) and their userinfo (raw `user:pass@` or percent-encoded
/// `%40`), over-long lines are truncated, and control characters are
/// stripped. Not a security boundary on its own — parsers must still avoid
/// echoing raw entries (see `parse_uri`) — but it stops the common leak
/// shapes from imported configs and API bodies.
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

/// One line of error text: if it carries a `scheme://`, the query/fragment
/// is cut first (a stray '@' inside the query must not defeat the userinfo
/// mask), then the userinfo up to the first '@' — raw or percent-encoded
/// `%40` — is replaced. An '@' that sits after a space is prose, not
/// userinfo, and is left alone.
fn redact_line(line: &str) -> String {
    let Some(scheme_end) = line.find("://") else {
        return line.to_owned();
    };
    let rest = &line[scheme_end + 3..];
    let cut = rest.find(['?', '#']).unwrap_or(rest.len());
    let head = &rest[..cut];
    let at = head.find('@').or_else(|| head.find("%40"));
    let mut out = String::with_capacity(line.len());
    out.push_str(&line[..scheme_end + 3]);
    match at.filter(|at| !head[..*at].contains(' ')) {
        Some(at) => {
            let sep_len = if head[at..].starts_with('@') { 1 } else { 4 };
            out.push_str("***@");
            out.push_str(&head[at + sep_len..]);
        }
        None => out.push_str(head),
    }
    out
}

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
    /// `none` or `tls` (`reality` is rejected at parse time: the builder
    /// cannot emit a working reality outbound, and xray would silently fail
    /// phase 2).
    pub security: String,
    pub tls_server_name: Option<String>,
    /// Client fingerprint, e.g. `chrome`.
    pub fingerprint: Option<String>,
    pub ws: Option<WsSettings>,
    pub tag: Option<String>,
    /// VMess legacy `alterId` (0 = AEAD-only); ignored by other protocols.
    pub alter_id: u16,
    /// VMess AEAD security (`scy` in v2ray JSON); xray's default applies
    /// when absent. Ignored by other protocols.
    pub vmess_security: Option<String>,
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

/// Full HTTPS GET with a subscription-friendly User-Agent. BoxFuture style
/// so it is dyn-compatible for `Arc<dyn SubFetch>` in the engine.
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

/// Fetches a subscription URL and parses every line.
pub async fn fetch_subscription(fetch: &impl SubFetch, url: &str) -> Result<SubscriptionParse> {
    let body = fetch.fetch(url).await?;
    Ok(parse_subscription(&body))
}

/// Parses one imported config entry: a vless/trojan/vmess/ss URI.
///
/// # Examples
///
/// ```
/// use cf_scanner::configs::parse_uri;
///
/// let spec = parse_uri(
///     "vless://00000000-0000-0000-0000-000000000000@104.17.160.217:2096\
///      ?security=tls&type=ws&path=/&host=front.example.com&fp=chrome#tag",
/// )
/// .unwrap();
/// assert_eq!(spec.protocol.as_str(), "vless");
/// assert_eq!(spec.server, "104.17.160.217");
/// assert_eq!(spec.port, 2096);
/// assert_eq!(spec.security, "tls");
/// assert_eq!(spec.ws.as_ref().unwrap().host.as_deref(), Some("front.example.com"));
///
/// // Garbage never panics; it errors.
/// assert!(parse_uri("not a uri").is_err());
/// ```
pub fn parse_uri(entry: &str) -> Result<OutboundSpec> {
    let entry = entry.trim();
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

/// Renders a ready-to-use vless/trojan URI for a verified candidate: the
/// config's id, security, SNI, fingerprint and (vless) ws settings, dialing
/// `dial_ip`:`port`. The inverse of `parse_uri` for the fields we support;
/// vmess/ss and trojan-over-ws exports are out of scope.
pub fn render_uri(
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    sni_override: Option<&str>,
) -> Result<String> {
    match spec.protocol {
        Protocol::Vless => {}
        Protocol::Trojan => {
            if spec.ws.is_some() {
                bail!("export not supported for this protocol: trojan-over-ws");
            }
        }
        _ => bail!("export not supported for this protocol"),
    }
    let mut out = String::with_capacity(128);
    out.push_str(spec.protocol.as_str());
    out.push_str("://");
    out.push_str(&utf8_percent_encode(&spec.user_id, USERINFO_ENCODE_SET).to_string());
    out.push('@');
    out.push_str(&dial_ip.to_string());
    out.push(':');
    out.push_str(&spec.port.to_string());
    out.push('?');
    let mut query = |key: &str, value: &str| {
        out.push_str(key);
        out.push('=');
        out.push_str(&utf8_percent_encode(value, QUERY_VALUE_ENCODE_SET).to_string());
        out.push('&');
    };
    query("security", &spec.security);
    let sni = sni_override
        .map(str::to_owned)
        .or_else(|| spec.tls_server_name.clone());
    if let Some(sni) = sni {
        query("sni", &sni);
    }
    if let Some(fp) = &spec.fingerprint {
        query("fp", fp);
    }
    if let Some(ws) = &spec.ws {
        query("type", WS);
        query("path", &ws.path);
        if let Some(host) = &ws.host {
            query("host", host);
        }
        if let Some(packet_encoding) = &ws.packet_encoding {
            query("packetencoding", packet_encoding);
        }
    }
    out.pop(); // the trailing '&' (security is always present)
    Ok(out)
}

/// One export path shared by the CLI and the API: parse the user's original
/// config URI, point it at the verified candidate, render the ready URI.
/// `sni_override` (when given) wins over the config's own SNI.
pub fn export_config_uri(
    original_config: &str,
    dial_ip: Ipv4Addr,
    port: u16,
    sni_override: Option<&str>,
) -> Result<String> {
    let mut spec = parse_uri(original_config)?;
    spec.server = dial_ip.to_string();
    spec.port = port;
    render_uri(&spec, dial_ip, sni_override)
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
    // Share links commonly omit the default port; 443 is universal for
    // vless/trojan.
    let port = url.port().unwrap_or(443);
    let q = query_map(&url);

    let userinfo = percent_decode(url.username());
    let user_id = match q.get("id").or_else(|| q.get("password")) {
        Some(id) if userinfo.is_empty() || id.is_empty() => id.clone(),
        _ if userinfo.is_empty() => bail!("missing user id or password"),
        _ => userinfo,
    };
    // The id lands verbatim in generated xray configs: a percent-encoded
    // megabyte in one query param would slip past whole-entry length checks
    // counted elsewhere, so bound the decoded value itself.
    if user_id.len() > MAX_USER_ID_BYTES {
        bail!("user id exceeds {MAX_USER_ID_BYTES} bytes");
    }

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
        alter_id: 0,
        vmess_security: None,
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
    let b64 = strip_scheme(b64, "vmess").ok_or_else(|| anyhow!("bad vmess prefix"))?;
    let decoded = base64_any(b64).map_err(|_| anyhow!("bad vmess base64"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|e| anyhow!("vmess payload is not JSON: {e}"))?;
    let o = json
        .as_object()
        .ok_or_else(|| anyhow!("vmess payload is not an object"))?;
    let get = |k: &str| o.get(k).and_then(|v| v.as_str());
    // Generators emit port/aid either quoted or as JSON numbers.
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
    let security = get("tls").unwrap_or("none").to_owned();
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
    Ok(OutboundSpec {
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

/// Shadowsocks URIs come in two forms:
/// `ss://BASE64(method:password)@host:port#tag` (SIP002 userinfo) or
/// `ss://BASE64(method:password@host:port)#tag` (full envelope).
fn parse_ss(entry: &str) -> Result<OutboundSpec> {
    let (b64, tag) = match entry.split_once('#') {
        Some((b, t)) => (b, Some(t.to_owned())),
        None => (entry, None),
    };
    let b64 = strip_scheme(b64, "ss").ok_or_else(|| anyhow!("bad ss prefix"))?;

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
        alter_id: 0,
        vmess_security: None,
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
            alter_id: vmess_meta.0,
            vmess_security: vmess_meta.1,
        });
    }
    bail!("no usable outbound found")
}

// --- helpers ---------------------------------------------------------------

/// Case-insensitive `scheme://` prefix strip, mirroring the lowercase scheme
/// dispatch in `parse_uri` (vmess/ss payloads are case-sensitive base64, so
/// the raw entry cannot be lowercased wholesale).
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

/// Security modes the outbound builder cannot emit correctly. `reality`
/// needs realitySettings/serverName, which `build_outbound` does not produce;
/// accepting it would make xray reject the config and phase 2 silently fail.
fn reject_unsupported_security(security: &str) -> Result<()> {
    if security.eq_ignore_ascii_case("reality") {
        bail!("security 'reality' is not supported; use tls or none")
    }
    Ok(())
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
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
            // A missing port no longer rejects (defaults to 443); a missing
            // host still must.
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
        // 0xFF produces a base64 group of 63, which is '_' in the URL-safe
        // alphabet and '/' in STANDARD: STANDARD decoding must fail and the
        // URL-safe fallback must kick in.
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
        // The ÿ pair forces a '/' sextet and the length a '=' pad, so all
        // four engine outputs are distinct inputs.
        let json = r#"{"v":"2","z":"ÿÿ","add":"5.6.7.8","port":"443","id":"u","net":"tcp","tls":"none"}"#;
        let variants = [
            STANDARD.encode(json),
            STANDARD_NO_PAD.encode(json),
            URL_SAFE.encode(json),
            URL_SAFE_NO_PAD.encode(json),
        ];
        assert_eq!(
            variants.iter().collect::<std::collections::BTreeSet<_>>().len(),
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
        // url crate rejects >u16 ports at parse time.
        assert!(parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:70000").is_err());
        // vmess carries the port inside base64 JSON: string parse must fail.
        let json = r#"{"add":"1.2.3.4","port":"abc","id":"u"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        assert!(parse_uri(&format!("vmess://{b64}")).is_err());
    }

    // --- sanitize_error_text / redact_line table (review r6) -----------------

    #[test]
    fn sanitize_error_text_redacts_secret_shapes() {
        let cases: &[(&str, &str)] = &[
            // Raw userinfo is masked, path kept.
            (
                "fetch failed: https://user:pass@example.com/x",
                "fetch failed: https://***@example.com/x",
            ),
            // Percent-encoded userinfo (`%40` = '@') is masked too.
            (
                "fetch failed: https://user%40pass@example.com/x",
                "fetch failed: https://***@example.com/x",
            ),
            // Query/fragment (the usual id/password carrier) is cut first,
            // so a stray '@' in the query cannot defeat the userinfo mask.
            (
                "https://user:pass@example.com/x?id=secret&token=abc#frag",
                "https://***@example.com/x",
            ),
            // An '@' after a space is prose, not userinfo: left alone.
            (
                "email me at admin@example.com or use https://example.com",
                "email me at admin@example.com or use https://example.com",
            ),
            // Lines without a scheme are untouched by design (the redactor
            // only masks URL-shaped text; prose stays readable).
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
    fn sanitize_error_text_strips_control_characters() {
        let input = "line one\x07 with bell\x1b[31m and escape\u{0085}newline";
        let out = sanitize_error_text(input);
        assert!(!out.contains('\x07') && !out.contains('\x1b') && !out.contains('\u{0085}'));
        assert!(out.contains("line one") && out.contains("escape") && out.contains("newline"));
    }

    #[test]
    fn sanitize_error_text_truncates_over_long_lines() {
        // The length must live in the path: query/fragment is stripped by the
        // redactor before truncation ever runs.
        let long = format!("https://example.com/{}", "a".repeat(600));
        let out = sanitize_error_text(&long);
        assert!(out.ends_with('…'), "truncation marker missing: {out}");
        assert_eq!(out.chars().count(), MAX_ERROR_LINE_BYTES + 1);
        // Multi-line input truncates per line, not as one blob.
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

    // --- render_uri / export_config_uri (review round) ----------------------

    const DIAL_IP: &str = "203.0.113.7";

    /// Parses, renders with a fake dial IP, re-parses, and checks every
    /// identity-critical field survived.
    fn assert_round_trips(original: &str, sni_override: Option<&str>) {
        let spec = parse_uri(original).unwrap();
        let uri = render_uri(&spec, DIAL_IP.parse().unwrap(), sni_override).unwrap();
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
            // Plain tls with explicit SNI + fingerprint.
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&sni=edgetunnel.workers.dev&fp=chrome",
            // Default security=none, no extras.
            "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443",
            // WS + Host fronting + packetencoding, as Cloudflare workers use.
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&type=ws&path=/&host=front.example.com&fp=chrome&sni=front.example.com&packetencoding=xudp",
            // An override swaps the config's own SNI.
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
        // ':' and '@' inside the userinfo must survive the round trip; a
        // raw ':' would split a user:pass pair in every parser, so the
        // input side is fed percent-encoded (as real configs are).
        for password in ["p@ss:word", "p a s s#1", "päss/word?x"] {
            let encoded = utf8_percent_encode(password, USERINFO_ENCODE_SET);
            let spec = parse_uri(&format!("trojan://{encoded}@1.2.3.4:443")).unwrap();
            assert_eq!(spec.user_id, password, "parse must decode the input");
            let uri = render_uri(&spec, DIAL_IP.parse().unwrap(), None).unwrap();
            let back = parse_uri(&uri).unwrap();
            assert_eq!(back.user_id, password, "{uri}");
            assert_eq!(back.server, DIAL_IP);
            assert_eq!(back.protocol, Protocol::Trojan);
        }
    }

    #[test]
    fn render_uri_rejects_unsupported_protocols_and_trojan_ws() {
        let vmess = parse_uri(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(
                r#"{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"tcp","tls":"none"}"#
            )
        ))
        .unwrap();
        let err = render_uri(&vmess, DIAL_IP.parse().unwrap(), None).unwrap_err();
        assert!(err.to_string().contains("export not supported"), "{err}");
        let ss = parse_uri(&format!(
            "ss://{}@1.2.3.4:8388",
            base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:secret")
        ))
        .unwrap();
        assert!(render_uri(&ss, DIAL_IP.parse().unwrap(), None).is_err());
        let trojan_ws = parse_uri("trojan://secret@1.2.3.4:443?type=ws&path=/api").unwrap();
        let err = render_uri(&trojan_ws, DIAL_IP.parse().unwrap(), None).unwrap_err();
        assert!(err.to_string().contains("trojan-over-ws"), "{err}");
    }

    #[test]
    fn export_config_uri_swaps_the_dial_endpoint() {
        let uri = export_config_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com&fp=chrome",
            DIAL_IP.parse().unwrap(),
            2096,
            Some("b.me"),
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
        // The override is what the scan verified; without one the config's
        // own SNI is preserved.
        let uri = export_config_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com",
            DIAL_IP.parse().unwrap(),
            443,
            None,
        )
        .unwrap();
        assert!(uri.contains("sni=orig.example.com"), "{uri}");
        // Garbage input errors instead of rendering something unusable.
        assert!(export_config_uri("not a uri", DIAL_IP.parse().unwrap(), 443, None).is_err());
    }
}
