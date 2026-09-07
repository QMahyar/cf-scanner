use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, CONTROLS};
use url::Url;

use crate::api::types::MAX_CONFIG_ENTRY_BYTES;

const SUB_UA: &str = "cf-scanner/0.1.0";
const WS: &str = "ws";
const GRPC: &str = "grpc";
const XHTTP: &str = "xhttp";
const SPLITHTTP: &str = "splithttp";
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
    pub grpc: Option<GrpcSettings>,
    pub xhttp: Option<XhttpSettings>,
    pub tag: Option<String>,
    pub alter_id: u16,
    pub vmess_security: Option<String>,
}

impl OutboundSpec {
    pub fn network(&self) -> &'static str {
        if self.ws.is_some() {
            WS
        } else if self.grpc.is_some() {
            GRPC
        } else if self.xhttp.is_some() {
            SPLITHTTP
        } else {
            "tcp"
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsSettings {
    pub path: String,
    pub host: Option<String>,
    pub packet_encoding: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrpcSettings {
    pub service_name: String,
    pub mode: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XhttpSettings {
    pub path: String,
    pub host: Option<String>,
    pub mode: Option<String>,
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

pub(crate) fn check_len(field: &str, value: &str, max: usize) -> Result<()> {
    let actual = value.len();
    if actual > max {
        bail!("{field} exceeds {max} bytes");
    }
    Ok(())
}

pub(crate) fn finish_spec(spec: OutboundSpec) -> Result<OutboundSpec> {
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
    if let Some(grpc) = &spec.grpc {
        check_len(
            "grpc serviceName",
            &grpc.service_name,
            MAX_FIELD_VALUE_BYTES,
        )?;
        if let Some(mode) = &grpc.mode {
            check_len("grpc mode", mode, MAX_FIELD_VALUE_BYTES)?;
        }
    }
    if let Some(xhttp) = &spec.xhttp {
        check_len("xhttp path", &xhttp.path, MAX_FIELD_VALUE_BYTES)?;
        if let Some(host) = &xhttp.host {
            check_len("xhttp host", host, MAX_FIELD_VALUE_BYTES)?;
        }
        if let Some(mode) = &xhttp.mode {
            check_len("xhttp mode", mode, MAX_FIELD_VALUE_BYTES)?;
        }
    }
    if let Some(scy) = &spec.vmess_security {
        check_len("vmess security", scy, MAX_FIELD_VALUE_BYTES)?;
    }
    Ok(spec)
}

pub(crate) fn strip_scheme<'a>(s: &'a str, scheme: &str) -> Option<&'a str> {
    let prefix = format!("{scheme}://");
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(&prefix))
        .then(|| &s[prefix.len()..])
}

pub(crate) fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned().to_ascii_lowercase(), v.into_owned()))
        .collect()
}

pub(crate) fn reject_unsupported_security(security: &str) -> Result<()> {
    if security.eq_ignore_ascii_case("reality") {
        bail!("security 'reality' is not supported; use tls or none")
    }
    Ok(())
}

pub(crate) fn base64_any(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|_| anyhow!("invalid base64"))
}

pub(crate) fn split_host_port(s: &str) -> Option<(&str, &str)> {
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

mod subscription;
mod uri;
mod xray_json;

pub use subscription::{
    RealSubFetch, SubFetch, SubscriptionParse, fetch_subscription, parse_subscription,
};
pub use uri::{export_config_uri, parse_uri, render_uri};
pub use xray_json::parse_xray_json;

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::utf8_percent_encode;
    use std::future::Future;
    use std::pin::Pin;

    const FIXTURE: &str = include_str!("../../tests/fixtures/vless-worker.txt");

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
    fn parses_grpc_transport_uri() {
        let spec = parse_uri(
            "vless://u@1.2.3.4:443?security=tls&sni=s.example.com&type=grpc&serviceName=grpc-svc&mode=multi",
        )
        .unwrap();
        assert_eq!(spec.protocol, Protocol::Vless);
        assert_eq!(spec.network(), "grpc");
        assert_eq!(spec.grpc.as_ref().unwrap().service_name, "grpc-svc");
        assert_eq!(spec.grpc.as_ref().unwrap().mode.as_deref(), Some("multi"));
        assert!(spec.ws.is_none());
        assert!(spec.xhttp.is_none());

        let defaults = parse_uri("trojan://secret@example.com:443?type=grpc").unwrap();
        assert_eq!(defaults.network(), "grpc");
        assert_eq!(defaults.grpc.as_ref().unwrap().service_name, "");
        assert!(defaults.grpc.as_ref().unwrap().mode.is_none());
    }

    #[test]
    fn parses_xhttp_transport_uri() {
        let spec = parse_uri(
            "vless://u@1.2.3.4:443?security=tls&type=xhttp&path=%2Fxh&host=cdn.example.com&mode=stream",
        )
        .unwrap();
        assert_eq!(spec.network(), "splithttp");
        assert_eq!(spec.xhttp.as_ref().unwrap().path, "/xh");
        assert_eq!(
            spec.xhttp.as_ref().unwrap().host.as_deref(),
            Some("cdn.example.com")
        );
        assert_eq!(spec.xhttp.as_ref().unwrap().mode.as_deref(), Some("stream"));
        assert!(spec.ws.is_none());

        let legacy = parse_uri("vless://u@1.2.3.4:443?type=splithttp&path=/x").unwrap();
        assert_eq!(legacy.network(), "splithttp");
        assert_eq!(legacy.xhttp.as_ref().unwrap().path, "/x");

        let defaults = parse_uri("trojan://secret@example.com:443?type=xhttp").unwrap();
        assert_eq!(defaults.xhttp.as_ref().unwrap().path, "/");
        assert!(defaults.xhttp.as_ref().unwrap().host.is_none());
    }

    #[test]
    fn parses_vmess_grpc_and_xhttp_payloads() {
        let std = base64::engine::general_purpose::STANDARD;
        let grpc = r#"{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"grpc","path":"grpc-svc","mode":"multi","tls":"tls"}"#;
        let spec = parse_uri(&format!("vmess://{}", std.encode(grpc))).unwrap();
        assert_eq!(spec.network(), "grpc");
        assert_eq!(spec.grpc.as_ref().unwrap().service_name, "grpc-svc");
        assert_eq!(spec.grpc.as_ref().unwrap().mode.as_deref(), Some("multi"));

        let legacy_path_key =
            r#"{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"grpc","path":"svc"}"#;
        let spec = parse_uri(&format!("vmess://{}", std.encode(legacy_path_key))).unwrap();
        assert_eq!(spec.grpc.as_ref().unwrap().service_name, "svc");

        let xhttp = r#"{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"xhttp","path":"/xh","host":"cdn.example.com","mode":"auto","tls":"tls"}"#;
        let spec = parse_uri(&format!("vmess://{}", std.encode(xhttp))).unwrap();
        assert_eq!(spec.network(), "splithttp");
        assert_eq!(spec.xhttp.as_ref().unwrap().path, "/xh");
        assert_eq!(
            spec.xhttp.as_ref().unwrap().host.as_deref(),
            Some("cdn.example.com")
        );
        assert_eq!(spec.xhttp.as_ref().unwrap().mode.as_deref(), Some("auto"));
    }

    #[test]
    fn parses_xray_json_grpc_and_xhttp_outbounds() {
        let grpc = r#"{"outbounds":[{"protocol":"vless",
          "settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"u"}]}]},
          "streamSettings":{"network":"grpc","security":"tls",
            "tlsSettings":{"serverName":"s.example.com"},
            "grpcSettings":{"serviceName":"grpc-svc","multiMode":true}}}]}"#;
        let spec = parse_xray_json(grpc).unwrap();
        assert_eq!(spec.network(), "grpc");
        assert_eq!(spec.grpc.as_ref().unwrap().service_name, "grpc-svc");
        assert_eq!(spec.grpc.as_ref().unwrap().mode.as_deref(), Some("multi"));
        assert_eq!(spec.tls_server_name.as_deref(), Some("s.example.com"));

        let xhttp = r#"{"outbounds":[{"protocol":"trojan",
          "settings":{"servers":[{"address":"1.2.3.4","port":443,"password":"pw"}]},
          "streamSettings":{"network":"xhttp","security":"none",
            "xhttpSettings":{"path":"/xh","host":"cdn.example.com","mode":"auto"}}}]}"#;
        let spec = parse_xray_json(xhttp).unwrap();
        assert_eq!(spec.network(), "splithttp");
        assert_eq!(spec.xhttp.as_ref().unwrap().path, "/xh");
        assert_eq!(
            spec.xhttp.as_ref().unwrap().host.as_deref(),
            Some("cdn.example.com")
        );
        assert_eq!(spec.xhttp.as_ref().unwrap().mode.as_deref(), Some("auto"));
    }

    #[test]
    fn grpc_and_xhttp_survive_uri_to_xray_json_round_trip() {
        for uri in [
            "vless://u@1.2.3.4:443?security=tls&type=grpc&serviceName=grpc-svc&mode=multi",
            "vless://u@1.2.3.4:443?security=tls&type=grpc&serviceName=grpc-svc",
            "vless://u@1.2.3.4:443?security=tls&type=xhttp&path=/xh&host=front.example.com&mode=stream",
            "trojan://secret@1.2.3.4:443?type=xhttp&path=/xh",
        ] {
            let spec = parse_uri(uri).unwrap();
            let outbound =
                crate::xray::build_outbound(&spec, "104.17.160.217".parse().unwrap(), None);
            let json = serde_json::json!({ "outbounds": [outbound] });
            let back = parse_xray_json(&json.to_string()).unwrap();
            assert_eq!(back.grpc, spec.grpc, "{json}");
            assert_eq!(back.xhttp, spec.xhttp, "{json}");
            assert_eq!(back.network(), spec.network(), "{json}");
        }
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
        assert_eq!(back.grpc, spec.grpc);
        assert_eq!(back.xhttp, spec.xhttp);
    }

    #[test]
    fn render_uri_round_trips_vless() {
        for uri in [
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&sni=edgetunnel.workers.dev&fp=chrome",
            "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&type=ws&path=/&host=front.example.com&fp=chrome&sni=front.example.com&packetencoding=xudp",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&type=grpc&serviceName=grpc-svc&mode=multi",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&type=grpc&serviceName=grpc-svc",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@104.17.160.217:2096?security=tls&type=xhttp&path=/xh&host=front.example.com&mode=stream",
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
    fn export_config_uri_round_trips_grpc_and_xhttp() {
        for uri in [
            "vless://u@1.2.3.4:443?security=tls&sni=orig.example.com&type=grpc&serviceName=grpc-svc&mode=multi",
            "vless://u@1.2.3.4:443?security=tls&type=xhttp&path=/xh&host=front.example.com&mode=stream",
        ] {
            let out = export_config_uri(uri, DIAL_IP.parse().unwrap(), 2096, None, None).unwrap();
            let back = parse_uri(&out).unwrap();
            assert_eq!(back.server, DIAL_IP);
            assert_eq!(back.port, 2096);
            assert_eq!(back.grpc, parse_uri(uri).unwrap().grpc, "{out}");
            assert_eq!(back.xhttp, parse_uri(uri).unwrap().xhttp, "{out}");
        }
        let grpc_out = export_config_uri(
            "vless://u@1.2.3.4:443?security=tls&type=grpc&serviceName=svc&flow=xtls-rprx-vision",
            DIAL_IP.parse().unwrap(),
            443,
            None,
            None,
        )
        .unwrap();
        assert!(grpc_out.contains("serviceName=svc"), "{grpc_out}");
        assert!(grpc_out.contains("flow=xtls-rprx-vision"), "{grpc_out}");
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

#[cfg(test)]
mod httpupgrade_tests {
    use super::*;

    // Pins the HTTPUpgrade claim in docs/spec.md §9 item 9: the URI parses,
    // but the transport is NOT modeled — it falls through to plain TCP.
    #[test]
    fn httpupgrade_uris_parse_with_the_transport_unmodeled() {
        let spec = parse_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?type=httpupgrade&path=/x",
        )
        .unwrap();
        assert!(
            spec.ws.is_none() && spec.grpc.is_none() && spec.xhttp.is_none(),
            "httpupgrade must not silently model as another transport"
        );
    }
}
