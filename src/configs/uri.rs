use std::net::Ipv4Addr;

use anyhow::{Result, anyhow, bail};
use percent_encoding::utf8_percent_encode;
use url::Url;

use base64::Engine as _;

use crate::util::percent_decode;

use super::{
    GRPC, GrpcSettings, MAX_CONFIG_ENTRY_BYTES, MAX_EXPORT_CONFIG_BYTES, OutboundSpec, Protocol,
    QUERY_VALUE_ENCODE_SET, SPLITHTTP, USERINFO_ENCODE_SET, WS, WsSettings, XHTTP, XhttpSettings,
    base64_any, finish_spec, query_map, reject_unsupported_security, split_host_port, strip_scheme,
    value_to_string,
};

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
    } else if let Some(grpc) = &spec.grpc {
        add("type", GRPC);
        add("serviceName", &grpc.service_name);
        if let Some(mode) = &grpc.mode {
            add("mode", mode);
        }
    } else if let Some(xhttp) = &spec.xhttp {
        add("type", XHTTP);
        add("path", &xhttp.path);
        if let Some(host) = &xhttp.host {
            add("host", host);
        }
        if let Some(mode) = &xhttp.mode {
            add("mode", mode);
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
    "servicename",
    "mode",
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
    let net = spec.network();
    payload.insert("net".into(), serde_json::json!(net));
    payload.insert("type".into(), serde_json::json!("none"));
    match (&spec.ws, &spec.grpc, &spec.xhttp) {
        (Some(ws), _, _) => {
            payload.insert("path".into(), serde_json::json!(ws.path));
            if let Some(host) = &ws.host {
                payload.insert("host".into(), serde_json::json!(host));
            }
        }
        (_, Some(grpc), _) => {
            payload.insert("path".into(), serde_json::json!(grpc.service_name));
            if let Some(mode) = &grpc.mode {
                payload.insert("mode".into(), serde_json::json!(mode));
            }
        }
        (_, _, Some(xhttp)) => {
            payload.insert("path".into(), serde_json::json!(xhttp.path));
            if let Some(host) = &xhttp.host {
                payload.insert("host".into(), serde_json::json!(host));
            }
        }
        _ => {}
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
    let mut ws = None;
    let mut grpc = None;
    let mut xhttp = None;
    match q.get("type").map(String::as_str) {
        Some(WS) => {
            ws = Some(WsSettings {
                path: q.get("path").cloned().unwrap_or_else(|| "/".to_owned()),
                host: q.get("host").cloned(),
                packet_encoding: q.get("packetencoding").filter(|v| !v.is_empty()).cloned(),
            });
        }
        Some(GRPC) => {
            grpc = Some(GrpcSettings {
                service_name: q.get("servicename").cloned().unwrap_or_default(),
                mode: q.get("mode").cloned(),
            });
        }
        Some(XHTTP) | Some(SPLITHTTP) => {
            xhttp = Some(XhttpSettings {
                path: q.get("path").cloned().unwrap_or_else(|| "/".to_owned()),
                host: q.get("host").cloned(),
                mode: q.get("mode").cloned(),
            });
        }
        _ => {}
    }

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
        grpc,
        xhttp,
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
    let mut ws = None;
    let mut grpc = None;
    let mut xhttp = None;
    match get("net") {
        Some(WS) => {
            ws = Some(WsSettings {
                path: get("path").unwrap_or("/").to_owned(),
                host: get("host").filter(|h| !h.is_empty()).map(str::to_owned),
                packet_encoding: None,
            });
        }
        Some(GRPC) => {
            grpc = Some(GrpcSettings {
                service_name: get("servicename")
                    .or_else(|| get("path"))
                    .unwrap_or("")
                    .to_owned(),
                mode: get("mode").filter(|m| !m.is_empty()).map(str::to_owned),
            });
        }
        Some(XHTTP) | Some(SPLITHTTP) => {
            xhttp = Some(XhttpSettings {
                path: get("path").unwrap_or("/").to_owned(),
                host: get("host").filter(|h| !h.is_empty()).map(str::to_owned),
                mode: get("mode").filter(|m| !m.is_empty()).map(str::to_owned),
            });
        }
        _ => {}
    }
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
        grpc,
        xhttp,
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
        grpc: None,
        xhttp: None,
        tag: tag.as_deref().map(percent_decode),
        alter_id: 0,
        vmess_security: None,
    })
}
