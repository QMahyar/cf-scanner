use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

use super::{
    GRPC, GrpcSettings, OutboundSpec, Protocol, SPLITHTTP, WS, WsSettings, XHTTP, XhttpSettings,
    finish_spec, reject_unsupported_security, value_to_string,
};

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
        let (ws, grpc, xhttp) = match network {
            WS => {
                let w = stream.and_then(|s| s.ws_settings.as_ref());
                (
                    Some(WsSettings {
                        path: w.map(|w| w.path.clone()).unwrap_or_else(|| "/".to_owned()),
                        host: w
                            .and_then(|w| w.headers.as_ref())
                            .and_then(|h| h.host.clone()),
                        packet_encoding: w
                            .and_then(|w| w.packet_encoding.as_ref())
                            .and_then(value_to_string),
                    }),
                    None,
                    None,
                )
            }
            GRPC => {
                let g = stream.and_then(|s| s.grpc_settings.as_ref());
                (
                    None,
                    Some(GrpcSettings {
                        service_name: g.and_then(|g| g.service_name.clone()).unwrap_or_default(),
                        mode: g
                            .map(|g| g.multi_mode)
                            .unwrap_or(false)
                            .then(|| "multi".to_owned()),
                    }),
                    None,
                )
            }
            XHTTP | SPLITHTTP => {
                let x = stream
                    .and_then(|s| s.xhttp_settings.as_ref().or(s.splithttp_settings.as_ref()));
                (
                    None,
                    None,
                    Some(XhttpSettings {
                        path: x
                            .and_then(|x| x.path.clone())
                            .unwrap_or_else(|| "/".to_owned()),
                        host: x.and_then(|x| x.host.clone()),
                        mode: x.and_then(|x| x.mode.clone()),
                    }),
                )
            }
            _ => (None, None, None),
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
            grpc,
            xhttp,
            tag: out.tag.clone(),
            alter_id: vmess_meta.0,
            vmess_security: vmess_meta.1,
        });
    }
    bail!("no usable outbound found")
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
    #[serde(default, rename = "grpcSettings")]
    grpc_settings: Option<XrayGrpcSettings>,
    #[serde(default, rename = "xhttpSettings")]
    xhttp_settings: Option<XrayXhttpSettings>,
    #[serde(default, rename = "splithttpSettings")]
    splithttp_settings: Option<XrayXhttpSettings>,
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

#[derive(Deserialize)]
struct XrayGrpcSettings {
    #[serde(default, rename = "serviceName")]
    service_name: Option<String>,
    #[serde(default, rename = "multiMode")]
    multi_mode: bool,
}

#[derive(Deserialize)]
struct XrayXhttpSettings {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    mode: Option<String>,
}

#[derive(Deserialize)]
struct XrayConfig {
    outbounds: Vec<XrayOutbound>,
}
