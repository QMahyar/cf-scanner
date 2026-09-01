//! Export endpouints: turn the last scan's verified candidates into something
//! a proxy client can consume directly. One server function serves every
//! format so the client never re-sends configs.
//!
//! Formats:
//! - `subscription` (base64 blob of rewritten URIs) — paste into v2rayN /
//!   NekoBox / Hiddify / sing-box.
//! - `raw` — newline-delimited rewritten URIs (no base64 wrapper).
//! - `singbox` — a minimal sing-box (or Stash) `outbounds` config.
//! - `clash` — a minimal Mihomo/Clash Meta proxies config.
//! - result dumps: `json` / `csv` with latency/country/colo metadata.

use std::net::IpAddr;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::api::types::Verdict;
use crate::configs;
use crate::server::state::AppState;

/// Serialized result export for `?format=json` / `?format=csv`.
#[derive(serde::Deserialize)]
pub(crate) struct ResultExportQuery {
    #[serde(default)]
    pub format: Option<String>,
}

/// `?format=base64|raw|singbox|clash` (default base64).
#[derive(serde::Deserialize)]
pub(crate) struct BundleQuery {
    #[serde(default)]
    pub format: Option<String>,
}

/// Content-type for each export; endpoints only allow localhost access.
fn text_response(body: String, content_type: &'static str, filename: &str) -> Response {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(n) = HeaderValue::from_str(filename) {
        headers.insert(header::CONTENT_DISPOSITION, n);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    (headers, body).into_response()
}

/// Best-effort remark (fragment tag) for a verified candidate.
fn remark_for(v: &Verdict) -> Option<String> {
    let p2 = v.phase2.as_ref()?;
    if !p2.passed {
        return None;
    }
    let place = v.colo.as_deref().or(v.country.as_deref()).unwrap_or("CF");
    let lat = p2.latency_ms.or(v.latency_ms);
    Some(match lat {
        Some(l) => format!("CF-{place}-{l}ms"),
        None => format!("CF-{place}"),
    })
}

/// Rewrite each passing candidate's original config against its verified
/// endpoint, returning one importable URI per row (skips rows with no
/// source config or a render failure).
fn rewrite_uris(non_null_ips: &[Verdict], configs: &[String]) -> Vec<String> {
    let mut uris = Vec::new();
    for v in non_null_ips {
        let Some(p2) = v.phase2.as_ref() else {
            continue;
        };
        if !p2.passed {
            continue;
        }
        let Some(idx) = p2.config_index else { continue };
        let Some(cfg) = configs.get(idx as usize) else {
            continue;
        };
        let IpAddr::V4(ip) = v.ip else { continue };
        let remark = remark_for(v);
        if let Ok(uri) = configs::export_config_uri(cfg, ip, v.port, None, remark.as_deref()) {
            uris.push(uri);
        }
    }
    uris
}

fn subscription_body(format: &str, non_null_ips: &[Verdict], configs: &[String]) -> Response {
    let uris = rewrite_uris(non_null_ips, configs);
    let joined = uris.join("\n");
    let body = match format {
        "raw" => joined,
        "singbox" => singbox_body(&uris),
        "clash" => clash_body(&uris),
        _ => base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            joined.as_bytes(),
        ),
    };
    let (ctype, filename) = match format {
        "raw" => (
            "text/plain; charset=utf-8",
            "attachment; filename=\"cf-scanner.txt\"",
        ),
        "singbox" => (
            "application/json; charset=utf-8",
            "attachment; filename=\"cf-scanner-singbox.json\"",
        ),
        "clash" => (
            "text/yaml; charset=utf-8",
            "attachment; filename=\"cf-scanner-clash.yaml\"",
        ),
        _ => (
            "text/plain; charset=utf-8",
            "attachment; filename=\"cf-scanner-sub.txt\"",
        ),
    };
    text_response(body, ctype, filename)
}
/// Minimal sing-box config: one `urltest`  group over the rewrite URIs so
/// several endpoints can be packed into a single importable file.
fn singbox_body(uris: &[String]) -> String {
    // sing-box accepts outbounds keyed by type; we decode each URI back into a
    // spec via the shared parser rather than string-splicing, so every field
    // (uuid, password, transport, tls, sni) survives.
    let mut outbounds: Vec<serde_json::Value> = Vec::new();
    for uri in uris {
        if let Ok(spec) = configs::parse_uri(uri) {
            let mut ob = serde_json::json!({
                "type": spec.protocol.as_str(),
                "tag": spec.tag.clone().unwrap_or_else(|| "cf-scanner".into()),
                "server": spec.server,
                "server_port": spec.port,
            });
            let obj = ob.as_object_mut().unwrap();
            match spec.protocol {
                configs::Protocol::Vless | configs::Protocol::Vmess => {
                    obj.insert("uuid".into(), spec.user_id.into());
                }
                configs::Protocol::Trojan | configs::Protocol::Shadowsocks => {
                    obj.insert("password".into(), spec.user_id.into());
                }
            }
            if let Some(m) = &spec.method {
                if spec.protocol == configs::Protocol::Shadowsocks {
                    obj.insert("method".into(), m.clone().into());
                }
            }
            if spec.security == "tls" {
                obj.insert("tls".into(), serde_json::json!({ "enabled": true }));
                if let Some(sni) = &spec.tls_server_name
                    && !sni.is_empty()
                {
                    obj["tls"]["server_name"] = sni.clone().into();
                }
            }
            if let Some(ws) = &spec.ws {
                obj.insert(
                    "transport".into(),
                    serde_json::json!({ "type": "ws", "path": ws.path }),
                );
            }
            outbounds.push(ob);
        }
    }
    serde_json::json!({ "outbounds": outbounds }).to_string()
}

/// Minimal Clash/Mihomo proxies config; JSON is accepted by Mihomo and is
/// easier to build safely than hand-rolled YAML.
fn clash_body(uris: &[String]) -> String {
    let mut proxies: Vec<serde_json::Value> = Vec::new();
    for uri in uris {
        if let Ok(spec) = configs::parse_uri(uri) {
            let mut p = serde_json::json!({
                "name": spec.tag.clone().unwrap_or_else(|| "cf-scanner".into()),
                "type": match spec.protocol {
                    configs::Protocol::Vless => "vless",
                    configs::Protocol::Vmess => "vmess",
                    configs::Protocol::Trojan => "trojan",
                    configs::Protocol::Shadowsocks => "ss",
                },
                "server": spec.server,
                "port": spec.port,
                "uuid": if matches!(spec.protocol, configs::Protocol::Vless | configs::Protocol::Vmess) { spec.user_id.clone() } else { String::new() },
                "password": if matches!(spec.protocol, configs::Protocol::Trojan | configs::Protocol::Shadowsocks) { spec.user_id.clone() } else { String::new() },
            });
            let obj = p.as_object_mut().unwrap();
            if spec.protocol == configs::Protocol::Shadowsocks {
                if let Some(m) = &spec.method {
                    obj.insert("cipher".into(), m.clone().into());
                }
            }
            if spec.security == "tls" {
                obj.insert("tls".into(), true.into());
                if let Some(sni) = &spec.tls_server_name
                    && !sni.is_empty()
                {
                    obj.insert("servername".into(), sni.clone().into());
                }
            }
            if let Some(ws) = &spec.ws {
                obj.insert("network".into(), "ws".into());
                obj.insert("ws-opts".into(), serde_json::json!({ "path": ws.path }));
            }
            proxies.push(p);
        }
    }
    // Mihomo reads JSON too; emit the same shape as a clash config.
    serde_json::json!({
        "mixed-port": 7890,
        "proxies": proxies,
    })
    .to_string()
}

fn result_dump(format: &str, verdicts: &[Verdict]) -> Response {
    // Verdicts arrive already sorted by latency (engine snapshot_sorted); keep
    // the order for CSV, and wrap JSON as a stable object for easy parsing.
    let body = match format {
        "json" => serde_json::json!({ "results": verdicts, "count": verdicts.len() }).to_string(),
        _ => {
            let mut out =
                String::from("ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms\n");
            for v in verdicts {
                let p2 = v.phase2.as_ref();
                out.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    v.ip,
                    v.port,
                    v.latency_ms.map(|x| x.to_string()).unwrap_or_default(),
                    v.country.as_deref().unwrap_or(""),
                    v.colo.as_deref().unwrap_or(""),
                    p2.map(|p| if p.passed { "1" } else { "0" }).unwrap_or(""),
                    p2.and_then(|p| p.latency_ms)
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                ));
            }
            out
        }
    };
    let (ctype, filename) = if format == "json" {
        (
            "application/json; charset=utf-8",
            "attachment; filename=\"cf-scanner-results.json\"",
        )
    } else {
        (
            "text/csv; charset=utf-8",
            "attachment; filename=\"cf-scanner-results.csv\"",
        )
    };
    text_response(body, ctype, filename)
}

/// `GET /api/bundle?format=...` — the last scan's verified set, rewritten.
pub(crate) async fn bundle(
    State(state): State<std::sync::Arc<AppState>>,
    Query(q): Query<BundleQuery>,
) -> Response {
    let format = q.format.as_deref().unwrap_or("base64");
    let configs = state.controller.phase2_configs();
    let results = state.controller.results();
    subscription_body(format, &results, &configs)
}

/// `GET /api/results/export?format=json|csv` — metadata dump of the results.
pub(crate) async fn result_export(
    State(state): State<std::sync::Arc<AppState>>,
    Query(q): Query<ResultExportQuery>,
) -> Response {
    let format = q.format.as_deref().unwrap_or("csv");
    let results = state.controller.results();
    result_dump(format, &results)
}
