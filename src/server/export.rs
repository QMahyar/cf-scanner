use std::net::IpAddr;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::api::types::Verdict;
use crate::configs;
use crate::server::error::ApiError;
use crate::server::state::AppState;

#[derive(serde::Deserialize)]
pub(crate) struct ResultExportQuery {
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct BundleQuery {
    #[serde(default)]
    pub format: Option<String>,
}

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

fn unique_tag(tag: String, seen: &mut std::collections::HashMap<String, usize>) -> String {
    let n = seen.entry(tag.clone()).or_insert(0);
    *n += 1;
    if *n == 1 {
        tag
    } else {
        format!("{tag}-{}", *n)
    }
}

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
fn singbox_body(uris: &[String]) -> String {
    let mut outbounds: Vec<serde_json::Value> = Vec::new();
    let mut seen_tags: std::collections::HashMap<String, usize> = Default::default();
    for uri in uris {
        if let Ok(spec) = configs::parse_uri(uri) {
            let tag = unique_tag(
                spec.tag.clone().unwrap_or_else(|| "cf-scanner".into()),
                &mut seen_tags,
            );
            let mut ob = serde_json::json!({
                "type": spec.protocol.as_str(),
                "tag": tag,
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

fn clash_body(uris: &[String]) -> String {
    let mut proxies: Vec<serde_json::Value> = Vec::new();
    let mut seen_names: std::collections::HashMap<String, usize> = Default::default();
    for uri in uris {
        if let Ok(spec) = configs::parse_uri(uri) {
            let mut p = serde_json::json!({
                "name": unique_tag(
                    spec.tag.clone().unwrap_or_else(|| "cf-scanner".into()),
                    &mut seen_names,
                ),
                "type": match spec.protocol {
                    configs::Protocol::Vless => "vless",
                    configs::Protocol::Vmess => "vmess",
                    configs::Protocol::Trojan => "trojan",
                    configs::Protocol::Shadowsocks => "ss",
                },
                "server": spec.server,
                "port": spec.port,
            });
            let obj = p.as_object_mut().unwrap();
            match spec.protocol {
                configs::Protocol::Vless | configs::Protocol::Vmess => {
                    obj.insert("uuid".into(), spec.user_id.into());
                }
                configs::Protocol::Trojan | configs::Protocol::Shadowsocks => {
                    obj.insert("password".into(), spec.user_id.into());
                }
            }
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
    serde_json::json!({
        "mixed-port": 7890,
        "proxies": proxies,
    })
    .to_string()
}

pub(crate) fn csv_field(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_owned()
    }
}

fn result_dump(format: &str, verdicts: &[Verdict]) -> Response {
    let body = match format {
        "json" => serde_json::json!({ "results": verdicts, "count": verdicts.len() }).to_string(),
        _ => {
            let mut out =
                String::from("ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms\n");
            for v in verdicts {
                let p2 = v.phase2.as_ref();
                let fields = [
                    v.ip.to_string(),
                    v.port.to_string(),
                    v.latency_ms.map(|x| x.to_string()).unwrap_or_default(),
                    v.country.as_deref().unwrap_or("").to_owned(),
                    v.colo.as_deref().unwrap_or("").to_owned(),
                    p2.map(|p| if p.passed { "1" } else { "0" })
                        .unwrap_or("")
                        .to_owned(),
                    p2.and_then(|p| p.latency_ms)
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                ];
                let quoted: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
                out.push_str(&quoted.join(","));
                out.push('\n');
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

pub(crate) async fn bundle(
    State(state): State<std::sync::Arc<AppState>>,
    Query(q): Query<BundleQuery>,
) -> Response {
    const FORMATS: [&str; 4] = ["base64", "raw", "singbox", "clash"];
    let Some(format) = resolve_format(q.format.as_deref(), &FORMATS) else {
        return ApiError::bad_request(format!(
            "unknown format {:?}; expected one of {}",
            q.format.as_deref().unwrap_or(""),
            FORMATS.join("|")
        ))
        .into_response();
    };
    let configs = state.controller.phase2_configs();
    let results = state.controller.results();
    subscription_body(format, &results, &configs)
}

pub(crate) async fn result_export(
    State(state): State<std::sync::Arc<AppState>>,
    Query(q): Query<ResultExportQuery>,
) -> Response {
    const FORMATS: [&str; 2] = ["csv", "json"];
    let Some(format) = resolve_format(q.format.as_deref(), &FORMATS) else {
        return ApiError::bad_request(format!(
            "unknown format {:?}; expected one of {}",
            q.format.as_deref().unwrap_or(""),
            FORMATS.join("|")
        ))
        .into_response();
    };
    let results = state.controller.results();
    result_dump(format, &results)
}

fn resolve_format<'a>(query: Option<&'a str>, allowed: &[&'a str]) -> Option<&'a str> {
    match query {
        None => Some(allowed.first().copied().unwrap_or("")),
        Some(f) if allowed.contains(&f) => Some(f),
        Some(_) => None,
    }
}
