use std::net::IpAddr;

use crate::api::types::Verdict;
use crate::configs;

pub const BUNDLE_FORMATS: [&str; 4] = ["base64", "raw", "singbox", "clash"];
pub const RESULT_FORMATS: [&str; 2] = ["csv", "json"];

pub fn render_bundle(
    format: &str,
    verdicts: &[Verdict],
    configs: &[String],
) -> Result<String, String> {
    resolve_format(format, &BUNDLE_FORMATS)
        .ok_or_else(|| unknown_format(format, &BUNDLE_FORMATS))
        .map(|fmt| bundle_body(fmt, verdicts, configs))
}

pub fn render_results(format: &str, verdicts: &[Verdict]) -> Result<String, String> {
    resolve_format(format, &RESULT_FORMATS)
        .ok_or_else(|| unknown_format(format, &RESULT_FORMATS))
        .map(|fmt| result_dump(fmt, verdicts))
}

fn unknown_format(format: &str, allowed: &[&str]) -> String {
    format!(
        "unknown format {format:?}; expected one of {}",
        allowed.join("|")
    )
}

fn resolve_format<'a>(format: &'a str, allowed: &[&'a str]) -> Option<&'a str> {
    if allowed.contains(&format) {
        Some(format)
    } else {
        None
    }
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

fn bundle_body(format: &str, non_null_ips: &[Verdict], configs: &[String]) -> String {
    let uris = rewrite_uris(non_null_ips, configs);
    let joined = uris.join("\n");
    match format {
        "raw" => joined,
        "singbox" => singbox_body(&uris),
        "clash" => clash_body(&uris),
        _ => base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            joined.as_bytes(),
        ),
    }
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

fn result_dump(format: &str, verdicts: &[Verdict]) -> String {
    match format {
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
    }
}

#[cfg(test)]
mod tests {
    use super::csv_field;

    #[test]
    fn csv_field_quotes_metacharacters() {
        assert_eq!(csv_field("LAX"), "LAX");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }
}
