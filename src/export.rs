use std::net::IpAddr;

use crate::api::types::Verdict;
use crate::configs;

pub const BUNDLE_FORMATS: [&str; 4] = ["base64", "raw", "singbox", "clash"];
pub const SHARELINK_FORMATS: [&str; 1] = ["sharelinks"];
pub const RESULT_FORMATS: [&str; 2] = ["csv", "json"];

pub fn render_bundle(
    format: &str,
    verdicts: &[Verdict],
    configs: &[String],
) -> Result<String, String> {
    let mut allowed: Vec<&str> = BUNDLE_FORMATS.to_vec();
    allowed.extend_from_slice(&SHARELINK_FORMATS);
    resolve_format(format, &allowed)
        .ok_or_else(|| unknown_format(format, &allowed))
        .and_then(|fmt| bundle_body(fmt, verdicts, configs))
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

fn rewrite_uris(non_null_ips: &[Verdict], configs: &[String]) -> (Vec<String>, usize) {
    let mut uris = Vec::new();
    let mut v6_skipped = 0usize;
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
        let IpAddr::V4(ip) = v.ip else {
            v6_skipped += 1;
            continue;
        };
        let sni_override = if p2.sni.is_empty() {
            None
        } else {
            Some(p2.sni.as_str())
        };
        let remark = remark_for(v);
        if let Ok(uri) =
            configs::export_config_uri(cfg, ip, v.port, sni_override, remark.as_deref())
        {
            uris.push(uri);
        }
    }
    (uris, v6_skipped)
}

fn bundle_body(
    format: &str,
    non_null_ips: &[Verdict],
    configs: &[String],
) -> Result<String, String> {
    let (uris, v6_skipped) = rewrite_uris(non_null_ips, configs);
    if uris.is_empty() && v6_skipped > 0 {
        return Err(format!(
            "no exportable endpoints: {v6_skipped} passing endpoint(s) are IPv6 and bundle formats support IPv4 only"
        ));
    }
    let joined = uris.join("\n");
    Ok(match format {
        "raw" | "sharelinks" => joined,
        "singbox" => singbox_body(&uris),
        "clash" => clash_body(&uris),
        _ => base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            joined.as_bytes(),
        ),
    })
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
            if spec.protocol == configs::Protocol::Vmess {
                if spec.alter_id != 0 {
                    obj.insert("alter_id".into(), spec.alter_id.into());
                }
                if let Some(scy) = &spec.vmess_security
                    && !scy.is_empty()
                {
                    obj.insert("security".into(), scy.clone().into());
                }
            }
            if let Some(m) = &spec.method {
                if spec.protocol == configs::Protocol::Shadowsocks {
                    obj.insert("method".into(), m.clone().into());
                }
            }
            if spec.security == "tls" {
                let mut tls = serde_json::json!({ "enabled": true });
                if let Some(sni) = &spec.tls_server_name
                    && !sni.is_empty()
                {
                    tls["server_name"] = sni.clone().into();
                }
                if let Some(fp) = &spec.fingerprint
                    && !fp.is_empty()
                {
                    tls["utls"] = serde_json::json!({ "enabled": true, "fingerprint": fp });
                }
                obj.insert("tls".into(), tls);
            }
            if let Some(ws) = &spec.ws {
                let mut transport = serde_json::json!({ "type": "ws", "path": ws.path });
                if let Some(host) = &ws.host
                    && !host.is_empty()
                {
                    transport["headers"] = serde_json::json!({ "Host": host });
                }
                obj.insert("transport".into(), transport);
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
            if spec.protocol == configs::Protocol::Vmess && spec.alter_id != 0 {
                obj.insert("alterId".into(), spec.alter_id.into());
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
                if let Some(fp) = &spec.fingerprint
                    && !fp.is_empty()
                {
                    obj.insert("client-fingerprint".into(), fp.clone().into());
                }
            }
            if let Some(ws) = &spec.ws {
                obj.insert("network".into(), "ws".into());
                let mut opts = serde_json::json!({ "path": ws.path });
                if let Some(host) = &ws.host
                    && !host.is_empty()
                {
                    opts["headers"] = serde_json::json!({ "Host": host });
                }
                obj.insert("ws-opts".into(), opts);
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
    let guarded = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn result_dump(format: &str, verdicts: &[Verdict]) -> String {
    match format {
        "json" => serde_json::json!({ "results": verdicts, "count": verdicts.len() }).to_string(),
        _ => {
            let mut out = String::from(
                "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,sent,received,loss_pct,fail_reason\n",
            );
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
                    v.sent.to_string(),
                    v.received.to_string(),
                    v.loss_pct.map(|x| x.to_string()).unwrap_or_default(),
                    v.fail_reason.clone().unwrap_or_default(),
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
    use super::*;
    use crate::api::types::{FragmentPreset, Phase2Verdict};
    use base64::Engine;

    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@origin.example.com:443?security=tls&sni=origin.example.com&type=ws&path=%2Fws&host=ws.example.com#orig";
    const TROJAN: &str = "trojan://pass2222-3333-4444-5555-666677778888@origin.example.com:443?security=tls&sni=origin.example.com#orig";

    fn passing(ip: &str, port: u16, cfg: Option<u32>) -> Verdict {
        Verdict {
            ip: ip.parse().unwrap(),
            port,
            latency_ms: Some(12),
            country: Some("US".into()),
            colo: Some("LAX".into()),
            phase2: Some(Phase2Verdict {
                passed: true,
                fragment: FragmentPreset::Medium,
                sni: "cdn.example.com".into(),
                latency_ms: Some(40),
                error: None,
                config_index: cfg,
                verifier: None,
            }),
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
        }
    }

    #[test]
    fn csv_field_quotes_metacharacters() {
        assert_eq!(csv_field("LAX"), "LAX");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn csv_field_neutralizes_formula_leadins() {
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("+cmd|'URL'"), "'+cmd|'URL'");
        assert_eq!(csv_field("-2+3"), "'-2+3");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("\t=cmd"), "'\t=cmd");
        assert_eq!(csv_field("\r=cmd"), "\"'\r=cmd\"");
        assert_eq!(csv_field("US"), "US");
        assert_eq!(csv_field("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn csv_field_neutralizes_then_quotes() {
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"");
        assert_eq!(csv_field("=say \"hi\""), "\"'=say \"\"hi\"\"\"");
    }

    #[test]
    fn render_results_json_shape() {
        let out = render_results("json", &[passing("1.2.3.4", 443, None)]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 1);
        let row = &v["results"][0];
        for key in ["ip", "port", "latency_ms", "country", "colo", "phase2"] {
            assert!(row.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(row["ip"], "1.2.3.4");
        let empty = render_results("json", &[]).unwrap();
        assert_eq!(empty, "{\"count\":0,\"results\":[]}");
    }

    #[test]
    fn render_results_csv_empty_and_unknown() {
        let header = "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,sent,received,loss_pct,fail_reason\n";
        assert_eq!(render_results("csv", &[]).unwrap(), header);
        let err = render_results("xml", &[]).unwrap_err();
        assert!(err.contains("csv|json"), "{err}");
    }

    #[test]
    fn render_results_csv_header_schema() {
        const EXPECTED: &str = "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,sent,received,loss_pct,fail_reason";
        let out = render_results("csv", &[passing("1.2.3.4", 443, None)]).unwrap();
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some(EXPECTED));
        for row in lines {
            assert_eq!(
                row.split(',').count(),
                EXPECTED.split(',').count(),
                "row/header column mismatch: {row}"
            );
        }
    }

    #[test]
    fn render_results_csv_includes_loss_and_fail_reason_columns() {
        let mut failed = passing("9.9.9.9", 443, None);
        failed.phase2 = None;
        failed.latency_ms = None;
        failed.sent = 1;
        failed.received = 0;
        failed.loss_pct = Some(100);
        failed.fail_reason = Some("refused".to_owned());
        let out = render_results("csv", &[passing("1.2.3.4", 443, None), failed]).unwrap();
        let rows: Vec<&str> = out.lines().collect();
        assert_eq!(rows.len(), 3);
        let good: Vec<&str> = rows[1].split(',').collect();
        assert_eq!(good[7], "1", "sent");
        assert_eq!(good[8], "1", "received");
        assert_eq!(good[9], "0", "loss_pct");
        assert_eq!(good[10], "", "no fail reason");
        let bad: Vec<&str> = rows[2].split(',').collect();
        assert_eq!(bad[2], "", "failed verdict has no latency");
        assert_eq!(bad[7], "1");
        assert_eq!(bad[8], "0");
        assert_eq!(bad[9], "100");
        assert_eq!(bad[10], "refused");
    }

    #[test]
    fn render_bundle_empty_inputs_are_valid() {
        assert_eq!(render_bundle("raw", &[], &[]).unwrap(), "");
        assert_eq!(render_bundle("base64", &[], &[]).unwrap(), "");
        assert_eq!(render_bundle("sharelinks", &[], &[]).unwrap(), "");
        let sb: serde_json::Value =
            serde_json::from_str(&render_bundle("singbox", &[], &[]).unwrap()).unwrap();
        assert_eq!(sb["outbounds"].as_array().unwrap().len(), 0);
        let cl: serde_json::Value =
            serde_json::from_str(&render_bundle("clash", &[], &[]).unwrap()).unwrap();
        assert_eq!(cl["proxies"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn render_bundle_errors_when_only_ipv6_passed() {
        let v6 = passing("2001:db8::1", 443, Some(0));
        let configs = [VLESS.to_owned()];
        for fmt in BUNDLE_FORMATS.into_iter().chain(SHARELINK_FORMATS) {
            let err = render_bundle(fmt, std::slice::from_ref(&v6), &configs).unwrap_err();
            assert!(err.contains("IPv6"), "{fmt}: {err}");
        }
    }

    #[test]
    fn render_bundle_drops_ipv6_in_mixed_sets() {
        let verdicts = [
            passing("1.2.3.4", 2053, Some(0)),
            passing("2001:db8::1", 443, Some(0)),
        ];
        let raw = render_bundle("raw", &verdicts, &[VLESS.to_owned()]).unwrap();
        assert_eq!(raw.lines().count(), 1);
        assert!(raw.contains("1.2.3.4:2053"));
        assert!(!raw.contains("2001:db8"));
    }

    #[test]
    fn render_bundle_base64_roundtrip_no_stray_newline() {
        let verdicts = [
            passing("1.2.3.4", 2053, Some(0)),
            passing("5.6.7.8", 8443, Some(1)),
        ];
        let configs = [VLESS.to_owned(), TROJAN.to_owned()];
        let raw = render_bundle("raw", &verdicts, &configs).unwrap();
        let b64 = render_bundle("base64", &verdicts, &configs).unwrap();
        assert!(!b64.contains(['\n', '\r', ' ']));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), raw);
    }

    #[test]
    fn render_bundle_uses_verified_sni_and_remark() {
        let raw = render_bundle(
            "raw",
            &[passing("1.2.3.4", 2053, Some(0))],
            &[VLESS.to_owned()],
        )
        .unwrap();
        assert!(raw.contains("@1.2.3.4:2053"), "{raw}");
        assert!(raw.contains("sni=cdn.example.com"), "{raw}");
        assert!(raw.contains("#CF-LAX-40ms"), "{raw}");
        assert!(!raw.contains("origin.example.com"), "{raw}");
    }

    #[test]
    fn render_bundle_sharelinks_rewrites_uri_onto_endpoint() {
        let out = render_bundle(
            "sharelinks",
            &[passing("1.2.3.4", 2053, Some(0))],
            &[VLESS.to_owned()],
        )
        .unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("vless://"), "{out}");
        assert!(out.contains("@1.2.3.4:2053"), "{out}");
        assert!(out.contains("sni=cdn.example.com"), "{out}");
        assert!(out.contains("#CF-LAX-40ms"), "{out}");
        assert!(!out.contains("origin.example.com"), "{out}");
    }

    #[test]
    fn render_bundle_rejects_bad_config_index() {
        let raw = render_bundle(
            "raw",
            &[passing("1.2.3.4", 2053, Some(9))],
            &[VLESS.to_owned()],
        )
        .unwrap();
        assert_eq!(raw, "");
    }

    fn vmess_uri() -> String {
        let payload = serde_json::json!({
            "v": "2", "ps": "tag-one", "add": "5.6.7.8", "port": "443",
            "id": "11112222-3333-4444-5555-666677778888", "aid": "64", "scy": "auto",
            "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/vp",
            "tls": "tls", "sni": "cdn.example.com", "fp": "chrome"
        });
        format!(
            "vmess://{}#tag-one",
            base64::engine::general_purpose::STANDARD.encode(payload.to_string())
        )
    }

    #[test]
    fn singbox_vmess_shape() {
        let sb: serde_json::Value = serde_json::from_str(&singbox_body(&[vmess_uri()])).unwrap();
        let ob = &sb["outbounds"][0];
        assert_eq!(ob["type"], "vmess");
        assert_eq!(ob["tag"], "tag-one");
        assert_eq!(ob["server"], "5.6.7.8");
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["uuid"], "11112222-3333-4444-5555-666677778888");
        assert_eq!(ob["alter_id"], 64);
        assert_eq!(ob["security"], "auto");
        assert_eq!(ob["tls"]["enabled"], true);
        assert_eq!(ob["tls"]["server_name"], "cdn.example.com");
        assert_eq!(ob["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(ob["transport"]["type"], "ws");
        assert_eq!(ob["transport"]["path"], "/vp");
        assert_eq!(ob["transport"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn clash_vmess_shape() {
        let cl: serde_json::Value = serde_json::from_str(&clash_body(&[vmess_uri()])).unwrap();
        let p = &cl["proxies"][0];
        assert_eq!(p["name"], "tag-one");
        assert_eq!(p["type"], "vmess");
        assert_eq!(p["server"], "5.6.7.8");
        assert_eq!(p["port"], 443);
        assert_eq!(p["uuid"], "11112222-3333-4444-5555-666677778888");
        assert_eq!(p["alterId"], 64);
        assert_eq!(p["tls"], true);
        assert_eq!(p["servername"], "cdn.example.com");
        assert_eq!(p["client-fingerprint"], "chrome");
        assert_eq!(p["network"], "ws");
        assert_eq!(p["ws-opts"]["path"], "/vp");
        assert_eq!(p["ws-opts"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn singbox_clash_ss_method_mapping() {
        let userinfo = "aes-128-gcm:pass";
        let uri = format!(
            "ss://{}@5.6.7.8:8388#tag",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(userinfo)
        );
        let sb: serde_json::Value =
            serde_json::from_str(&singbox_body(std::slice::from_ref(&uri))).unwrap();
        let ob = &sb["outbounds"][0];
        assert_eq!(ob["type"], "shadowsocks");
        assert_eq!(ob["method"], "aes-128-gcm");
        assert_eq!(ob["password"], "pass");
        let cl: serde_json::Value = serde_json::from_str(&clash_body(&[uri])).unwrap();
        let p = &cl["proxies"][0];
        assert_eq!(p["type"], "ss");
        assert_eq!(p["cipher"], "aes-128-gcm");
        assert_eq!(p["password"], "pass");
    }
}
