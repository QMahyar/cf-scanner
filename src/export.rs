use std::net::IpAddr;
use std::sync::Arc;

use clap::ValueEnum;

use crate::api::types::{Verdict, Verifier};
use crate::configs;
use crate::engine::ScanController;

fn human_reason(reason: &str) -> &str {
    match reason {
        "refused" => "connection refused",
        "timeout" => "timed out",
        "tls_failed" => "TLS handshake failed",
        "http_status" => "unexpected HTTP status",
        other => other,
    }
}

pub fn diagnostic_line(v: &Verdict) -> String {
    let endpoint = match v.ip {
        IpAddr::V6(_) => format!("[{}]:{}", v.ip, v.port),
        _ => format!("{}:{}", v.ip, v.port),
    };
    let mut parts = vec![endpoint];
    match (&v.fail_reason, v.latency_ms) {
        (Some(reason), _) => parts.push(human_reason(reason).to_owned()),
        (None, Some(ms)) => parts.push(format!("ok, {ms}ms")),
        (None, None) => parts.push("no result".to_owned()),
    }
    if v.loss_pct.unwrap_or(0) > 0 {
        parts.push(format!("loss {}%", v.loss_pct.unwrap_or(0)));
    }
    match (&v.country, &v.colo) {
        (Some(country), Some(colo)) => parts.push(format!("{country}/{colo}")),
        (Some(country), None) => parts.push(country.clone()),
        (None, Some(colo)) => parts.push(format!("colo {colo}")),
        (None, None) => {}
    }
    if let Some(asn) = v.asn {
        match &v.isp {
            Some(isp) if !isp.is_empty() => parts.push(format!("AS{asn} {isp}")),
            _ => parts.push(format!("AS{asn}")),
        }
    }
    if let Some(p) = &v.phase2 {
        if p.passed {
            let via = match p.verifier {
                Some(Verifier::Inline) => "via inline ",
                Some(Verifier::Xray) => "via xray ",
                None => "",
            };
            match p.latency_ms {
                Some(ms) => parts.push(format!("tunnel {via}ok ({ms}ms)")),
                None => parts.push(format!("tunnel {via}ok")),
            }
        } else {
            match &p.error {
                Some(err) => parts.push(format!("tunnel failed ({err})")),
                None => parts.push("tunnel failed".to_owned()),
            }
        }
    }
    parts.join(" — ")
}

/// The single source of truth for export formats (F-27.6). Adding a format
/// means: one `FormatSpec` row here + one `ExportFormatArg` variant +
/// one `export_format_name` arm + one `write_export` group arm; the
/// name lists, resolvers, and docs derive from this table.
pub struct FormatSpec {
    pub name: &'static str,
    pub kind: FormatKind,
    pub description: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    /// Row-per-verdict results (csv, json).
    Results,
    /// Re-rendered config bundles keyed off phase-2 passing verdicts.
    Bundle,
    /// A bundle that is itself share URIs (raw/sharelinks).
    Sharelinks,
}

pub const FORMATS: &[FormatSpec] = &[
    FormatSpec {
        name: "csv",
        kind: FormatKind::Results,
        description: "spreadsheet rows, one endpoint per line",
    },
    FormatSpec {
        name: "json",
        kind: FormatKind::Results,
        description: "full verdict objects with a count header",
    },
    FormatSpec {
        name: "base64",
        kind: FormatKind::Bundle,
        description: "base64 of the share-URI list",
    },
    FormatSpec {
        name: "raw",
        kind: FormatKind::Sharelinks,
        description: "share URIs, one per line",
    },
    FormatSpec {
        name: "singbox",
        kind: FormatKind::Bundle,
        description: "sing-box outbounds JSON",
    },
    FormatSpec {
        name: "clash",
        kind: FormatKind::Bundle,
        description: "clash proxies JSON",
    },
    FormatSpec {
        name: "sharelinks",
        kind: FormatKind::Sharelinks,
        description: "share URIs, one per line",
    },
    FormatSpec {
        name: "v2ray",
        kind: FormatKind::Bundle,
        description: "v2rayN clipboard JSON",
    },
    FormatSpec {
        name: "shadowrocket",
        kind: FormatKind::Bundle,
        description: "base64 URI list for Shadowrocket import",
    },
    FormatSpec {
        name: "quantumult",
        kind: FormatKind::Bundle,
        description: "Quantumult X server lines",
    },
];

pub(crate) fn format_names(kind: Option<FormatKind>) -> Vec<&'static str> {
    FORMATS
        .iter()
        .filter(|f| kind.is_none_or(|k| f.kind == k))
        .map(|f| f.name)
        .collect()
}

pub fn render_bundle(
    format: &str,
    verdicts: &[Verdict],
    configs: &[String],
) -> Result<String, String> {
    let allowed = format_names(None);
    resolve_format(format, &allowed)
        .ok_or_else(|| unknown_format(format, &allowed))
        .and_then(|fmt| bundle_body(fmt, verdicts, configs))
}

pub fn render_results(format: &str, verdicts: &[Verdict]) -> Result<String, String> {
    let allowed = format_names(Some(FormatKind::Results));
    resolve_format(format, &allowed)
        .ok_or_else(|| unknown_format(format, &allowed))
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

fn rewrite_uris(non_null_ips: &[Verdict], configs: &[String]) -> (Vec<String>, usize, usize) {
    let mut uris = Vec::new();
    let mut v6_skipped = 0usize;
    let mut malformed = 0usize;
    for v in non_null_ips {
        let Some(p2) = v.phase2.as_ref() else {
            continue;
        };
        if !p2.passed {
            continue;
        }
        let Some(idx) = p2.config_index else {
            malformed += 1;
            continue;
        };
        let Some(cfg) = configs.get(idx as usize) else {
            malformed += 1;
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
        } else {
            malformed += 1;
        }
    }
    (uris, v6_skipped, malformed)
}

fn bundle_body(
    format: &str,
    non_null_ips: &[Verdict],
    configs: &[String],
) -> Result<String, String> {
    let (uris, v6_skipped, malformed) = rewrite_uris(non_null_ips, configs);
    if uris.is_empty() && v6_skipped > 0 {
        return Err(format!(
            "no exportable endpoints: {v6_skipped} passing endpoint(s) are IPv6 and bundle formats support IPv4 only"
        ));
    }
    if v6_skipped > 0 {
        eprintln!(
            "warning: bundle export skipped {v6_skipped} passing IPv6 endpoint(s); bundle formats support IPv4 only"
        );
    }
    if malformed > 0 {
        eprintln!(
            "warning: bundle export skipped {malformed} endpoint(s) whose phase-2 config no longer resolves"
        );
    }
    let joined = uris.join("\n");
    Ok(match format {
        "raw" | "sharelinks" => joined,
        "singbox" => singbox_body(&uris),
        "clash" => clash_body(&uris),
        "v2ray" => v2ray_body(&uris),
        "shadowrocket" => shadowrocket_body(&uris),
        "quantumult" => quantumult_body(&uris),
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
            } else if let Some(grpc) = &spec.grpc {
                let mut transport = serde_json::json!({
                    "type": "grpc",
                    "service_name": grpc.service_name,
                });
                if let Some(mode) = &grpc.mode
                    && !mode.is_empty()
                {
                    transport["multi_mode"] = (mode == "multi").into();
                }
                obj.insert("transport".into(), transport);
            } else if let Some(xhttp) = &spec.xhttp {
                let mut transport = serde_json::json!({ "type": "splithttp", "path": xhttp.path });
                if let Some(host) = &xhttp.host
                    && !host.is_empty()
                {
                    transport["host"] = host.clone().into();
                }
                if let Some(mode) = &xhttp.mode
                    && !mode.is_empty()
                {
                    transport["mode"] = mode.clone().into();
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
                // Clash defaults to false, silently dropping UDP; scanned
                // endpoints passed real probes, so enable it.
                "udp": true,
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
                if let Some(pe) = &ws.packet_encoding
                    && !pe.is_empty()
                {
                    opts["packet-encoding"] = pe.clone().into();
                }
                obj.insert("ws-opts".into(), opts);
            } else if let Some(grpc) = &spec.grpc {
                obj.insert("network".into(), "grpc".into());
                let mut opts = serde_json::json!({ "grpc-service-name": grpc.service_name });
                if let Some(mode) = &grpc.mode
                    && !mode.is_empty()
                {
                    opts["grpc-mode"] = mode.clone().into();
                }
                obj.insert("grpc-opts".into(), opts);
            } else if let Some(xhttp) = &spec.xhttp {
                obj.insert("network".into(), "xhttp".into());
                let mut opts = serde_json::json!({ "path": xhttp.path });
                if let Some(host) = &xhttp.host
                    && !host.is_empty()
                {
                    opts["host"] = host.clone().into();
                }
                if let Some(mode) = &xhttp.mode
                    && !mode.is_empty()
                {
                    opts["mode"] = mode.clone().into();
                }
                obj.insert("xhttp-opts".into(), opts);
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

/// V2RayN-style JSON: one object per URI, `add`/`port`/`id` flat fields.
/// Consumed by v2rayN/v2rayNG import-from-clipboard.
fn v2ray_body(uris: &[String]) -> String {
    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut seen_tags: std::collections::HashMap<String, usize> = Default::default();
    for uri in uris {
        let Ok(spec) = configs::parse_uri(uri) else {
            continue;
        };
        let ps = unique_tag(
            spec.tag.clone().unwrap_or_else(|| "cf-scanner".into()),
            &mut seen_tags,
        );
        let mut entry = serde_json::json!({
            "ps": ps,
            "add": spec.server,
            "port": spec.port.to_string(),
            "id": spec.user_id,
            "scy": spec.vmess_security.clone().unwrap_or_else(|| "auto".to_owned()),
            "net": match (&spec.ws, &spec.grpc, &spec.xhttp) {
                (Some(_), _, _) => "ws",
                (_, Some(_), _) => "grpc",
                (_, _, Some(_)) => "splithttp",
                (None, None, None) => "tcp",
            },
            "type": "none",
            "tls": if spec.security == "tls" { "tls" } else { "" },
        });
        let obj = entry.as_object_mut().unwrap();
        if let Some(sni) = &spec.tls_server_name
            && !sni.is_empty()
        {
            obj.insert("sni".into(), sni.clone().into());
        }
        if let Some(fp) = &spec.fingerprint
            && !fp.is_empty()
        {
            obj.insert("fp".into(), fp.clone().into());
        }
        match spec.protocol {
            configs::Protocol::Shadowsocks => {
                obj.insert(
                    "method".into(),
                    spec.method.clone().unwrap_or_default().into(),
                );
            }
            configs::Protocol::Vmess if spec.alter_id != 0 => {
                obj.insert("aid".into(), spec.alter_id.to_string().into());
            }
            _ => {}
        }
        if let Some(ws) = &spec.ws {
            obj.insert("path".into(), ws.path.clone().into());
            if let Some(host) = &ws.host
                && !host.is_empty()
            {
                obj.insert("host".into(), host.clone().into());
            }
        } else if let Some(grpc) = &spec.grpc {
            obj.insert("path".into(), grpc.service_name.clone().into());
        } else if let Some(xhttp) = &spec.xhttp {
            obj.insert("path".into(), xhttp.path.clone().into());
        }
        entries.push(entry);
    }
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_owned())
}

/// Shadowrocket: a base64-encoded newline list of share URIs (its standard
/// clipboard import format).
fn shadowrocket_body(uris: &[String]) -> String {
    let joined = uris.join("\n");
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        joined.as_bytes(),
    )
}

/// Quantumult X: one line per endpoint in its server-local format.
/// Only vless (vles:// trojan) has a native QX line; vmess is the base64
/// blob QX accepts inline; ss uses its URI form.
fn quantumult_body(uris: &[String]) -> String {
    let mut lines = Vec::new();
    for uri in uris {
        let Ok(spec) = configs::parse_uri(uri) else {
            continue;
        };
        let tls_part = if spec.security == "tls" {
            ",tls=true"
        } else {
            ""
        };
        let sni_part = spec
            .tls_server_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!(",tls-host={s}"))
            .unwrap_or_default();
        let obfs_part = if spec.ws.is_some() { ",obfs=wss" } else { "" };
        match spec.protocol {
            configs::Protocol::Shadowsocks => {
                let method = spec.method.clone().unwrap_or_default();
                lines.push(format!(
                    "shadowsocks={}:{}, method={}, password={}",
                    spec.server, spec.port, method, spec.user_id
                ));
            }
            configs::Protocol::Trojan => {
                lines.push(format!(
                    "trojan={}:{}, password={}{tobfs}{tls}{sni}",
                    spec.server,
                    spec.port,
                    spec.user_id,
                    tobfs = obfs_part,
                    tls = tls_part,
                    sni = sni_part,
                ));
            }
            configs::Protocol::Vless | configs::Protocol::Vmess => {
                // QX has no native vless/vmess line; ship the share URI so the
                // user's importer handles conversion.
                lines.push(uri.clone());
            }
        }
    }
    lines.join("\n")
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
        "json" => {
            // config_index is engine-internal plumbing; it never appears in
            // exported files.
            let cleaned: Vec<serde_json::Value> = verdicts
                .iter()
                .map(|v| {
                    let mut val = serde_json::to_value(v).unwrap_or(serde_json::Value::Null);
                    if let Some(p2) = val.get_mut("phase2").and_then(|p| p.as_object_mut()) {
                        p2.remove("config_index");
                    }
                    val
                })
                .collect();
            serde_json::json!({ "results": cleaned, "count": verdicts.len() }).to_string()
        }
        _ => {
            let mut out = String::from(
                "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,speed_test_mbps,sent,received,loss_pct,fail_reason,asn,isp\n",
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
                    p2.and_then(|p| p.speed_test_mbps)
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                    v.sent.to_string(),
                    v.received.to_string(),
                    v.loss_pct.map(|x| x.to_string()).unwrap_or_default(),
                    v.fail_reason.clone().unwrap_or_default(),
                    v.asn.map(|x| x.to_string()).unwrap_or_default(),
                    v.isp.clone().unwrap_or_default(),
                ];
                let quoted: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
                out.push_str(&quoted.join(","));
                out.push('\n');
            }
            out
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum ExportFormatArg {
    Csv,
    Json,
    Base64,
    Raw,
    Singbox,
    Clash,
    Sharelinks,
    V2ray,
    Shadowrocket,
    Quantumult,
}

fn export_format_name(format: ExportFormatArg) -> &'static str {
    match format {
        ExportFormatArg::Csv => "csv",
        ExportFormatArg::Json => "json",
        ExportFormatArg::Base64 => "base64",
        ExportFormatArg::Raw => "raw",
        ExportFormatArg::Singbox => "singbox",
        ExportFormatArg::Clash => "clash",
        ExportFormatArg::Sharelinks => "sharelinks",
        ExportFormatArg::V2ray => "v2ray",
        ExportFormatArg::Shadowrocket => "shadowrocket",
        ExportFormatArg::Quantumult => "quantumult",
    }
}

pub fn write_export(
    controller: &Arc<ScanController>,
    path: &std::path::Path,
    format: ExportFormatArg,
) -> anyhow::Result<()> {
    let format_name = export_format_name(format);
    let results = controller.results();
    let body = match format {
        ExportFormatArg::Csv | ExportFormatArg::Json => render_results(format_name, &results),
        ExportFormatArg::Base64
        | ExportFormatArg::Raw
        | ExportFormatArg::Singbox
        | ExportFormatArg::Clash
        | ExportFormatArg::Sharelinks
        | ExportFormatArg::V2ray
        | ExportFormatArg::Shadowrocket
        | ExportFormatArg::Quantumult => {
            let configs = controller.phase2_configs();
            render_bundle(format_name, &results, &configs)
        }
    }
    .map_err(|e| anyhow::anyhow!("export failed: {e}"))?;
    if path.as_os_str() == "-" {
        println!("{body}");
    } else {
        atomic_write_file(path, body.as_bytes())
            .map_err(|e| anyhow::anyhow!("could not write {}: {e}", path.display()))?;
        eprintln!("results exported to {}", path.display());
    }
    Ok(())
}

static EXPORT_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn atomic_write_file(dest: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_owned());
    let uniq = EXPORT_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dest.with_file_name(format!("{name}.tmp-{}-{uniq}", std::process::id()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(dest);
        }
        std::fs::rename(&tmp, dest)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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
                speed_test_mbps: None,
            }),
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
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
        let header = "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,speed_test_mbps,sent,received,loss_pct,fail_reason,asn,isp\n";
        assert_eq!(render_results("csv", &[]).unwrap(), header);
        let err = render_results("xml", &[]).unwrap_err();
        assert!(err.contains("csv|json"), "{err}");
    }

    #[test]
    fn render_results_csv_header_schema() {
        const EXPECTED: &str = "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,speed_test_mbps,sent,received,loss_pct,fail_reason,asn,isp";
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
    fn render_results_csv_includes_speed_test_column_when_measured() {
        let mut measured = passing("1.2.3.4", 443, None);
        measured.phase2.as_mut().unwrap().speed_test_mbps = Some(3.5);
        let out = render_results("csv", &[measured]).unwrap();
        let row: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
        assert_eq!(
            row[7], "3.5",
            "speed_test_mbps column carries the measurement: {out}"
        );
        let plain = passing("5.6.7.8", 443, None);
        let out = render_results("csv", &[plain]).unwrap();
        let row: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
        assert_eq!(
            row[7], "",
            "unmeasured endpoints leave the column empty: {out}"
        );
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
        assert_eq!(good[8], "1", "sent");
        assert_eq!(good[9], "1", "received");
        assert_eq!(good[10], "0", "loss_pct");
        assert_eq!(good[11], "", "no fail reason");
        let bad: Vec<&str> = rows[2].split(',').collect();
        assert_eq!(bad[2], "", "failed verdict has no latency");
        assert_eq!(bad[8], "1");
        assert_eq!(bad[9], "0");
        assert_eq!(bad[10], "100");
        assert_eq!(bad[11], "refused");
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
        for fmt in format_names(None) {
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

    #[test]
    fn singbox_clash_emit_grpc_and_xhttp_transports() {
        let grpc = "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?security=tls&type=grpc&serviceName=grpc-svc";
        let sb: serde_json::Value = serde_json::from_str(&singbox_body(&[grpc.into()])).unwrap();
        let ob = &sb["outbounds"][0];
        assert_eq!(ob["transport"]["type"], "grpc");
        assert_eq!(ob["transport"]["service_name"], "grpc-svc");
        let cl: serde_json::Value = serde_json::from_str(&clash_body(&[grpc.into()])).unwrap();
        let p = &cl["proxies"][0];
        assert_eq!(p["network"], "grpc");
        assert_eq!(p["grpc-opts"]["grpc-service-name"], "grpc-svc");

        let xhttp = "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?security=tls&type=xhttp&path=%2Fxh&host=cdn.example.com&mode=stream";
        let sb: serde_json::Value = serde_json::from_str(&singbox_body(&[xhttp.into()])).unwrap();
        let ob = &sb["outbounds"][0];
        assert_eq!(ob["transport"]["type"], "splithttp");
        assert_eq!(ob["transport"]["path"], "/xh");
        assert_eq!(ob["transport"]["host"], "cdn.example.com");
        assert_eq!(ob["transport"]["mode"], "stream");
        let cl: serde_json::Value = serde_json::from_str(&clash_body(&[xhttp.into()])).unwrap();
        let p = &cl["proxies"][0];
        assert_eq!(p["network"], "xhttp");
        assert_eq!(p["xhttp-opts"]["path"], "/xh");
        assert_eq!(p["xhttp-opts"]["host"], "cdn.example.com");
        assert_eq!(p["xhttp-opts"]["mode"], "stream");
    }

    fn failed(ip: &str, port: u16, reason: &str) -> Verdict {
        Verdict {
            ip: ip.parse().unwrap(),
            port,
            latency_ms: None,
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 0,
            loss_pct: Some(100),
            fail_reason: Some(reason.to_owned()),
            asn: None,
            isp: None,
        }
    }

    #[test]
    fn diagnostic_lines_cover_failure_modes() {
        assert_eq!(
            diagnostic_line(&failed("203.0.113.5", 443, "refused")),
            "203.0.113.5:443 — connection refused — loss 100%"
        );
        assert_eq!(
            diagnostic_line(&failed("203.0.113.6", 443, "timeout")),
            "203.0.113.6:443 — timed out — loss 100%"
        );
        assert_eq!(
            diagnostic_line(&failed("203.0.113.7", 443, "tls_failed")),
            "203.0.113.7:443 — TLS handshake failed — loss 100%"
        );
        assert_eq!(
            diagnostic_line(&failed("203.0.113.8", 8443, "http_status")),
            "203.0.113.8:8443 — unexpected HTTP status — loss 100%"
        );
    }

    #[test]
    fn diagnostic_lines_cover_passing_rows() {
        assert_eq!(
            diagnostic_line(&passing("203.0.113.1", 443, None)),
            "203.0.113.1:443 — ok, 12ms — US/LAX — tunnel ok (40ms)"
        );
        let mut clean = passing("203.0.113.2", 443, None);
        clean.loss_pct = Some(0);
        clean.country = None;
        clean.colo = None;
        clean.phase2 = None;
        assert_eq!(diagnostic_line(&clean), "203.0.113.2:443 — ok, 12ms");
        let mut v6 = passing("2606:4700::1", 443, None);
        v6.phase2 = None;
        v6.country = None;
        v6.colo = None;
        v6.loss_pct = None;
        assert_eq!(diagnostic_line(&v6), "[2606:4700::1]:443 — ok, 12ms");
    }

    #[test]
    fn render_results_csv_carries_asn_isp_columns() {
        let mut v = passing("1.2.3.4", 443, None);
        v.asn = Some(13335);
        v.isp = Some("CLOUDFLARENET".to_owned());
        let out = render_results("csv", &[v]).unwrap();
        let row: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
        assert_eq!(row[12], "13335", "asn column: {out}");
        assert_eq!(row[13], "CLOUDFLARENET", "isp column: {out}");
        let plain = passing("5.6.7.8", 443, None);
        let out = render_results("csv", &[plain]).unwrap();
        let row: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
        assert_eq!(row[12], "", "unenriched endpoints leave asn empty: {out}");
        assert_eq!(row[13], "", "unenriched endpoints leave isp empty: {out}");
    }

    #[test]
    fn diagnostic_line_shows_asn_when_enriched() {
        let mut v = passing("1.2.3.4", 443, None);
        v.asn = Some(13335);
        v.isp = Some("CLOUDFLARENET".to_owned());
        assert_eq!(
            diagnostic_line(&v),
            "1.2.3.4:443 — ok, 12ms — US/LAX — AS13335 CLOUDFLARENET — tunnel ok (40ms)"
        );
    }

    #[test]
    fn atomic_write_round_trips_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!(
            "cf-scanner-export-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("results.csv");
        atomic_write_file(&dest, b"a,b\n1,2\n").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"a,b\n1,2\n");
        atomic_write_file(&dest, b"overwrite\n").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"overwrite\n");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "no tmp files must remain");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remark_for_prefers_colo_then_country_then_placeholder() {
        let mut v = passing("1.2.3.4", 443, Some(0));
        assert_eq!(remark_for(&v).as_deref(), Some("CF-LAX-40ms"));
        v.colo = None; // fall back to country
        assert_eq!(remark_for(&v).as_deref(), Some("CF-US-40ms"));
        v.country = None; // then the "CF" placeholder (place slot, so CF-CF)
        assert_eq!(remark_for(&v).as_deref(), Some("CF-CF-40ms"));
        v.phase2.as_mut().unwrap().latency_ms = None;
        v.latency_ms = None;
        assert_eq!(remark_for(&v).as_deref(), Some("CF-CF"));
        // A failed phase-2 never gets a remark.
        v.phase2.as_mut().unwrap().passed = false;
        assert_eq!(remark_for(&v), None);
        // No phase-2 at all: no remark.
        v.phase2 = None;
        assert_eq!(remark_for(&v), None);
    }

    #[test]
    fn unique_tag_appends_dedup_suffixes_in_insertion_order() {
        let mut seen = std::collections::HashMap::new();
        assert_eq!(unique_tag("CF-LAX".to_owned(), &mut seen), "CF-LAX");
        assert_eq!(unique_tag("CF-LAX".to_owned(), &mut seen), "CF-LAX-2");
        assert_eq!(unique_tag("CF-LAX".to_owned(), &mut seen), "CF-LAX-3");
        assert_eq!(unique_tag("CF-NRT".to_owned(), &mut seen), "CF-NRT");
        assert_eq!(unique_tag("CF-LAX".to_owned(), &mut seen), "CF-LAX-4");
    }

    #[tokio::test]
    async fn write_export_writes_csv_and_json_files_atomically() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![passing("1.2.3.4", 443, Some(0))]);
        let dir = std::env::temp_dir().join(format!("cf-scanner-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let csv_path = dir.join("out.csv");
        write_export(&c, &csv_path, ExportFormatArg::Csv).unwrap();
        let csv = std::fs::read_to_string(&csv_path).unwrap();
        assert!(csv.starts_with("ip,port,latency_ms,"), "{csv}");
        assert!(csv.contains("1.2.3.4,443"), "{csv}");
        assert!(!dir.join("out.csv.tmp-0-0").exists(), "tmp file cleaned");

        let json_path = dir.join("out.json");
        write_export(&c, &json_path, ExportFormatArg::Json).unwrap();
        let json = std::fs::read_to_string(&json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["results"][0]["ip"], "1.2.3.4");

        // Overwrite replaces the file cleanly.
        write_export(&c, &csv_path, ExportFormatArg::Csv).unwrap();
        let tmps: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(tmps.is_empty(), "no tmp leftovers: {tmps:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_export_fails_loudly_on_an_unwritable_target() {
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        crate::engine::store_seed(&c, vec![passing("1.2.3.4", 443, Some(0))]);
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-export-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A directory where the file should be: atomic write must fail.
        let err = write_export(&c, &dir, ExportFormatArg::Csv).unwrap_err();
        assert!(err.to_string().contains("could not write"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
    fn golden_uris() -> Vec<String> {
        vec![
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=front.example.com&fp=chrome&type=ws&path=/ws&host=front.example.com#tag-a".to_owned(),
            vmess_uri(),
            "trojan://SecretPass123@5.6.7.8:443?security=tls#tag-t".to_owned(),
            "ss://YWVzLTEyOC1nY206cGFzcw==@9.9.9.9:8388#tag-ss".to_owned(),
        ]
    }

    #[test]
    fn v2ray_golden_covers_all_protocols_and_transports() {
        let body = v2ray_body(&golden_uris());
        let entries: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 4);
        let vless = &entries[0];
        assert_eq!(vless["add"], "1.2.3.4");
        assert_eq!(vless["port"], "443");
        assert_eq!(vless["net"], "ws");
        assert_eq!(vless["tls"], "tls");
        assert_eq!(vless["sni"], "front.example.com");
        assert_eq!(vless["host"], "front.example.com");
        assert_eq!(vless["ps"], "tag-a");
        let vmess = &entries[1];
        assert_eq!(vmess["aid"], "64");
        assert_eq!(vmess["scy"], "auto");
        assert_eq!(vmess["ps"], "tag-one");
        let trojan = &entries[2];
        assert_eq!(trojan["tls"], "tls");
        assert!(trojan.get("sni").is_none(), "no SNI in the URI, no sni key");
        assert_eq!(trojan["net"], "tcp");
        let ss = &entries[3];
        assert_eq!(ss["method"], "aes-128-gcm");
        // ss reuses the generic shape: user_id (the password) lands in "id".
        assert_eq!(ss["id"], "pass");
    }

    #[test]
    fn shadowrocket_golden_is_base64_uri_list() {
        let uris = golden_uris();
        let body = shadowrocket_body(&uris);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), uris.join("\n"));
    }

    #[test]
    fn quantumult_golden_renders_ss_trojan_lines_and_keeps_share_uris() {
        let body = quantumult_body(&golden_uris());
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(
            lines[0].starts_with("vless://"),
            "vless has no native QX line: {lines:?}"
        );
        assert!(lines[1].starts_with("vmess://"), "{lines:?}");
        assert!(lines[2].starts_with("trojan=5.6.7.8:443,"), "{lines:?}");
        assert!(lines[2].contains("password=SecretPass123"), "{lines:?}");
        assert!(lines[2].contains("tls=true"), "{lines:?}");
        assert!(
            lines[3].starts_with("shadowsocks=9.9.9.9:8388,"),
            "{lines:?}"
        );
        assert!(lines[3].contains("method=aes-128-gcm"), "{lines:?}");
        assert!(lines[3].contains("password=pass"), "{lines:?}");
    }

    #[test]
    fn singbox_and_clash_carry_grpc_mode_and_clash_enables_udp() {
        let grpc_uri = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?type=grpc&serviceName=svc&mode=multi#grpc-tag".to_owned();
        let sb: serde_json::Value =
            serde_json::from_str(&singbox_body(std::slice::from_ref(&grpc_uri))).unwrap();
        assert_eq!(sb["outbounds"][0]["transport"]["type"], "grpc");
        assert_eq!(sb["outbounds"][0]["transport"]["multi_mode"], true);
        let cl: serde_json::Value = serde_json::from_str(&clash_body(&[grpc_uri])).unwrap();
        assert_eq!(cl["proxies"][0]["grpc-opts"]["grpc-mode"], "multi");
        assert_eq!(cl["proxies"][0]["udp"], true);
    }

    #[test]
    fn clash_ws_opts_carry_packet_encoding() {
        let uri = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?type=ws&path=/ws&packetencoding=xudp#pe".to_owned();
        let cl: serde_json::Value = serde_json::from_str(&clash_body(&[uri])).unwrap();
        assert_eq!(cl["proxies"][0]["ws-opts"]["packet-encoding"], "xudp");
    }

    #[test]
    fn bundle_export_warns_to_stderr_on_v6_and_malformed_skips() {
        // v6 skipped: render_bundle returns an error only when NOTHING remains.
        let v6_only = vec![Verdict {
            ip: "2606:4700::1".parse().unwrap(),
            port: 443,
            latency_ms: Some(5),
            country: None,
            colo: None,
            phase2: Some(Phase2Verdict {
                passed: true,
                fragment: FragmentPreset::Off,
                sni: String::new(),
                latency_ms: Some(9),
                error: None,
                config_index: Some(0),
                verifier: None,
                speed_test_mbps: None,
            }),
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        }];
        let err =
            render_bundle("raw", &v6_only, &["vless://a@1.2.3.4:443".to_owned()]).unwrap_err();
        assert!(err.contains("IPv6"), "{err}");
        // Mixed: one v4 (exported) + one v6 (warned) → body keeps the v4 only.
        let mut mixed = v6_only;
        mixed.push(passing("1.2.3.4", 443, Some(0)));
        let body = render_bundle("raw", &mixed, &["vless://a@1.2.3.4:443".to_owned()]).unwrap();
        assert!(body.contains("1.2.3.4"), "{body}");
        // Malformed skip: config_index pointing out of range is counted.
        let mut bad = passing("5.6.7.8", 443, Some(9));
        bad.ip = "5.6.7.8".parse().unwrap();
        let body = render_bundle("raw", &[bad], &["vless://a@1.2.3.4:443".to_owned()]).unwrap();
        assert_eq!(body, "", "out-of-range index yields no URI");
    }

    #[test]
    fn json_export_strips_internal_config_index() {
        let out = render_results("json", &[passing("1.2.3.4", 443, Some(7))]).unwrap();
        assert!(
            !out.contains("config_index"),
            "internal field must not leak into exports: {out}"
        );
        assert!(out.contains("\"passed\":true"), "{out}");
    }

    #[test]
    fn new_bundle_formats_resolve_and_reject_unknown() {
        for fmt in ["v2ray", "shadowrocket", "quantumult"] {
            assert!(render_bundle(fmt, &[], &[]).is_ok(), "{fmt} must resolve");
        }
        assert!(render_bundle("v2rayn", &[], &[]).is_err());
    }
    #[test]
    fn v6_endpoints_never_silently_enter_bundle_formats() {
        // T-36: the v6 half of the loud-drop decision. IPv6 verdicts never
        // produce URIs (export_config_uri dials v4); mixed sets keep only
        // the v4 rows, and nothing reaches the JSON bodies half-bracketed.
        let v6 = passing("2001:db8::1", 443, Some(0));
        let v4 = passing("1.2.3.4", 443, Some(0));
        let configs = [VLESS.to_owned()];
        for fmt in ["singbox", "clash", "v2ray"] {
            let body = render_bundle(fmt, &[v4.clone(), v6.clone()], &configs).unwrap();
            // v2ray is a bare array; singbox/clash wrap the list in a key.
            let (arr, addr_key) = match fmt {
                "clash" => (
                    serde_json::from_str::<serde_json::Value>(&body).unwrap()["proxies"].take(),
                    "server",
                ),
                "singbox" => (
                    serde_json::from_str::<serde_json::Value>(&body).unwrap()["outbounds"].take(),
                    "server",
                ),
                _ => (
                    serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                    "add",
                ),
            };
            let arr = arr.as_array().unwrap();
            assert_eq!(arr.len(), 1, "{fmt}: only the v4 endpoint exports");
            assert_eq!(arr[0][addr_key].as_str().unwrap(), "1.2.3.4", "{fmt}");
        }
    }
}
