use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::api::types::MAX_ISP_CHARS;
use crate::engine::ScanController;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
const LOOKUP_CONCURRENCY: usize = 8;

pub struct AsnInfo {
    pub asn: u32,
    pub isp: String,
}

fn ipwho_url(ip: IpAddr) -> String {
    format!("https://ipwho.is/{ip}")
}

pub fn parse_ipwho_response(body: &str) -> Option<AsnInfo> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v.get("success").and_then(|s| s.as_bool()) != Some(true) {
        return None;
    }
    let asn = v
        .pointer("/connection/asn")
        .and_then(|a| a.as_u64())
        .and_then(|a| u32::try_from(a).ok())?;
    if asn == 0 {
        return None;
    }
    let isp = v
        .pointer("/connection/isp")
        .and_then(|s| s.as_str())
        .unwrap_or_default();
    let mut isp = isp.to_owned();
    isp.truncate(MAX_ISP_CHARS);
    Some(AsnInfo { asn, isp })
}

async fn lookup(ip: IpAddr) -> Option<AsnInfo> {
    let body = crate::ranges::HTTP_CLIENT
        .get(ipwho_url(ip))
        .timeout(LOOKUP_TIMEOUT)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()?;
    parse_ipwho_response(&body)
}

/// Best-effort ASN/ISP annotation for every stored verdict with an IP.
/// Failures are silent by design: enrichment must never fail a scan.
pub async fn enrich_working(controller: &Arc<ScanController>) -> usize {
    let targets: Vec<(IpAddr, u16)> = controller
        .results()
        .into_iter()
        .map(|v| (v.ip, v.port))
        .collect();
    if targets.is_empty() {
        return 0;
    }
    let semaphore = Arc::new(tokio::sync::Semaphore::new(LOOKUP_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for (ip, _) in &targets {
        let ip = *ip;
        let permit = Arc::clone(&semaphore);
        set.spawn(async move {
            let _guard = permit.acquire_owned().await.ok()?;
            lookup(ip).await.map(|info| (ip, info))
        });
    }
    let mut enriched = 0;
    while let Some(res) = set.join_next().await {
        if let Ok(Some((ip, info))) = res {
            for (tip, tport) in &targets {
                if *tip == ip && controller.set_asn(*tip, *tport, info.asn, &info.isp) {
                    enriched += 1;
                }
            }
        }
    }
    enriched
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &str = r#"{"ip":"8.8.8.8","success":true,"type":"IPv4","connection":{"asn":15169,"org":"Google LLC","isp":"Google LLC","domain":"google.com"}}"#;

    #[test]
    fn parses_asn_and_isp_from_ipwho_shape() {
        let info = parse_ipwho_response(GOOGLE).expect("valid response must parse");
        assert_eq!(info.asn, 15169);
        assert_eq!(info.isp, "Google LLC");
    }

    #[test]
    fn rejects_unsuccessful_and_malformed_bodies() {
        assert!(parse_ipwho_response(r#"{"success":false,"message":"reserved range"}"#).is_none());
        assert!(parse_ipwho_response(r#"{"success":true}"#).is_none());
        assert!(
            parse_ipwho_response(r#"{"success":true,"connection":{"asn":0,"isp":"x"}}"#).is_none()
        );
        assert!(parse_ipwho_response("not json").is_none());
        assert!(parse_ipwho_response("").is_none());
    }

    #[test]
    fn missing_isp_defaults_empty_and_long_isp_truncates() {
        let no_isp = parse_ipwho_response(r#"{"success":true,"connection":{"asn":13335}}"#)
            .expect("missing isp must still parse");
        assert_eq!(no_isp.asn, 13335);
        assert!(no_isp.isp.is_empty());
        let long = format!(
            r#"{{"success":true,"connection":{{"asn":1,"isp":"{}"}}}}"#,
            "x".repeat(MAX_ISP_CHARS + 50)
        );
        let info = parse_ipwho_response(&long).expect("long isp must parse");
        assert_eq!(info.isp.len(), MAX_ISP_CHARS);
    }

    #[test]
    fn lookup_url_targets_the_queried_ip() {
        assert_eq!(
            ipwho_url("1.2.3.4".parse().unwrap()),
            "https://ipwho.is/1.2.3.4"
        );
        assert_eq!(
            ipwho_url("2606:4700::1".parse().unwrap()),
            "https://ipwho.is/2606:4700::1"
        );
    }
}
