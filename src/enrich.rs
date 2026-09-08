use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::api::types::MAX_ISP_CHARS;
use crate::engine::ScanController;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
const LOOKUP_CONCURRENCY: usize = 8;

#[derive(Clone, Debug)]
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

/// Injectable fetch seam so enrichment is unit-testable offline.
use std::pin::Pin;
pub trait AsnFetch: Send + Sync {
    fn fetch(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Option<AsnInfo>> + Send + '_>>;
}

pub struct RealAsnFetch;

impl AsnFetch for RealAsnFetch {
    fn fetch(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Option<AsnInfo>> + Send + '_>> {
        Box::pin(async move { lookup(ip).await })
    }
}

/// Best-effort ASN/ISP annotation for every stored verdict with an IP.
/// Failures are silent by design: enrichment must never fail a scan.
pub async fn enrich_working(controller: &Arc<ScanController>) -> usize {
    enrich_working_with(Arc::new(RealAsnFetch), controller).await
}

pub async fn enrich_working_with(
    fetch: Arc<dyn AsnFetch>,
    controller: &Arc<ScanController>,
) -> usize {
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
    // One lookup per distinct IP; every port of that IP gets annotated.
    let mut distinct: Vec<IpAddr> = targets.iter().map(|(ip, _)| *ip).collect();
    distinct.sort();
    distinct.dedup();
    for ip in distinct {
        let permit = Arc::clone(&semaphore);
        set.spawn({
            let fetch = Arc::clone(&fetch);
            async move {
                let _guard = permit.acquire_owned().await.ok()?;
                fetch.fetch(ip).await.map(|info| (ip, info))
            }
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

    fn seeded_controller(ips: &[&str]) -> Arc<ScanController> {
        use crate::api::types::Verdict;
        let c = Arc::new(ScanController::new(Arc::new(
            crate::probe::FakeTransport::new(),
        )));
        let batch: Vec<Verdict> = ips
            .iter()
            .map(|s| Verdict {
                ip: s.parse().unwrap(),
                port: 443,
                latency_ms: Some(5),
                country: None,
                colo: None,
                phase2: None,
                sent: 1,
                received: 1,
                loss_pct: Some(0),
                fail_reason: None,
                asn: None,
                isp: None,
            })
            .collect();
        crate::engine::store_seed(&c, batch);
        c
    }

    struct ScriptedFetch(Vec<(IpAddr, Option<AsnInfo>)>);

    impl AsnFetch for ScriptedFetch {
        fn fetch(&self, ip: IpAddr) -> Pin<Box<dyn Future<Output = Option<AsnInfo>> + Send + '_>> {
            let hit = self
                .0
                .iter()
                .find(|(target, _)| *target == ip)
                .and_then(|(_, info)| info.clone());
            Box::pin(async move { hit })
        }
    }

    fn scripted(entries: Vec<(&str, Option<AsnInfo>)>) -> Arc<dyn AsnFetch> {
        Arc::new(ScriptedFetch(
            entries
                .into_iter()
                .map(|(ip, info)| (ip.parse::<IpAddr>().unwrap(), info))
                .collect(),
        ))
    }

    fn info(asn: u32) -> Option<AsnInfo> {
        Some(AsnInfo {
            asn,
            isp: "CLOUDFLARENET".to_owned(),
        })
    }

    #[tokio::test]
    async fn enrich_empty_results_is_a_no_op() {
        let c = seeded_controller(&[]);
        assert_eq!(enrich_working_with(scripted(vec![]), &c).await, 0);
    }

    #[tokio::test]
    async fn enrich_counts_only_successful_lookups_and_annotates_the_verdict() {
        let c = seeded_controller(&["1.1.1.1", "8.8.8.8"]);
        let fetch = scripted(vec![
            ("1.1.1.1", info(13335)),
            // 8.8.8.8 lookup fails (timeout/429/500 are all None upstream).
            ("8.8.8.8", None),
        ]);
        assert_eq!(enrich_working_with(fetch, &c).await, 1);
        let results = c.results();
        let cf = results
            .iter()
            .find(|v| v.ip == "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(cf.unwrap().asn, Some(13335));
        assert_eq!(cf.unwrap().isp.as_deref(), Some("CLOUDFLARENET"));
        let g = results
            .iter()
            .find(|v| v.ip == "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(
            g.unwrap().asn,
            None,
            "failed lookup leaves the verdict bare"
        );
    }

    #[tokio::test]
    async fn enrich_annotates_every_port_of_the_same_ip() {
        use crate::api::types::Verdict;
        let c = seeded_controller(&["1.1.1.1"]);
        // A second port for the same IP: enrichment applies to all of them.
        let second = Verdict {
            ip: "1.1.1.1".parse().unwrap(),
            port: 8443,
            latency_ms: Some(9),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        crate::engine::store_seed(&c, vec![second]);
        let fetch = scripted(vec![("1.1.1.1", info(13335))]);
        assert_eq!(enrich_working_with(fetch, &c).await, 2);
        assert!(c.results().iter().all(|v| v.asn == Some(13335)));
    }

    #[tokio::test]
    async fn enrich_all_lookups_fail_is_silent_zero() {
        let c = seeded_controller(&["1.1.1.1", "8.8.8.8"]);
        assert_eq!(enrich_working_with(scripted(vec![]), &c).await, 0);
        assert!(c.results().iter().all(|v| v.asn.is_none()));
    }
}
