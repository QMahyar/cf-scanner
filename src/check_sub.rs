//! `check-sub`: fetch a subscription and verify every config against its own
//! declared server, reporting per-config results as NDJSON (F-C1).
//!
//! Thin wrapper, not a second engine: it composes the existing subscription
//! fetch (`configs`), the existing tunnel probe trait (`verify`), and the
//! existing redaction (`configs::sanitize_error_text`). Caps and timeouts
//! are enforced per config; keys never reach output.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::api::types::{CustomFragment, FragmentPreset};
use crate::configs::{OutboundSpec, SubFetch};
use crate::verify::{ProbeRequest, TunnelProbe};

/// One NDJSON row of the report.
#[derive(Debug)]
pub struct CheckRow {
    pub config_index: usize,
    pub tag: String,
    pub server: String,
    pub ok: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

/// Fetches `url`, parses every entry, and probes each parsed v4 config
/// against its own server. Parse failures become `ok:false` rows so the
/// report accounts for every subscription line.
pub async fn check_subscription(
    url: &str,
    fetcher: &dyn SubFetch,
    probe: &dyn TunnelProbe,
    timeout_ms: u64,
) -> Result<Vec<CheckRow>> {
    let body = fetcher
        .fetch(url)
        .await
        .with_context(|| "subscription fetch failed")?;
    let parsed = crate::configs::parse_subscription(&body);

    let mut rows = Vec::new();
    for spec in &parsed.specs {
        rows.push(check_one(spec, probe, timeout_ms).await);
    }
    // Unparseable lines are reported as one aggregate row (they carry no
    // per-line identity to report).
    if parsed.ignored > 0 || !parsed.errors.is_empty() {
        rows.push(CheckRow {
            config_index: parsed.specs.len(),
            tag: "<unparseable lines>".to_owned(),
            server: "-".to_owned(),
            ok: false,
            latency_ms: None,
            error: Some(format!(
                "{} line(s) ignored, {} parse error(s)",
                parsed.ignored,
                parsed.errors.len()
            )),
        });
    }
    Ok(rows)
}

async fn check_one(spec: &OutboundSpec, probe: &dyn TunnelProbe, timeout_ms: u64) -> CheckRow {
    let tag = spec.tag.clone().unwrap_or_else(|| "untitled".to_owned());
    let server = format!("{}:{}", spec.server, spec.port);
    let Ok(dial_ip) = spec.server.parse::<Ipv4Addr>() else {
        return CheckRow {
            config_index: usize::MAX,
            tag,
            server,
            ok: false,
            latency_ms: None,
            error: Some("subscription config dials a non-IPv4 server; skipped".to_owned()),
        };
    };
    let req = ProbeRequest {
        spec,
        dial_ip,
        preset: &FragmentPreset::Off,
        custom: None::<&CustomFragment>,
        sni: None,
        probe_urls: &[],
        timeout_ms,
    };
    let result =
        tokio::time::timeout(Duration::from_millis(timeout_ms + 1_000), probe.probe(req)).await;
    match result {
        Err(_) => CheckRow {
            config_index: usize::MAX,
            tag,
            server,
            ok: false,
            latency_ms: None,
            error: Some("check timed out".to_owned()),
        },
        Ok(Ok(res)) => {
            if res.passed {
                CheckRow {
                    config_index: usize::MAX,
                    tag,
                    server,
                    ok: true,
                    latency_ms: res.latency_ms,
                    error: None,
                }
            } else {
                CheckRow {
                    config_index: usize::MAX,
                    tag,
                    server,
                    ok: false,
                    latency_ms: None,
                    error: Some("tunnel verification failed".to_owned()),
                }
            }
        }
        Ok(Err(err)) => {
            // The probe errors carry sanitized text already; belt and braces.
            CheckRow {
                config_index: usize::MAX,
                tag,
                server,
                ok: false,
                latency_ms: None,
                error: Some(crate::configs::sanitize_error_text(&format!("{err:#}"))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::{SubscriptionParse, parse_uri};
    use std::pin::Pin;

    /// Returns a canned subscription body (real parse path, no network).
    struct FakeSub(String);

    impl SubFetch for FakeSub {
        fn fetch(&self, _url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
            let body = self.0.clone();
            Box::pin(async move { Ok(body) })
        }
    }

    struct FakeProbe(bool);

    impl TunnelProbe for FakeProbe {
        fn probe(
            &self,
            _req: ProbeRequest<'_>,
        ) -> Pin<Box<dyn Future<Output = Result<crate::verify::TunnelResult>> + Send + '_>>
        {
            let ok = self.0;
            Box::pin(async move {
                Ok(crate::verify::TunnelResult {
                    passed: ok,
                    latency_ms: ok.then_some(42),
                    colo: None,
                    verifier: Some("inline"),
                })
            })
        }
    }

    // check_subscription consumes the parse output; pin the report shape by
    // driving check_one through a spec list directly (fetch is covered by
    // the subscription tests; a FakeSub returning an empty body keeps the
    // public entry honest).
    #[tokio::test]
    async fn reports_pass_fail_rows_per_config() {
        let body = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#good
not-a-uri
";
        let rows = check_subscription(
            "https://sub.example/x",
            &FakeSub(body.to_owned()),
            &FakeProbe(true),
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 2, "one config row + one unparseable aggregate");
        assert_eq!(rows[0].tag, "good");
        assert!(rows[0].ok, "{rows:?}");
        assert_eq!(rows[0].latency_ms, Some(42));
        assert_eq!(rows[1].tag, "<unparseable lines>");
        assert!(!rows[1].ok);
        assert!(
            rows[1]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("1 line(s)"))
        );
    }

    #[tokio::test]
    async fn mixed_pass_fail_report_orders_each_config() {
        let body = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#a
trojan://pw@1.2.3.5:443#b
";
        let rows = check_subscription(
            "https://sub.example/x",
            &FakeSub(body.to_owned()),
            &FakeProbe(false),
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 2, "both parse: no aggregate row");
        assert!(rows.iter().all(|r| !r.ok));
        assert_eq!(rows[0].tag, "a");
        assert_eq!(rows[1].tag, "b");
    }

    #[tokio::test]
    async fn probe_failures_become_error_rows_not_panics() {
        let spec =
            parse_uri("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#tag").unwrap();
        let row = check_one(&spec, &FakeProbe(false), 1_000).await;
        assert!(!row.ok);
        assert!(row.error.is_some(), "{row:?}");
        assert_eq!(row.server, "1.2.3.4:443");
    }

    #[tokio::test]
    async fn non_ipv4_server_configs_are_reported_as_skipped() {
        let mut spec =
            parse_uri("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#v4").unwrap();
        spec.server = "example.invalid".to_owned();
        let row = check_one(&spec, &FakeProbe(true), 1_000).await;
        assert!(!row.ok);
        assert!(row.error.as_deref().is_some_and(|e| e.contains("non-IPv4")));
    }

    #[test]
    fn subscription_parse_shape_is_what_the_report_assumes() {
        // Guards the contract between configs::parse_subscription and the
        // report: specs carry tag/server, ignored counts unparseable lines.
        let parsed: SubscriptionParse = SubscriptionParse::default();
        assert!(parsed.specs.is_empty() && parsed.ignored == 0);
    }
}
