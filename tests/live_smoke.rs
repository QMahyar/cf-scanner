//! Live smoke tests, opt-in only: `cargo test --test live_smoke -- --ignored`.
//! They hit real endpoints; credentials come from the environment (never
//! committed).

use cf_scanner::configs::{RealSubFetch, fetch_subscription, parse_uri};
use cf_scanner::configs::Protocol;

/// Mirrors the provider install `main()` performs; the test binary has no
/// main of its own.
fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
#[ignore = "hits the user's subscription endpoint; needs CFSCANNER_SUB_URL"]
async fn subscription_endpoint_returns_parseable_configs() {
    install_crypto();
    let url = std::env::var("CFSCANNER_SUB_URL").expect("CFSCANNER_SUB_URL not set");
    let parsed = fetch_subscription(&RealSubFetch, &url)
        .await
        .expect("subscription fetch failed");
    assert!(
        !parsed.specs.is_empty(),
        "subscription returned no parseable configs (ignored {})",
        parsed.ignored
    );
    for spec in &parsed.specs {
        assert!(spec.port > 0);
        assert!(!spec.server.is_empty());
    }
}

#[test]
#[ignore = "network; validates against the live Cloudflare IP"]
fn vless_fixture_dials_its_own_server() {
    // Parsing is covered by unit tests; this just asserts the fixture is a
    // well-formed URI for the known worker (no dialing happens here).
    let fixture = include_str!("fixtures/vless-worker.txt");
    let spec = parse_uri(fixture).expect("fixture must parse");
    assert_eq!(spec.protocol, Protocol::Vless);
}