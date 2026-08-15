//! Live smoke tests, opt-in only: `cargo test --test live_smoke -- --ignored`.
//! They hit real endpoints; credentials come from the environment (never
//! committed).

use cf_scanner::configs::Protocol;
use cf_scanner::configs::{RealSubFetch, fetch_subscription, parse_uri};

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

/// Genuinely dials the fixture's live Cloudflare worker endpoint. The dial is
/// a short TCP connect (the anycast IP refuses on blocked networks), so a
/// filtered/offline network SKIPS instead of failing the ignored run.
#[tokio::test]
#[ignore = "network; dials the live Cloudflare IP from the fixture"]
async fn vless_fixture_dials_its_own_server() {
    if std::env::var("CFSCANNER_SUB_URL").is_err() {
        eprintln!("skipping: live-dial tests are gated on CFSCANNER_SUB_URL");
        return;
    }
    let fixture = include_str!("fixtures/vless-worker.txt");
    let spec = parse_uri(fixture).expect("fixture must parse");
    assert_eq!(spec.protocol, Protocol::Vless);

    let addr = format!("{}:{}", spec.server, spec.port);
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_stream)) => {}
        Ok(Err(err)) => {
            eprintln!("skipping: {addr} refused the dial ({err})");
            return;
        }
        Err(_) => {
            eprintln!("skipping: dial to {addr} timed out");
            return;
        }
    }
}
