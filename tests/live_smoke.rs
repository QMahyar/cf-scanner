use cf_scanner::configs::Protocol;
use cf_scanner::configs::{RealSubFetch, fetch_subscription, parse_uri};

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
#[ignore = "network; hits the user's subscription endpoint; needs CFSCANNER_SUB_URL"]
async fn subscription_endpoint_returns_parseable_configs() {
    if std::env::var("CFSCANNER_SUB_URL").is_err() {
        eprintln!("skipping: subscription tests are gated on CFSCANNER_SUB_URL");
        return;
    }
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
        Ok(Err(err)) => panic!("{addr} refused the dial ({err})"),
        Err(_) => panic!("dial to {addr} timed out"),
    }
}
