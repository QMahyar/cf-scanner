#![cfg(unix)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cf_scanner::api::types::FragmentPreset;
use cf_scanner::configs::{OutboundSpec, Protocol};
use cf_scanner::verify::{ProbeRequest, TunnelProbe, XrayTunnelProbe};
use cf_scanner::xray;
use serde_json::json;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn fake_xray_child() {
    let Ok(port) = std::env::var("CF_SCANNER_FAKE_PORT") else {
        return;
    };
    let port: u16 = port.parse().expect("fake port must parse");
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", port)).expect("fake xray binds the socks port");
    std::thread::sleep(std::time::Duration::from_secs(120));
    drop(listener);
}

fn write_fake_xray(bin_path: &Path, marker: &Path) -> std::io::Result<()> {
    let child_bin = std::env::current_exe()?;
    let script = format!(
        r#"#!/bin/sh
: > "{marker}"
port=$(sed -n 's/.*"port": *\([0-9][0-9]*\).*/\1/p' "$3" | head -n1)
exec env CF_SCANNER_FAKE_PORT="$port" "{child}" --exact fake_xray_child --nocapture
"#,
        marker = marker.display(),
        child = child_bin.display(),
    );
    std::fs::write(bin_path, &script)?;
    let mut perm = std::fs::metadata(bin_path)?.permissions();
    use std::os::unix::fs::PermissionsExt as _;
    perm.set_mode(0o755);
    std::fs::set_permissions(bin_path, perm)?;

    use sha2::Digest as _;
    let digest = cf_scanner::dgst::hex_lower(&sha2::Sha256::digest(script.as_bytes()));
    std::fs::write(dgst_path(bin_path), format!("SHA2-256= {digest}\n"))
}

fn dgst_path(bin: &Path) -> PathBuf {
    bin.with_extension("dgst")
}

fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock sane")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir creatable");
    dir
}

fn pick_ephemeral_port() -> u16 {
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("ephemeral port bindable");
    listener.local_addr().expect("local addr").port()
}

#[tokio::test]
async fn spawn_launches_fake_xray_and_stop_kills_it() {
    let tmp = unique_dir("cf-scanner-xray-spawn");
    let marker = tmp.join("spawned.marker");
    let fake_bin = tmp.join("xray");
    write_fake_xray(&fake_bin, &marker).expect("fake xray writable");

    let port = pick_ephemeral_port();
    let cfg = json!({
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": false},
        }],
        "outbounds": [{"tag": "proxy", "protocol": "freedom", "settings": {}}],
    });

    let mut proc = xray::spawn(&tmp, &fake_bin, &cfg)
        .await
        .expect("spawn must succeed once the fake binds the socks port");
    assert!(
        marker.exists(),
        "the fake xray executable must have been spawned"
    );
    assert_eq!(proc.socks_addr, SocketAddr::from(([127, 0, 0, 1], port)));
    tokio::net::TcpStream::connect(proc.socks_addr)
        .await
        .expect("socks inbound must accept connections while the fake is up");

    proc.stop().await;
    assert!(
        tokio::net::TcpStream::connect(proc.socks_addr)
            .await
            .is_err(),
        "socks port must refuse connections after stop() kills the fake"
    );
    std::fs::remove_dir_all(&tmp).ok();
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn tunnel_probe_lifecycle_spawns_and_cleans_trial_dirs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = unique_dir("cf-scanner-xray-probe");
    let marker = tmp.join("spawned.marker");
    write_fake_xray(&tmp.join("xray"), &marker).expect("fake xray writable");

    unsafe {
        std::env::set_var("CF_SCANNER_DATA_DIR", &tmp);
    }
    let data_dir = cf_scanner::paths::data_dir().expect("data dir resolves");
    if !data_dir.starts_with(&tmp) {
        unsafe {
            std::env::remove_var("CF_SCANNER_DATA_DIR");
        }
        eprintln!(
            "CF_SCANNER_DATA_DIR is not honored by paths::data_dir() yet (lands with \
             review/xray); skipping the XrayTunnelProbe lifecycle check"
        );
        return;
    }

    let spec = OutboundSpec {
        protocol: Protocol::Vless,
        server: "104.17.160.217".to_owned(),
        port: 2096,
        user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000".to_owned(),
        method: None,
        security: "none".to_owned(),
        tls_server_name: None,
        fingerprint: None,
        ws: None,
        grpc: None,
        xhttp: None,
        tag: None,
        alter_id: 0,
        vmess_security: None,
    };
    let req = ProbeRequest {
        spec: &spec,
        dial_ip: "104.17.160.217".parse().expect("ip parses"),
        preset: &FragmentPreset::Off,
        custom: None,
        sni: None,
        probe_urls: &["http://127.0.0.1:1/".to_owned()],
        timeout_ms: 2_000,
    };
    let result = XrayTunnelProbe.probe(req).await;
    unsafe {
        std::env::remove_var("CF_SCANNER_DATA_DIR");
    }

    let result = result.expect("probe must complete without a local failure");
    assert!(!result.passed);
    assert!(marker.exists(), "the fake xray must have been spawned");

    let leftovers: Vec<String> = std::fs::read_dir(&tmp)
        .expect("data dir readable")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("trial-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "trial dirs must be cleaned: {leftovers:?}"
    );
    std::fs::remove_dir_all(&tmp).ok();
}
