#![cfg(windows)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cf_scanner::api::types::FragmentPreset;
use cf_scanner::configs::{OutboundSpec, Protocol};
use cf_scanner::verify::{ProbeRequest, TunnelProbe, XrayTunnelProbe};
use cf_scanner::xray;
use serde_json::json;

static ENV_LOCK: Mutex<()> = Mutex::new(());

const FAKE_SRC: &str = r##"
fn main() {
    if let Ok(m) = std::env::var("FAKE_MARKER") {
        let _ = std::fs::write(m, b"spawned");
    }
    let args: Vec<String> = std::env::args().collect();
    let cfg = args
        .iter()
        .position(|a| a == "-c")
        .and_then(|i| args.get(i + 1))
        .expect("xray-fake: -c <config.json> required");
    let text = std::fs::read_to_string(cfg).expect("xray-fake: read config");
    // First numeric run following the `port` key's colon = socks inbound.
    let port: u16 = text
        .split("port")
        .nth(1)
        .and_then(|rest| rest.split(':').nth(1))
        .map(|v| {
            v.trim()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
        .expect("xray-fake: no inbound port in config");
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .expect("xray-fake: bind socks port");
    eprintln!("xray-fake listening on {port}");
    // Hold the port until the parent kills us (stop()/Drop kill the child).
    std::thread::sleep(std::time::Duration::from_secs(120));
    drop(listener);
}
"##;

fn write_fake_xray(bin_path: &Path, marker_env_key: &str) -> std::io::Result<()> {
    let src = tmp_sibling(bin_path, "fake_xray_src.rs");
    std::fs::write(&src, FAKE_SRC)?;
    let status = std::process::Command::new("rustc")
        .arg("--edition")
        .arg("2021")
        .arg("-Cdebuginfo=0")
        .arg("-o")
        .arg(bin_path)
        .arg(&src)
        .status()?;
    assert!(status.success(), "rustc must compile the fake xray");

    use sha2::Digest as _;
    let bytes = std::fs::read(bin_path)?;
    let digest = cf_scanner::dgst::hex_lower(&sha2::Sha256::digest(&bytes));
    std::fs::write(dgst_path(bin_path), format!("SHA2-256= {digest}\n"))?;
    unsafe {
        std::env::set_var(marker_env_key, marker_for(bin_path));
    }
    Ok(())
}

fn marker_for(bin: &Path) -> PathBuf {
    tmp_sibling(bin, "spawned.marker")
}

fn tmp_sibling(bin: &Path, name: &str) -> PathBuf {
    bin.parent().unwrap().join(name)
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
#[allow(clippy::await_holding_lock)]
async fn spawn_launches_fake_xray_and_stop_kills_it() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = unique_dir("cf-scanner-xray-spawn-win");
    let marker = tmp.join("spawned.marker");
    let fake_bin = tmp.join(if cfg!(windows) { "xray.exe" } else { "xray" });
    write_fake_xray(&fake_bin, "FAKE_MARKER").expect("fake xray writable");

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
    assert!(marker.exists(), "the fake xray must have been spawned");
    assert_eq!(proc.socks_addr, SocketAddr::from(([127, 0, 0, 1], port)));
    tokio::net::TcpStream::connect(proc.socks_addr)
        .await
        .expect("socks inbound must accept connections while the fake is up");

    proc.stop().await;
    let mut refused = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(proc.socks_addr)
            .await
            .is_err()
        {
            refused = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(refused, "socks port must refuse connections after stop()");
    std::fs::remove_dir_all(&tmp).ok();
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn tunnel_probe_lifecycle_spawns_and_cleans_trial_dirs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = unique_dir("cf-scanner-xray-probe-win");
    let marker = tmp.join("spawned.marker");
    write_fake_xray(&tmp.join("xray.exe"), "FAKE_MARKER").expect("fake xray writable");

    unsafe {
        std::env::set_var("CF_SCANNER_DATA_DIR", &tmp);
    }
    let data_dir = cf_scanner::paths::data_dir().expect("data dir resolves");
    assert!(
        data_dir.starts_with(&tmp),
        "CF_SCANNER_DATA_DIR must be honored by paths::data_dir()"
    );

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
        std::env::remove_var("FAKE_MARKER");
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
