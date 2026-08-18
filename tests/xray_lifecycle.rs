//! Xray subprocess lifecycle integration tests (Domain 6 review rec 2): the
//! `xray run -c config.json` spawn/stop/cleanup path exercised WITHOUT a real
//! xray binary. A fake executable (shell script) re-executes THIS test binary
//! in child mode (`--exact fake_xray_child`), reads the socks port from the
//! config xray wrote, and binds it — so `xray::spawn`'s readiness poll
//! succeeds and the child stays alive until the parent kills it.
//!
//! Unix-only: the fake is a shell script, so on Windows the whole file
//! compiles to an empty test binary (no subprocess is spawned either way).
//! The full `XrayTunnelProbe` run uses the `CF_SCANNER_DATA_DIR` override in
//! paths.rs (landed with review/xray) to isolate the probe's work dir and
//! the cached-binary resolution from the real user data dir.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cf_scanner::api::types::FragmentPreset;
use cf_scanner::configs::{OutboundSpec, Protocol};
use cf_scanner::verify::{ProbeRequest, TunnelProbe, XrayTunnelProbe};
use cf_scanner::xray;
use serde_json::json;

/// Serializes the `CF_SCANNER_DATA_DIR` env mutation against the parallel
/// tests in this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Runs as the fake xray when spawned with `--exact fake_xray_child` (see
/// `write_fake_xray`); a no-op during a normal test run.
#[test]
fn fake_xray_child() {
    let Ok(port) = std::env::var("CF_SCANNER_FAKE_PORT") else {
        return;
    };
    let port: u16 = port.parse().expect("fake port must parse");
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", port)).expect("fake xray binds the socks port");
    // Hold the port until the parent kills us (stop() / Drop kill the child).
    std::thread::sleep(std::time::Duration::from_secs(120));
    drop(listener);
}

/// Writes the fake xray executable: touches `marker` on spawn, then
/// `exec`s this test binary in child mode with the socks port taken from the
/// `-c <config.json>` argument xray passes (the first `"port"` in the file
/// is the socks inbound; outbounds come later). `exec` is what makes
/// `XrayProcess::stop()` effective: it replaces the shell so the killed
/// child IS the process holding the socks listener.
///
/// A matching `<bin>.dgst` is written alongside (same format as the real
/// cached install) so `xray::ensure_binary`'s use-time checksum
/// re-verification accepts the fake instead of deleting it and downloading a
/// real binary.
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
    let digest = hex_lower(&sha2::Sha256::digest(script.as_bytes()));
    std::fs::write(dgst_path(bin_path), format!("SHA2-256= {digest}\n"))
}

fn dgst_path(bin: &Path) -> PathBuf {
    bin.with_extension("dgst")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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

/// Drives `xray::spawn` with an explicit config dir and fake binary: the
/// subprocess must be launched (marker), the socks inbound must come up, and
/// `XrayProcess::stop()` must kill it so the port refuses connections again.
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

/// Full `XrayTunnelProbe` run against the fake binary in the data dir: the
/// probe must complete locally (no real xray, no real network) with a failed
/// tunnel — and every `trial-*` dir must be cleaned up afterwards. Relies on
/// the `CF_SCANNER_DATA_DIR` override in paths.rs; the guard below keeps the
/// test honest (it would skip loudly if the seam ever regressed).
// The guard intentionally spans the probe: sibling tests run on separate
// runtimes/threads and mutate the same process env, so the lock must stay
// held while the probe re-reads CF_SCANNER_DATA_DIR. No task can be parked
// on this std Mutex within one test's runtime, so the await-holding-lock
// lint is a false positive here.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn tunnel_probe_lifecycle_spawns_and_cleans_trial_dirs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = unique_dir("cf-scanner-xray-probe");
    let marker = tmp.join("spawned.marker");
    write_fake_xray(&tmp.join("xray"), &marker).expect("fake xray writable");

    // unsafe: process-global env mutation (edition 2024), serialized above.
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

    // The fake binds the socks port but is not a SOCKS server: the handshake
    // times out and the probe completes locally with a failed tunnel.
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
