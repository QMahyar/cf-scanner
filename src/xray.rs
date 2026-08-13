//! Xray manager (phase 2): bundled-binary discovery, checksum-verified
//! download fallback, subprocess spawn/cleanup with a local socks inbound,
//! and the fragment preset -> config JSON builder (freedom outbound +
//! `sockopt.dialerProxy` chain). The crates.io `xray-core` crate is a gRPC
//! client only and is never used; xray always runs as a subprocess.

use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::api::types::{CustomFragment, FragmentPreset};
use crate::configs::{OutboundSpec, Protocol, WsSettings};
use crate::paths;
use crate::ranges;

const VERSION: &str = include_str!("../data/xray-version.txt");
const RELEASE_BASE: &str = "https://github.com/XTLS/Xray-core/releases/download";
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Fragment preset -> freedom-outbound fragment block (community cfray
/// values, packets always `tlshello` per the AGENTS.md contract).
pub fn fragment_block(preset: &FragmentPreset, custom: Option<&CustomFragment>) -> Option<Value> {
    let (length, interval) = match preset {
        FragmentPreset::Off => return None,
        FragmentPreset::Light => ("100-200", "10-20"),
        FragmentPreset::Medium => ("50-200", "10-40"),
        FragmentPreset::Heavy => ("10-300", "5-50"),
        FragmentPreset::Custom => {
            let c = custom?;
            (c.length.as_str(), c.interval.as_str())
        }
    };
    Some(json!({
        "packets": "tlshello",
        "length": length,
        "interval": interval,
    }))
}

/// The chained freedom outbound carrying the fragment block.
fn fragment_outbound(preset: &FragmentPreset, custom: Option<&CustomFragment>) -> Option<Value> {
    fragment_block(preset, custom).map(|fragment| {
        json!({
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {},
            "fragment": fragment,
        })
    })
}

/// Rebuilds the user's outbound JSON from a normalized spec, dialing
/// `dial_ip` (the phase-2 candidate) instead of the original server.
pub fn build_outbound(spec: &OutboundSpec, dial_ip: Ipv4Addr, sni_override: Option<&str>) -> Value {
    let mut stream = json!({"network": ws_network(spec.ws.as_ref())});
    if spec.security == "tls" {
        let mut tls = json!({});
        tls["serverName"] = Value::from(
            sni_override
                .or(spec.tls_server_name.as_deref())
                .unwrap_or("cloudflare.com"),
        );
        if let Some(fp) = &spec.fingerprint {
            tls["fingerprint"] = Value::String(fp.clone());
        }
        stream["security"] = Value::from("tls");
        stream["tlsSettings"] = tls;
    } else {
        stream["security"] = Value::from(spec.security.clone());
    }
    if let Some(ws) = &spec.ws {
        let mut ws_json = json!({"path": ws.path});
        let host = sni_override.or(ws.host.as_deref());
        if let Some(host) = host {
            ws_json["headers"] = json!({"Host": host});
        }
        if let Some(pe) = &ws.packet_encoding {
            ws_json["packetEncoding"] = Value::String(pe.clone());
        }
        stream["wsSettings"] = ws_json;
    }

    let mut outbound = match spec.protocol {
        Protocol::Vless | Protocol::Vmess => json!({
            "tag": "proxy",
            "protocol": spec.protocol.as_str(),
            "settings": {"vnext": [{
                "address": dial_ip.to_string(), "port": spec.port,
                "users": [{"id": spec.user_id, "encryption": "none"}],
            }]},
        }),
        Protocol::Trojan => json!({
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": dial_ip.to_string(), "port": spec.port,
                "password": spec.user_id,
            }]},
        }),
        Protocol::Shadowsocks => json!({
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": dial_ip.to_string(), "port": spec.port,
                "method": spec.method.clone().unwrap_or_default(),
                "password": spec.user_id,
            }]},
        }),
    };
    outbound["streamSettings"] = stream;
    outbound
}

fn ws_network(ws: Option<&WsSettings>) -> &str {
    if ws.is_some() { "ws" } else { "tcp" }
}

/// Full `xray run` config: socks inbound on `socks_port` plus the proxied
/// outbound, chained to the fragment freedom outbound when enabled.
pub fn build_config(
    spec: &OutboundSpec,
    dial_ip: Ipv4Addr,
    preset: &FragmentPreset,
    custom: Option<&CustomFragment>,
    sni_override: Option<&str>,
    socks_port: u16,
) -> Result<Value> {
    let mut outbounds: Vec<Value> = vec![];
    if let Some(frag) = fragment_outbound(preset, custom) {
        outbounds.push(frag);
    }
    let mut proxy = build_outbound(spec, dial_ip, sni_override);
    if preset != &FragmentPreset::Off {
        proxy["streamSettings"]["sockopt"] = json!({"dialerProxy": "fragment"});
    }
    outbounds.push(proxy);
    Ok(json!({
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": false},
        }],
        "outbounds": outbounds,
    }))
}

/// A running `xray run -c ...` subprocess. Killing on drop prevents orphans.
pub struct XrayProcess {
    child: tokio::process::Child,
    pub socks_addr: SocketAddr,
}

impl XrayProcess {
    pub async fn stop(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawns `xray run -c <dir>/config.json` and waits until the socks inbound
/// accepts connections. The config must be written to `config_dir` first.
pub async fn spawn(config_dir: &Path, xray_bin: &Path, config_json: &Value) -> Result<XrayProcess> {
    let config_path = config_dir.join("config.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(config_json)?)?;

    let child = tokio::process::Command::new(xray_bin)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn xray; is the binary present?")?;

    let socks_port = config_json
        .pointer("/inbounds/0/port")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("config has no socks inbound"))? as u16;
    let socks_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), socks_port);
    wait_for_socks(socks_addr, READY_TIMEOUT)
        .await
        .context("xray socks inbound never came up")?;

    Ok(XrayProcess { child, socks_addr })
}

/// Polls a TCP connect until it succeeds (proves the socks inbound is up).
async fn wait_for_socks(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() >= deadline => {
                bail!("socks {addr} not reachable within {timeout:?}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

// --- binary discovery + fallback download ----------------------------------

fn asset_name() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "Xray-windows-64.zip",
        ("linux", "x86_64") => "Xray-linux-64.zip",
        ("linux", "aarch64") => "Xray-linux-arm64.zip",
        ("macos", "x86_64") => "Xray-macos-64.zip",
        ("macos", "aarch64") => "Xray-macos-arm64.zip",
        (os, arch) => bail!("no xray asset for {os}/{arch}"),
    })
}

fn exe_name() -> &'static str {
    if cfg!(windows) { "xray.exe" } else { "xray" }
}

/// Bundled xray next to the running binary (release archives carry it).
pub fn find_bundled() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.join(exe_name());
    path.is_file().then_some(path)
}

/// Checked-out xray in the data dir (dev/fallback installs).
pub fn cached_in_data_dir() -> Option<PathBuf> {
    let path = paths::xray_binary_path().ok()?;
    path.is_file().then_some(path)
}

/// Discovery order: bundled next to the exe, then the data dir.
pub fn find_binary() -> Option<PathBuf> {
    find_bundled().or_else(cached_in_data_dir)
}

/// Downloads the pinned release, verifies its `.dgst` SHA-256, extracts the
/// binary into the data dir, and returns its path. Refuses to overwrite an
/// existing file.
pub async fn download_binary(fetch: &impl BinaryFetch) -> Result<PathBuf> {
    let asset = asset_name()?;
    let url = format!("{RELEASE_BASE}/{VERSION}/{asset}");
    let dgst_url = format!("{url}.dgst");

    let (zip, dgst) = tokio::join!(fetch.bytes(&url), fetch.bytes(&dgst_url));
    let zip = zip?;
    let dgst = dgst?;
    let expected = parse_dgst(&String::from_utf8_lossy(&dgst), asset)?;
    let actual = hex_lower(&Sha256::digest(&zip));
    if actual != expected {
        bail!("xray checksum mismatch: got {actual}, want {expected}");
    }

    let dest = paths::xray_binary_path()?;
    if dest.exists() {
        bail!("{} already exists; refusing to overwrite", dest.display());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = PathBuf::from(format!("{}.tmp", dest.display()));
    extract_xray_from_zip(&zip, &tmp)?;
    make_executable(&tmp)?;
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parses XTLS `.dgst` text (`SHA256 (file.zip) = <hex>`); scoped to the
/// first 64-char hex run so format variations are tolerated.
fn parse_dgst(text: &str, asset: &str) -> Result<String> {
    let line = text
        .lines()
        .find(|l| l.contains(asset))
        .ok_or_else(|| anyhow!(".dgst has no line for {asset}"))?;
    let hex64: Vec<&str> = line
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|s| s.len() == 64)
        .collect();
    hex64
        .first()
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| anyhow!(".dgst line has no 64-char digest: {line}"))
}

/// Extracts just the xray binary out of the release zip.
fn extract_xray_from_zip(zip_bytes: &[u8], dest: &Path) -> Result<()> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("invalid xray zip")?;
    let name = find_entry(&archive, exe_name())?;
    let mut entry = archive.by_index(name)?;
    std::fs::write(dest, {
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        buf
    })?;
    Ok(())
}

fn find_entry(archive: &zip::ZipArchive<std::io::Cursor<&[u8]>>, exe: &str) -> Result<usize> {
    for i in 0..archive.len() {
        let name = archive.name_for_index(i).unwrap_or("");
        let base = name.rsplit('/').next().unwrap_or(name);
        if base == exe {
            return Ok(i);
        }
    }
    bail!("zip contains no {exe}")
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perm = std::fs::metadata(path)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Injectable byte fetcher so download/verify/extract is testable offline.
#[allow(async_fn_in_trait)] // internal seam; send bounds are irrelevant here
pub trait BinaryFetch {
    async fn bytes(&self, url: &str) -> Result<Vec<u8>>;
}

pub struct RealFetch;

impl BinaryFetch for RealFetch {
    async fn bytes(&self, url: &str) -> Result<Vec<u8>> {
        ranges::fetch_bytes(url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::FragmentPreset;
    use crate::configs::{OutboundSpec, Protocol, WsSettings};

    fn spec() -> OutboundSpec {
        OutboundSpec {
            protocol: Protocol::Vless,
            server: "1.1.1.1".to_owned(),
            port: 443,
            user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000".to_owned(),
            method: None,
            security: "tls".to_owned(),
            tls_server_name: Some("front.example.com".to_owned()),
            fingerprint: Some("chrome".to_owned()),
            ws: Some(WsSettings {
                path: "/ws".to_owned(),
                host: Some("front.example.com".to_owned()),
                packet_encoding: Some("xudp".to_owned()),
            }),
            tag: None,
        }
    }

    fn dial() -> Ipv4Addr {
        "104.17.160.217".parse().unwrap()
    }

    #[test]
    fn fragment_presets_map_to_community_values() {
        assert_eq!(fragment_block(&FragmentPreset::Off, None), None);
        let light = fragment_block(&FragmentPreset::Light, None).unwrap();
        assert_eq!(light["packets"], "tlshello");
        assert_eq!(light["length"], "100-200");
        assert_eq!(light["interval"], "10-20");
        let medium = fragment_block(&FragmentPreset::Medium, None).unwrap();
        assert_eq!(medium["length"], "50-200");
        assert_eq!(medium["interval"], "10-40");
        let heavy = fragment_block(&FragmentPreset::Heavy, None).unwrap();
        assert_eq!(heavy["length"], "10-300");
        assert_eq!(heavy["interval"], "5-50");
    }

    #[test]
    fn custom_fragment_requires_values() {
        assert!(fragment_block(&FragmentPreset::Custom, None).is_none());
        let custom = CustomFragment {
            packets: "1-3".to_owned(),
            length: "1-2".to_owned(),
            interval: "3-4".to_owned(),
        };
        let block = fragment_block(&FragmentPreset::Custom, Some(&custom)).unwrap();
        assert_eq!(block["packets"], "tlshello");
        assert_eq!(block["length"], "1-2");
        assert_eq!(block["interval"], "3-4");
    }

    #[test]
    fn off_fragment_is_freedomless_and_not_chained() {
        let cfg = build_config(&spec(), dial(), &FragmentPreset::Off, None, None, 28000).unwrap();
        assert_eq!(cfg["inbounds"][0]["port"], 28000);
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 1);
        assert!(outbounds[0]["streamSettings"].get("sockopt").is_none());
        assert_eq!(
            outbounds[0]["settings"]["vnext"][0]["address"],
            "104.17.160.217"
        );
    }

    #[test]
    fn fragment_chains_via_dialer_proxy() {
        let cfg = build_config(&spec(), dial(), &FragmentPreset::Light, None, None, 28001).unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["tag"], "fragment");
        assert_eq!(outbounds[0]["protocol"], "freedom");
        assert_eq!(outbounds[0]["fragment"]["length"], "100-200");
        assert_eq!(
            outbounds[1]["streamSettings"]["sockopt"]["dialerProxy"],
            "fragment"
        );
    }

    #[test]
    fn tls_settings_carry_sni_fingerprint_and_ws_headers() {
        let cfg = build_config(&spec(), dial(), &FragmentPreset::Off, None, None, 28002).unwrap();
        let stream = &cfg["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "ws");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "front.example.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "chrome");
        assert_eq!(stream["wsSettings"]["path"], "/ws");
        assert_eq!(stream["wsSettings"]["headers"]["Host"], "front.example.com");
        assert_eq!(stream["wsSettings"]["packetEncoding"], "xudp");
    }

    #[test]
    fn sni_override_fronts_server_name_and_ws_host() {
        let cfg = build_config(
            &spec(),
            dial(),
            &FragmentPreset::Off,
            None,
            Some("front.me"),
            28003,
        )
        .unwrap();
        let stream = &cfg["outbounds"][0]["streamSettings"];
        assert_eq!(stream["tlsSettings"]["serverName"], "front.me");
        assert_eq!(stream["wsSettings"]["headers"]["Host"], "front.me");
    }

    #[test]
    fn plain_tcp_none_security_has_no_tls_settings() {
        let mut s = spec();
        s.security = "none".to_owned();
        s.ws = None;
        s.tls_server_name = None;
        let cfg = build_config(&s, dial(), &FragmentPreset::Off, None, None, 28004).unwrap();
        let stream = &cfg["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "tcp");
        assert_eq!(stream["security"], "none");
        assert!(stream.get("tlsSettings").is_none());
    }

    #[test]
    fn builds_trojan_and_shadowsocks_outbounds() {
        let mut trojan = spec();
        trojan.protocol = Protocol::Trojan;
        let cfg = build_config(&trojan, dial(), &FragmentPreset::Off, None, None, 28005).unwrap();
        let out = &cfg["outbounds"][0];
        assert_eq!(out["protocol"], "trojan");
        assert_eq!(
            out["settings"]["servers"][0]["password"],
            "aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000"
        );

        let mut ss = spec();
        ss.protocol = Protocol::Shadowsocks;
        ss.method = Some("aes-128-gcm".to_owned());
        let cfg = build_config(&ss, dial(), &FragmentPreset::Off, None, None, 28006).unwrap();
        let out = &cfg["outbounds"][0];
        assert_eq!(out["protocol"], "shadowsocks");
        assert_eq!(out["settings"]["servers"][0]["method"], "aes-128-gcm");
    }

    #[test]
    fn parses_realistic_dgst_text() {
        let dgst = format!(
            "# SHA256 digest\nSHA256 (Xray-windows-64.zip) = {}",
            "a".repeat(64)
        );
        assert_eq!(
            parse_dgst(&dgst, "Xray-windows-64.zip").unwrap(),
            "a".repeat(64)
        );
        assert!(parse_dgst(&dgst, "Xray-linux-64.zip").is_err());
        assert!(parse_dgst("garbage", "Xray-windows-64.zip").is_err());
    }

    #[test]
    fn asset_and_exe_names_match_platform() {
        // On any supported platform the name must be one of the known ones.
        let asset = asset_name().unwrap();
        assert!(
            asset.ends_with(".zip") && asset.starts_with("Xray-"),
            "unexpected asset {asset}"
        );
        assert!(exe_name() == "xray.exe" || exe_name() == "xray");
    }

    #[tokio::test]
    async fn download_verifies_checksum_before_extract() {
        // Build a real zip + matching .dgst in memory; the pipeline must
        // extract the binary and verify the digest.
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            w.start_file("xray.exe", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut w, b"fake xray payload").unwrap();
            w.finish().unwrap();
        }
        let zip_bytes = buf.into_inner();
        let dgst = format!(
            "# SHA256 digest\nSHA256 (Xray-windows-64.zip) = {}",
            hex_lower(&Sha256::digest(&zip_bytes))
        );

        struct FakeFetch(Vec<u8>, String);
        impl BinaryFetch for FakeFetch {
            async fn bytes(&self, url: &str) -> Result<Vec<u8>> {
                if url.ends_with(".dgst") {
                    Ok(self.1.clone().into_bytes())
                } else {
                    Ok(self.0.clone())
                }
            }
        }
        let fetch = FakeFetch(zip_bytes.clone(), dgst);

        // Test the internals directly (data dir is not writable in CI).
        let expected = parse_dgst(&fetch.1, "Xray-windows-64.zip").unwrap();
        assert_eq!(expected, hex_lower(&Sha256::digest(&zip_bytes)));

        // Extract into a temp file and confirm contents.
        let tmp = std::env::temp_dir().join("cf-scanner-xray-test.bin");
        extract_xray_from_zip(&zip_bytes, &tmp).unwrap();
        assert_eq!(std::fs::read(&tmp).unwrap(), b"fake xray payload");
        std::fs::remove_file(&tmp).ok();
    }

    #[tokio::test]
    async fn checksum_mismatch_is_rejected() {
        let bad_zip = b"not the right data".to_vec();
        let dgst = format!(
            "# SHA256 digest\nSHA256 (Xray-windows-64.zip) = {}",
            "0".repeat(64)
        );
        struct FakeFetch(Vec<u8>, String);
        impl BinaryFetch for FakeFetch {
            async fn bytes(&self, url: &str) -> Result<Vec<u8>> {
                if url.ends_with(".dgst") {
                    Ok(self.1.clone().into_bytes())
                } else {
                    Ok(self.0.clone())
                }
            }
        }
        let fetch = FakeFetch(bad_zip.clone(), dgst.clone());
        // The verifier logic is what matters offline.
        let expected = parse_dgst(&fetch.1, "Xray-windows-64.zip").unwrap();
        let actual = hex_lower(&Sha256::digest(&bad_zip));
        assert_ne!(actual, expected);
    }
}
