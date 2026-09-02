//! Xray manager (phase 2): bundled-binary discovery, checksum-verified
//! download fallback, subprocess spawn/cleanup with a local socks inbound,
//! and the fragment preset -> config JSON builder (freedom outbound +
//! `sockopt.dialerProxy` chain). The crates.io `xray-core` crate is a gRPC
//! client only and is never used; xray always runs as a subprocess.

use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::api::types::{CustomFragment, FragmentPreset};
use crate::configs::{OutboundSpec, Protocol, sanitize_error_text};
use crate::dgst::hex_lower;
use crate::paths;

pub const VERSION: &str = include_str!("../data/xray-version.txt");
const RELEASE_BASE: &str = "https://github.com/XTLS/Xray-core/releases/download";
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Fragment preset -> freedom-outbound fragment block (community cfray
/// values, packets always `tlshello` except Custom which honors the user's
/// validated `packets` value).
fn fragment_block(preset: &FragmentPreset, custom: Option<&CustomFragment>) -> Option<Value> {
    let (packets, length, interval) = match preset {
        FragmentPreset::Off => return None,
        FragmentPreset::Light => ("tlshello", "100-200", "10-20"),
        FragmentPreset::Medium => ("tlshello", "50-200", "10-40"),
        FragmentPreset::Heavy => ("tlshello", "10-300", "5-50"),
        FragmentPreset::Custom => {
            let c = custom?;
            (c.packets.as_str(), c.length.as_str(), c.interval.as_str())
        }
    };
    Some(json!({
        "packets": packets,
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
    let mut stream = json!({"network": if spec.ws.is_some() { "ws" } else { "tcp" }});
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
        Protocol::Vless => json!({
            "tag": "proxy",
            "protocol": spec.protocol.as_str(),
            "settings": {"vnext": [{
                "address": dial_ip.to_string(), "port": spec.port,
                "users": [{"id": spec.user_id, "encryption": "none"}],
            }]},
        }),
        Protocol::Vmess => json!({
            "tag": "proxy",
            "protocol": spec.protocol.as_str(),
            "settings": {"vnext": [{
                "address": dial_ip.to_string(), "port": spec.port,
                "users": [{
                    "id": spec.user_id,
                    "alterId": spec.alter_id,
                    "security": spec.vmess_security.as_deref().unwrap_or("auto"),
                }],
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
    // The chain exists only when the fragment outbound exists: a Custom preset
    // with no values yields no fragment outbound, and a `dialerProxy` naming a
    // missing tag would make xray refuse the whole config.
    let fragment = fragment_outbound(preset, custom);
    let has_fragment = fragment.is_some();
    if let Some(frag) = fragment {
        outbounds.push(frag);
    }
    let mut proxy = build_outbound(spec, dial_ip, sni_override);
    if has_fragment {
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

/// Spawns `xray run -c <dir>/config.json` and waits until the socks inbound
/// accepts connections. The config must be written to `config_dir` first.
pub async fn spawn(config_dir: &Path, xray_bin: &Path, config_json: &Value) -> Result<XrayProcess> {
    let config_path = config_dir.join("config.json");
    write_trial_config(&config_path, config_json).await?;

    let mut child = tokio::process::Command::new(xray_bin)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn xray; is the binary present?")?;

    // Stderr is xray's own diagnostics (glibc mismatches, corrupt binary).
    // Config-material values can show up in it (e.g. a parse-error dump), so
    // every line is masked against the trial config's secrets before it is
    // logged or kept for the failure error — the only way a dead-on-arrival
    // child is diagnosable.
    let secrets = config_secrets(config_json);
    let stderr_tail = capture_stderr(child.stderr.take().expect("stderr is piped"), secrets);

    let socks_port = config_json
        .pointer("/inbounds/0/port")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("config has no socks inbound"))? as u16;
    let socks_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), socks_port);
    if let Err(err) = wait_for_socks(&mut child, socks_addr, READY_TIMEOUT).await {
        // The child may still be running (poll timed out): kill and reap it
        // so the stderr reader hits EOF and the tail is complete.
        let _ = child.start_kill();
        let _ = child.wait().await;
        let tail = stderr_tail.tail().await;
        let message = if tail.is_empty() {
            format!("{err:#}")
        } else {
            format!("{err:#}; xray stderr:\n{tail}")
        };
        return Err(anyhow!(message));
    }
    Ok(XrayProcess { child, socks_addr })
}

/// Polls a TCP connect until it succeeds (proves the socks inbound is up),
/// racing the child's exit so a corrupt/arch-mismatched binary that dies on
/// arrival fails in ~20ms with its actual exit code instead of polling the
/// full timeout.
async fn wait_for_socks(
    child: &mut tokio::process::Child,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut interval = Duration::from_millis(20);
    loop {
        if let Some(status) = child.try_wait().context("failed to poll xray")? {
            bail!("{}", early_exit_message(&status));
        }
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() >= deadline => {
                bail!("socks {addr} not reachable within {timeout:?}")
            }
            Err(_) => {
                tokio::time::sleep(interval).await;
                interval = (interval.mul_f64(1.5)).min(Duration::from_millis(200));
            }
        }
    }
}

fn early_exit_message(status: &std::process::ExitStatus) -> String {
    let Some(code) = status.code() else {
        return "xray was terminated by a signal before its socks inbound came up".to_owned();
    };
    if code == 0 {
        return "xray exited before its socks inbound came up".to_owned();
    }
    format!(
        "xray exited with code {code} before its socks inbound came up \
         (a corrupt or mismatched binary usually exits immediately — \
         re-download it or check the platform runtime, e.g. glibc on Termux)"
    )
}

/// Writes the trial config (which embeds the user's id/password) and locks
/// it down to the owning user on Unix; the blocking fs runs off the async
/// executor. The 0o600 mode is applied at open time (not via a later chmod)
/// so the file is never world-readable, not even for a microsecond.
async fn write_trial_config(path: &Path, config_json: &Value) -> Result<()> {
    let path = path.to_path_buf();
    let json = serde_json::to_string_pretty(config_json)?;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(json.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            crate::paths::write_secret(&path, json.as_bytes())?;
        }
        Ok(())
    })
    .await
    .context("config write task failed")??;
    Ok(())
}

const STDERR_TAIL_LINES: usize = 20;

/// Credential-adjacent values embedded in the trial config; the stderr
/// capture masks them so a diagnostic that echoes config material never
/// leaks the user's id/password or fronting identity.
fn config_secrets(config_json: &Value) -> Vec<String> {
    let mut secrets = Vec::new();
    let Some(outbounds) = config_json["outbounds"].as_array() else {
        return secrets;
    };
    for outbound in outbounds {
        if let Some(users) = outbound
            .pointer("/settings/vnext/0/users")
            .and_then(Value::as_array)
        {
            for user in users {
                if let Some(id) = user["id"].as_str() {
                    secrets.push(id.to_owned());
                }
            }
        }
        if let Some(servers) = outbound
            .pointer("/settings/servers")
            .and_then(Value::as_array)
        {
            for server in servers {
                if let Some(password) = server["password"].as_str() {
                    secrets.push(password.to_owned());
                }
            }
        }
        let stream = &outbound["streamSettings"];
        if let Some(name) = stream
            .pointer("/tlsSettings/serverName")
            .and_then(Value::as_str)
        {
            secrets.push(name.to_owned());
        }
        if let Some(host) = stream
            .pointer("/wsSettings/headers/Host")
            .and_then(Value::as_str)
        {
            secrets.push(host.to_owned());
        }
    }
    secrets
}

/// Replaces every secret occurrence with `***`, longest first so a value
/// that is a prefix of another cannot leave a partial leak behind.
fn mask_values(line: &str, secrets: &[String]) -> String {
    let mut sorted = secrets.to_vec();
    sorted.retain(|s| !s.is_empty());
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = line.to_owned();
    for secret in sorted {
        out = out.replace(&secret, "***");
    }
    out
}

/// Bounded stderr capture for a spawned child: lines are debug-logged as
/// they arrive and the last `STDERR_TAIL_LINES` are kept for error reports.
struct StderrCapture {
    tail: Arc<Mutex<Vec<String>>>,
    done: tokio::task::JoinHandle<()>,
}

impl StderrCapture {
    /// Awaits EOF (the child exited) and returns the captured tail.
    async fn tail(self) -> String {
        let _ = self.done.await;
        self.tail.lock().unwrap().join("\n")
    }
}

fn capture_stderr(stderr: tokio::process::ChildStderr, secrets: Vec<String>) -> StderrCapture {
    let tail = Arc::new(Mutex::new(Vec::new()));
    let done = tokio::spawn(drain_stderr(stderr, tail.clone(), secrets));
    StderrCapture { tail, done }
}

async fn drain_stderr(
    stderr: tokio::process::ChildStderr,
    tail: Arc<Mutex<Vec<String>>>,
    secrets: Vec<String>,
) {
    use tokio::io::AsyncBufReadExt as _;
    let mut lines = tokio::io::BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let masked = sanitize_error_text(&mask_values(&line, &secrets));
        tracing::debug!(stderr_line = %masked, "xray stderr");
        let mut guard = tail.lock().unwrap();
        guard.push(masked);
        if guard.len() > STDERR_TAIL_LINES {
            guard.remove(0);
        }
    }
}

// --- binary discovery + fallback download ----------------------------------

fn asset_name() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "Xray-windows-64.zip",
        ("linux", "x86_64") => "Xray-linux-64.zip",
        // XTLS v26+: arm64 assets carry a -v8a suffix (see ADR-007 gotchas).
        ("linux", "aarch64") => "Xray-linux-arm64-v8a.zip",
        ("macos", "x86_64") => "Xray-macos-64.zip",
        ("macos", "aarch64") => "Xray-macos-arm64-v8a.zip",
        (os, arch) => bail!("no xray asset for {os}/{arch}"),
    })
}

fn exe_name() -> &'static str {
    if cfg!(windows) { "xray.exe" } else { "xray" }
}

/// Bundled xray next to the running binary (release archives carry it; a
/// directory include lands it under `bundled/` inside the archive).
pub fn find_bundled() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let parent = exe.parent()?;
    find_bundled_in(parent)
}

fn find_bundled_in(parent: &Path) -> Option<PathBuf> {
    let candidates = [parent.to_path_buf(), parent.join("bundled")];
    candidates
        .into_iter()
        .map(|dir| dir.join(exe_name()))
        .find(|path| valid_bundled(path))
}

/// A bundled binary must be a real file with real content: release archives
/// carry the actual xray, but the repo's tracked 0-byte placeholders (and
/// any truncated write) must never be mistaken for a working binary. Real
/// xray binaries are tens of megabytes, so 1 MiB is a safe floor.
const MIN_BUNDLED_BYTES: u64 = 1 << 20;

fn valid_bundled(path: &Path) -> bool {
    path.is_file() && path.metadata().is_ok_and(|m| m.len() >= MIN_BUNDLED_BYTES)
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

/// Stored beside the cached binary: `SHA2-256= <hex>` of the binary file
/// itself, written at download time so use-time re-verification is fully
/// offline (the release `.dgst` covers the zip only).
fn dgst_path(bin: &Path) -> PathBuf {
    bin.with_extension("dgst")
}

/// Once-per-process outcome of "make a verified xray binary available":
/// bundled first, then the data-dir cache (checksum-verified), then a
/// single-flight download that every concurrent attempt awaits.
static BINARY_STATE: OnceLock<tokio::sync::Mutex<Option<Result<PathBuf, String>>>> =
    OnceLock::new();

/// Resolves the xray binary for phase 2, verifying the cached copy against
/// its `.dgst` exactly once per process. A corrupt (or unverifiable) cache
/// is removed and re-downloaded; concurrent attempts share one outcome.
/// Only successes are memoized — a transient network failure must not brick
/// phase 2 for the process lifetime, so failures retry on the next attempt.
pub async fn ensure_binary(fetch: &impl BinaryFetch) -> Result<PathBuf> {
    let state = BINARY_STATE.get_or_init(|| tokio::sync::Mutex::new(None));
    let cached_ok = |path: &PathBuf| {
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.len() >= MIN_BUNDLED_BYTES)
    };
    // Fast path: a memoized success (file still present) returns without
    // queueing behind the download lock.
    let snapshot = { state.lock().await.clone() };
    if let Some(Ok(path)) = &snapshot
        && cached_ok(path)
    {
        return Ok(path.clone());
    }
    // cached binary vanished or truncated: treat as miss
    // Slow path: hold the async lock across resolution so concurrent
    // attempts share ONE download instead of stampeding the origin.
    let mut guard = state.lock().await;
    if let Some(Ok(path)) = &*guard
        && cached_ok(path)
    {
        return Ok(path.clone());
    }
    let result = resolve_binary(fetch).await;
    match &result {
        Ok(path) => *guard = Some(Ok(path.clone())),
        Err(err) => {
            tracing::warn!("xray binary resolution failed; the next attempt will retry: {err:#}")
        }
    }
    result
}

async fn resolve_binary(fetch: &impl BinaryFetch) -> Result<PathBuf> {
    if let Some(bundled) = find_bundled() {
        return Ok(bundled);
    }
    if let Some(cached) = cached_in_data_dir() {
        if cached_matches_dgst(&cached).await {
            return Ok(cached);
        }
        tracing::warn!(path = %cached.display(), "cached xray binary failed its checksum; re-downloading");
        let _ = tokio::fs::remove_file(dgst_path(&cached)).await;
        let _ = tokio::fs::remove_file(&cached).await;
    }
    download_binary(fetch).await
}

/// SHA-256 of the on-disk binary vs its stored `.dgst`; a missing or
/// unparsable `.dgst` counts as a mismatch (refuse the unverifiable cache).
async fn cached_matches_dgst(bin: &Path) -> bool {
    let Ok(text) = tokio::fs::read_to_string(dgst_path(bin)).await else {
        return false;
    };
    let Ok(expected) = parse_dgst(&text, exe_name()) else {
        return false;
    };
    let Ok(bytes) = tokio::fs::read(bin).await else {
        return false;
    };
    // Hashing up to 64 MiB is CPU-bound: keep it off the runtime workers.
    match tokio::task::spawn_blocking(move || hex_lower(&Sha256::digest(&bytes))).await {
        Ok(actual) => actual == expected,
        Err(_) => false,
    }
}

/// Downloads the pinned release, verifies its `.dgst` SHA-256, extracts the
/// binary into the data dir (writing its own `.dgst` for use-time
/// re-verification), and returns the path. Refuses to overwrite an existing
/// file.
pub async fn download_binary(fetch: &impl BinaryFetch) -> Result<PathBuf> {
    let asset = asset_name()?;
    let version = VERSION.trim();
    let url = format!("{RELEASE_BASE}/{version}/{asset}");
    let dgst_url = format!("{url}.dgst");

    let (zip, dgst) = tokio::join!(fetch.bytes(&url), fetch.bytes(&dgst_url));
    let zip = zip?;
    let dgst = dgst?;
    let expected = parse_dgst(&String::from_utf8_lossy(&dgst), asset)?;

    let dest = paths::xray_binary_path()?;
    if dest.exists() {
        bail!("{} already exists; refusing to overwrite", dest.display());
    }
    let dgst_dest = dgst_path(&dest);
    let install_dest = dest.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // Verify BEFORE anything lands on disk: hashing the 64 MiB zip is
        // CPU-bound, so it runs inside this blocking closure.
        let actual = hex_lower(&Sha256::digest(&zip));
        if actual != expected {
            bail!("xray checksum mismatch: got {actual}, want {expected}");
        }
        if let Some(parent) = install_dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Re-check inside the closure: the outer check raced with any other
        // process installing between it and the rename, and `rename` would
        // silently replace whatever appeared.
        if install_dest.exists() {
            bail!(
                "{} already exists; refusing to overwrite",
                install_dest.display()
            );
        }
        // Unique temp name (pid + randomness): two processes resolving the
        // binary concurrently must not extract into the same file.
        let tmp = install_dest.with_file_name(format!(
            "{}.tmp-{}-{:08x}",
            install_dest
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            std::process::id(),
            random_u32()
        ));
        extract_xray_from_zip(&zip, &tmp)?;
        make_executable(&tmp)?;
        let _gate = crate::paths::data_write_guard();
        std::fs::rename(&tmp, &install_dest)?;
        let digest = hex_lower(&Sha256::digest(&std::fs::read(&install_dest)?));
        std::fs::write(dgst_dest, format!("SHA2-256= {digest}\n"))?;
        Ok(())
    })
    .await
    .context("xray install task failed")??;
    Ok(dest)
}

fn random_u32() -> u32 {
    RngCore::next_u32(&mut OsRng)
}

/// Maps the shared `.dgst` grammar (crate::dgst — the same file build.rs
/// includes) onto this module's typed errors.
fn parse_dgst(text: &str, asset: &str) -> Result<String> {
    crate::dgst::dgst_sha256_hex(text)
        .ok_or_else(|| anyhow!("no SHA2-256 digest in .dgst for {asset}"))
}

/// Extracts just the xray binary out of the release zip.
fn extract_xray_from_zip(zip_bytes: &[u8], dest: &Path) -> Result<()> {
    const MAX_ZIP_BYTES: usize = 64 * 1024 * 1024;
    const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
    if zip_bytes.len() > MAX_ZIP_BYTES + 1024 {
        bail!("xray archive exceeds 64 MiB cap");
    }
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("invalid xray zip")?;
    let name = find_entry(&archive, exe_name())?;
    let entry = archive.by_index(name)?;
    if entry.size() > MAX_ENTRY_BYTES {
        bail!(
            "xray archive entry exceeds 64 MiB cap: {} claims {} bytes",
            exe_name(),
            entry.size()
        );
    }
    let mut buf = Vec::new();
    let mut limited = entry.take(MAX_ENTRY_BYTES + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_ENTRY_BYTES {
        bail!("xray archive entry exceeds 64 MiB cap: decompressed size exceeds limit");
    }
    std::fs::write(dest, buf)?;
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
        crate::ranges::validate_fetch_url(url)?;
        const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
        let resp = crate::ranges::HTTP_CLIENT
            .get(url)
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .context("failed to start download")?
            .error_for_status()
            .context("download returned an error")?;
        if let Some(len) = resp.content_length()
            && len > MAX_BODY_BYTES
        {
            bail!("response body too large: {len} bytes exceeds 64 MiB cap");
        }
        let bytes = resp.bytes().await.context("failed to read download body")?;
        if bytes.len() as u64 > MAX_BODY_BYTES {
            bail!(
                "response body too large: {} bytes exceeds 64 MiB cap",
                bytes.len()
            );
        }
        Ok(bytes.to_vec())
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
            alter_id: 0,
            vmess_security: None,
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
        assert_eq!(block["packets"], "1-3");
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
    fn vmess_build_emits_alterid_and_security() {
        // xray's vmess user schema carries alterId/security; `encryption` is
        // a vless-user key and must stay out of the vmess object.
        let mut s = spec();
        s.protocol = Protocol::Vmess;
        s.alter_id = 64;
        s.vmess_security = Some("aes-128-gcm".to_owned());
        let out = build_outbound(&s, dial(), None);
        let user = &out["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["alterId"], 64);
        assert_eq!(user["security"], "aes-128-gcm");
        assert!(user.get("encryption").is_none());
    }

    #[test]
    fn vless_build_keeps_encryption_none() {
        let out = build_outbound(&spec(), dial(), None);
        let user = &out["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["encryption"], "none");
        assert!(user.get("security").is_none());
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
    fn custom_fragment_without_values_is_not_chained() {
        // Custom preset with no values: no fragment outbound exists, so the
        // proxy must not carry a dialerProxy naming a missing tag (xray
        // would refuse the whole config).
        let cfg =
            build_config(&spec(), dial(), &FragmentPreset::Custom, None, None, 28007).unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 1);
        assert!(outbounds[0]["streamSettings"].get("sockopt").is_none());
        let custom = CustomFragment {
            packets: "1-3".to_owned(),
            length: "1-2".to_owned(),
            interval: "3-4".to_owned(),
        };
        let cfg = build_config(
            &spec(),
            dial(),
            &FragmentPreset::Custom,
            Some(&custom),
            None,
            28008,
        )
        .unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        assert_eq!(
            outbounds[1]["streamSettings"]["sockopt"]["dialerProxy"],
            "fragment"
        );
    }

    #[test]
    fn stderr_lines_mask_config_secrets() {
        let mut cfg =
            build_config(&spec(), dial(), &FragmentPreset::Light, None, None, 28009).unwrap();
        let mut s = spec();
        s.protocol = Protocol::Shadowsocks;
        s.user_id = "shadowsocks-password".to_owned();
        let cfg2 = build_config(&s, dial(), &FragmentPreset::Off, None, None, 28010).unwrap();
        if let Some(ss_outbound) = cfg2["outbounds"].as_array().and_then(|a| a.first()) {
            cfg["outbounds"]
                .as_array_mut()
                .unwrap()
                .push(ss_outbound.clone());
        }
        let secrets = config_secrets(&cfg);
        assert!(secrets.contains(&"aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000".to_owned()));
        assert!(secrets.contains(&"shadowsocks-password".to_owned()));
        assert!(secrets.contains(&"front.example.com".to_owned()));
        let masked = mask_values(
            "failed to dial aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000 via shadowsocks-password at front.example.com",
            &secrets,
        );
        assert!(
            !masked.contains("aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000"),
            "{masked}"
        );
        assert!(!masked.contains("shadowsocks-password"), "{masked}");
        assert!(!masked.contains("front.example.com"), "{masked}");
        assert_eq!(masked.matches("***").count(), 3, "{masked}");
    }

    #[test]
    fn bundled_placeholder_files_are_not_valid() {
        let dir =
            std::env::temp_dir().join(format!("cf-scanner-bundled-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bundled")).unwrap();
        let bundled = dir.join("bundled").join(exe_name());
        std::fs::write(&bundled, b"").unwrap();
        assert!(
            find_bundled_in(&dir).is_none(),
            "0-byte placeholder must not resolve"
        );
        std::fs::write(&bundled, vec![0u8; (MIN_BUNDLED_BYTES as usize) + 1]).unwrap();
        assert_eq!(find_bundled_in(&dir), Some(bundled));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn parses_realistic_dgst_text() {
        // The format XTLS actually ships: labeled digests, no filename.
        let dgst = format!(
            "MD5= {}\nSHA1= {}\nSHA2-256= {}\nSHA2-512= {}",
            "b".repeat(32),
            "c".repeat(40),
            "a".repeat(64),
            "d".repeat(128)
        );
        assert_eq!(
            parse_dgst(&dgst, "Xray-windows-64.zip").unwrap(),
            "a".repeat(64)
        );
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
            w.start_file(exe_name(), zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut w, b"fake xray payload").unwrap();
            w.finish().unwrap();
        }
        let zip_bytes = buf.into_inner();
        let dgst = format!("SHA2-256= {}", hex_lower(&Sha256::digest(&zip_bytes)));

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
        let dgst = format!("SHA2-256= {}", "0".repeat(64));
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

    /// Builds a zip containing `payload` under the platform exe name plus
    /// the matching zip-level `.dgst` text (mirrors the release artifacts).
    fn fake_zip(payload: &[u8]) -> (Vec<u8>, String) {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            w.start_file(exe_name(), zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut w, payload).unwrap();
            w.finish().unwrap();
        }
        let zip_bytes = buf.into_inner();
        let dgst = format!("SHA2-256= {}", hex_lower(&Sha256::digest(&zip_bytes)));
        (zip_bytes, dgst)
    }

    /// Drops the once-per-process outcome so each test starts from a cold
    /// cache; callers hold `paths::test_env::DATA_DIR_LOCK` so the reset
    /// never races another test's `ensure_binary`.
    async fn reset_binary_state() {
        let state = BINARY_STATE.get_or_init(|| tokio::sync::Mutex::new(None));
        *state.lock().await = None;
    }

    /// Points `paths::data_dir()` at a fresh temp dir for the lifetime of
    /// the guard. Uses the test seam instead of the process-wide
    /// `CF_SCANNER_DATA_DIR` env var so the warpgen tests (which flip that
    /// var themselves) can never be clobbered by ours mid-body.
    struct SeamDir(PathBuf);

    impl Drop for SeamDir {
        fn drop(&mut self) {
            *crate::paths::test_env::SEAM_DATA_DIR.lock().unwrap() = None;
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn isolated_data_dir() -> SeamDir {
        let dir = std::env::temp_dir().join("cf-scanner-xray-tests");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        *crate::paths::test_env::SEAM_DATA_DIR.lock().unwrap() = Some(dir.clone());
        SeamDir(dir)
    }

    #[cfg(unix)]
    fn exit_3_command() -> tokio::process::Command {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.arg("-c").arg("exit 3");
        command
    }

    #[cfg(windows)]
    fn exit_3_command() -> tokio::process::Command {
        let mut command = tokio::process::Command::new("cmd");
        command.arg("/C").arg("exit 3");
        command
    }

    fn free_loopback_addr() -> SocketAddr {
        std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[tokio::test]
    async fn wait_for_socks_fails_fast_with_exit_code_on_early_child_exit() {
        let mut child = exit_3_command()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let started = tokio::time::Instant::now();
        // Generous timeout so the deadline cannot fire first; a child that
        // dies on arrival must fail via the early-exit path in well under a
        // second (Windows may stall one refused connect ~2s, hence the 5s
        // bound — still a fraction of the 10s poll).
        let err = wait_for_socks(&mut child, free_loopback_addr(), Duration::from_secs(60))
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "early exit must fail fast, took {elapsed:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("with code 3"),
            "missing exit code: {message}"
        );
        assert!(message.contains("glibc"), "missing hint: {message}");
    }

    #[tokio::test]
    async fn cached_binary_passes_use_time_checksum_verification() {
        let _guard = crate::paths::test_env::DATA_DIR_LOCK.lock().await;
        let _isolated = isolated_data_dir().await;
        let bin = paths::xray_binary_path().unwrap();
        std::fs::write(&bin, b"fake xray payload").unwrap();
        let digest = hex_lower(&Sha256::digest(b"fake xray payload"));
        std::fs::write(dgst_path(&bin), format!("SHA2-256= {digest}\n")).unwrap();
        reset_binary_state().await;

        struct NeverFetch;
        impl BinaryFetch for NeverFetch {
            async fn bytes(&self, _url: &str) -> Result<Vec<u8>> {
                bail!("a verified cache must not trigger a download")
            }
        }
        let resolved = ensure_binary(&NeverFetch).await.unwrap();
        assert_eq!(resolved, bin);
    }

    #[tokio::test]
    async fn corrupt_cached_binary_is_refused_and_redownloaded() {
        let _guard = crate::paths::test_env::DATA_DIR_LOCK.lock().await;
        let _isolated = isolated_data_dir().await;
        let bin = paths::xray_binary_path().unwrap();
        std::fs::write(&bin, b"corrupt payload").unwrap();
        std::fs::write(dgst_path(&bin), format!("SHA2-256= {}\n", "0".repeat(64))).unwrap();
        reset_binary_state().await;

        let (zip_bytes, zip_dgst) = fake_zip(b"good xray payload");
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
        let resolved = ensure_binary(&FakeFetch(zip_bytes, zip_dgst))
            .await
            .unwrap();
        assert_eq!(resolved, bin);
        assert_eq!(std::fs::read(&bin).unwrap(), b"good xray payload");
        assert!(
            cached_matches_dgst(&bin).await,
            "re-download must leave a verifiable dgst"
        );
    }

    #[tokio::test]
    async fn concurrent_attempts_share_one_download() {
        let _guard = crate::paths::test_env::DATA_DIR_LOCK.lock().await;
        let _isolated = isolated_data_dir().await;
        reset_binary_state().await;

        let (zip_bytes, zip_dgst) = fake_zip(b"shared download payload");
        struct CountingFetch {
            calls: std::sync::atomic::AtomicUsize,
            zip: Vec<u8>,
            dgst: String,
        }
        impl BinaryFetch for CountingFetch {
            async fn bytes(&self, url: &str) -> Result<Vec<u8>> {
                self.calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if url.ends_with(".dgst") {
                    Ok(self.dgst.clone().into_bytes())
                } else {
                    Ok(self.zip.clone())
                }
            }
        }
        impl BinaryFetch for std::sync::Arc<CountingFetch> {
            async fn bytes(&self, url: &str) -> Result<Vec<u8>> {
                (**self).bytes(url).await
            }
        }
        let fetch = std::sync::Arc::new(CountingFetch {
            calls: std::sync::atomic::AtomicUsize::new(0),
            zip: zip_bytes,
            dgst: zip_dgst,
        });
        let mut handles = Vec::new();
        for _ in 0..4 {
            let fetch = fetch.clone();
            handles.push(tokio::spawn(async move { ensure_binary(&fetch).await }));
        }
        for handle in handles {
            handle.await.unwrap().unwrap();
        }
        // One download = one zip fetch + one dgst fetch; the rest reused
        // the cached outcome.
        assert_eq!(fetch.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
}
