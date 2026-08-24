//! Build-time data embedding (Task 15, Task 17):
//! - db-ip Lite country mmdb (embedded): the official host only ships gzipped
//!   builds, so download + decompress + cache. The version and its SHA-256
//!   are pinned in `data/geoip-version.txt`; a failed download or checksum
//!   mismatch fails the build (never embed an empty db). Setting
//!   `CFSCANNER_OFFLINE_BUILD=1` skips the network and embeds a small
//!   placeholder instead — runtime country lookups then return None (see
//!   src/geo.rs), never a hard failure.
//! - dist builds only (`dist-bundle-xray` feature): the pinned, checksum
//!   verified xray binary, written over the committed placeholder in
//!   `data/bundled/` so release archives carry it next to the app binary.
//!   Dev builds are untouched; the runtime fallback download covers them.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

// Same grammar file src/xray.rs parses at runtime; included so the two
// cannot silently diverge (src/dgst.rs is std-only on purpose).
#[path = "src/dgst.rs"]
mod dgst;

const VERSION_FILE: &str = include_str!("data/geoip-version.txt");
const XRAY_VERSION_FILE: &str = include_str!("data/xray-version.txt");
const URL: &str = "https://download.db-ip.com/free/dbip-country-lite-{version}.mmdb.gz";
const XRAY_BASE: &str = "https://github.com/XTLS/Xray-core/releases/download";
const MIN_VALID_BYTES: u64 = 100_000;

fn version() -> &'static str {
    VERSION_FILE.lines().next().unwrap_or("").trim_end()
}

/// SHA-256 of the pinned `.mmdb.gz` download (review Domain 1 rec 6).
fn geoip_pin() -> &'static str {
    VERSION_FILE.lines().nth(1).unwrap_or("").trim_end()
}

/// `CFSCANNER_OFFLINE_BUILD` set to any non-empty value (e.g. `1`): skip the
/// geoip download + checksum and embed a placeholder instead.
fn offline_build() -> bool {
    std::env::var_os("CFSCANNER_OFFLINE_BUILD")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

fn xray_version() -> &'static str {
    XRAY_VERSION_FILE.trim_end()
}

fn main() {
    println!("cargo:rerun-if-changed=data/geoip-version.txt");
    println!("cargo:rerun-if-changed=data/xray-version.txt");
    println!("cargo:rerun-if-env-changed=CFSCANNER_OFFLINE_BUILD");
    embed_geoip();
    bundle_xray_if_requested();
}

fn embed_geoip() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("geoip.mmdb");
    // The offline escape hatch: compile without network access. The flags
    // must not affect normal builds — it is checked before any download or
    // cache validation, and the placeholder is never mistaken for the db.
    if offline_build() {
        // cargo:warning= (not eprintln!) is what cargo shows on a successful
        // build script run; plain stderr is swallowed unless the script fails.
        println!(
            "cargo:warning=CFSCANNER_OFFLINE_BUILD set: embedding placeholder geoip db; \
             country lookups will return None"
        );
        // A few readable bytes, clearly not a valid mmdb (min 100 KB):
        // geo.rs's Reader::from_source fails and degrades to None lookups.
        if std::fs::write(&dest, b"cf-scanner offline build: no geoip db\n").is_err() {
            eprintln!("error: could not write placeholder {}", dest.display());
            std::process::exit(1);
        }
        return;
    }
    // OUT_DIR survives between builds (unlike the OS temp dir, which is
    // shared and unpredictable); the git-tracked data/ dir stays untouched.
    let cache = out_dir.join(format!("dbip-country-lite-{}.mmdb", version()));

    if !cache_intact(&cache) {
        refresh_cache(&cache);
    }
    if let Err(err) = std::fs::copy(&cache, &dest) {
        eprintln!(
            "error: could not copy cached db {} into place {}: {err}",
            cache.display(),
            dest.display()
        );
        std::process::exit(1);
    }
}

/// Re-download, verify against the pinned `.mmdb.gz` sha256, decompress, then
/// atomically place both the cache and its `<cache>.sha256` sidecar (digest
/// of the decompressed mmdb) so verify-before-use can trust later builds.
fn refresh_cache(cache: &Path) {
    let Some(bytes) = download(&URL.replace("{version}", version())) else {
        eprintln!(
            "error: db-ip download failed; refusing to embed an empty geoip db \
             (pinned version {}, sha256 {}...)",
            version(),
            &geoip_pin()[..8]
        );
        std::process::exit(1);
    };
    let actual = hex_lower(&Sha256::digest(&bytes));
    if actual != geoip_pin().to_ascii_lowercase() {
        eprintln!(
            "error: db-ip mmdb checksum mismatch: got {actual}, want {}",
            geoip_pin()
        );
        std::process::exit(1);
    }
    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut raw = Vec::new();
    if decoder.read_to_end(&mut raw).is_err() || raw.is_empty() {
        eprintln!("error: db-ip download is not valid gzip");
        std::process::exit(1);
    }
    if let Err(err) = write_atomic(cache, &raw) {
        eprintln!("error: could not cache {}: {err}", cache.display());
        std::process::exit(1);
    }
    let sidecar = sidecar_path(cache);
    let digest = hex_lower(&Sha256::digest(&raw));
    if let Err(err) = write_atomic(&sidecar, format!("{digest}\n").as_bytes()) {
        eprintln!(
            "error: could not write digest sidecar {}: {err}",
            sidecar.display()
        );
        std::process::exit(1);
    }
}

/// Verify-before-use: the cache counts as good only when a fresh SHA-256 of
/// its bytes matches the sidecar written at download time. A truncated or
/// otherwise corrupted cache (or missing/garbled sidecar) forces re-download
/// instead of persisting forever the way the old size-only check allowed.
/// The size floor doubles as a cheap early-out before hashing megabytes.
fn cache_intact(cache: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(cache) else {
        return false;
    };
    if meta.len() < MIN_VALID_BYTES {
        return false;
    }
    let Some(expected) = std::fs::read_to_string(sidecar_path(cache))
        .ok()
        .as_deref()
        .and_then(parse_sidecar_digest)
    else {
        return false;
    };
    let Ok(bytes) = std::fs::read(cache) else {
        return false;
    };
    hex_lower(&Sha256::digest(&bytes)) == expected
}

/// Sidecar holds just the lowercase hex digest; trailing newline tolerated.
fn parse_sidecar_digest(text: &str) -> Option<String> {
    let digest = text.trim();
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| digest.to_ascii_lowercase())
}

fn sidecar_path(cache: &Path) -> PathBuf {
    let mut name = cache.file_name().unwrap_or_default().to_os_string();
    name.push(".sha256");
    cache.with_file_name(name)
}

/// tmp+rename so a killed build never leaves a half-written file that a
/// later run would accept (the rename replaces any existing file).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

/// dist-only: place the verified xray binary at `data/bundled/<exe>` so the
/// release archive (dist `include`) carries it. Refuses to run when the
/// placeholder is missing, keeping accidental repo mutations out of dev.
fn bundle_xray_if_requested() {
    if std::env::var_os("CARGO_FEATURE_DIST_BUNDLE_XRAY").is_none() {
        return;
    }
    let target = std::env::var("TARGET").unwrap_or_default();
    let Some(asset) = xray_asset(&target) else {
        eprintln!(
            "error: no xray asset for target {target}; refusing to ship archive without xray"
        );
        std::process::exit(1);
    };
    let exe = if asset.contains("windows") {
        "xray.exe"
    } else {
        "xray"
    };
    let dest = PathBuf::from("data/bundled").join(exe);
    ensure_placeholder(&dest);
    // A leftover real binary from an earlier dist build only counts when it
    // was bundled for the pinned version: the stamp lives in OUT_DIR, so it
    // survives between builds but resets on `cargo clean` — re-bundling
    // after a data/xray-version.txt bump or a placeholder restore, never
    // silently shipping a stale binary.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let stamp = out_dir.join("bundled-xray-version.txt");
    let stamped = std::fs::read_to_string(&stamp)
        .map(|v| v.trim() == xray_version())
        .unwrap_or(false);
    let dest_real = std::fs::metadata(&dest)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if stamped && dest_real {
        return; // already bundled for this pinned version
    }

    let url = format!("{XRAY_BASE}/{}/{}", xray_version(), asset);
    let Some(zip) = download(&url) else {
        eprintln!("error: could not download {url}");
        std::process::exit(1);
    };
    let Some(dgst) = download(&format!("{url}.dgst")) else {
        eprintln!("error: could not download {url}.dgst");
        std::process::exit(1);
    };
    let text = String::from_utf8_lossy(&dgst);
    let expected = dgst::dgst_sha256_hex(text.as_ref()).unwrap_or_else(|| {
        eprintln!("error: no SHA-256 in .dgst for {asset}");
        std::process::exit(1)
    });
    let actual = hex_lower(&Sha256::digest(&zip));
    if actual != expected {
        eprintln!("error: xray checksum mismatch: got {actual}, want {expected}");
        std::process::exit(1);
    }

    let tmp = dest.with_extension("tmp");
    let mut archive = ZipArchive::new(std::io::Cursor::new(&zip)).unwrap_or_else(|err| {
        eprintln!("error: xray zip unreadable: {err}");
        std::process::exit(1)
    });
    let mut entry = archive.by_name(exe).unwrap_or_else(|err| {
        eprintln!("error: no {exe} entry in xray zip: {err}");
        std::process::exit(1)
    });
    std::fs::write(&tmp, read_all(&mut entry)).unwrap_or_else(|err| {
        eprintln!("error: writing {}: {err}", tmp.display());
        std::process::exit(1)
    });
    make_executable(&tmp);
    std::fs::rename(&tmp, &dest).unwrap_or_else(|err| {
        eprintln!("error: moving {}: {err}", tmp.display());
        std::process::exit(1)
    });
    std::fs::write(&stamp, xray_version()).unwrap_or_else(|err| {
        eprintln!("error: writing stamp {}: {err}", stamp.display());
        std::process::exit(1)
    });
    // Archives must carry only this target's binary: drop the foreign
    // 0-byte placeholder so dist's include glob picks up a single xray. A
    // later build of the other target recreates it via ensure_placeholder.
    let foreign = if exe == "xray.exe" {
        "xray"
    } else {
        "xray.exe"
    };
    let _ = std::fs::remove_file(PathBuf::from("data/bundled").join(foreign));
    println!("bundled {asset} -> {}", dest.display());
}

/// dist builds overwrite the git-tracked 0-byte placeholders with real
/// binaries; a prior build of the other target may have deleted this
/// placeholder (foreign-target sweep), so recreate it instead of failing.
fn ensure_placeholder(path: &std::path::Path) {
    if path.exists() {
        return;
    }
    if std::fs::write(path, []).is_err() {
        eprintln!("error: could not create placeholder {}", path.display());
        std::process::exit(1);
    }
}

fn read_all<R: Read>(entry: &mut R) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = entry.read_to_end(&mut buf);
    buf
}

fn xray_asset(target: &str) -> Option<String> {
    // XTLS asset naming (v26.x): macos uses "macos" (not darwin), and arm64
    // carries a "-v8a" suffix across all platforms.
    let (os, arch) = if target.contains("windows") {
        (
            "windows",
            if target.contains("aarch64") {
                "arm64-v8a"
            } else {
                "64"
            },
        )
    } else if target.contains("apple") {
        (
            "macos",
            if target.contains("aarch64") {
                "arm64-v8a"
            } else {
                "64"
            },
        )
    } else if target.contains("linux") {
        (
            "linux",
            if target.contains("aarch64") {
                "arm64-v8a"
            } else {
                "64"
            },
        )
    } else {
        return None;
    };
    Some(format!("Xray-{os}-{arch}.zip"))
}

/// Digest extraction lives in the shared src/dgst.rs (also included by
/// src/xray.rs) — keep it the single spec of the `.dgst` format.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) {}

fn download(url: &str) -> Option<Vec<u8>> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--retry",
            "3",
            "--retry-delay",
            "2",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "180",
            "-o",
            "-",
            url,
        ])
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    Some(out.stdout)
}
