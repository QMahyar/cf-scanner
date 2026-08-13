//! Build-time data embedding (Task 15, Task 17):
//! - db-ip Lite country mmdb (embedded; the official host only ships gzipped
//!   builds, so download + decompress + cache; offline builds embed an empty
//!   file and `Geo::embedded()` degrades gracefully).
//! - dist builds only (`dist-bundle-xray` feature): the pinned, checksum
//!   verified xray binary, written over the committed placeholder in
//!   `data/bundled/` so release archives carry it next to the app binary.
//!   Dev builds are untouched; the runtime fallback download covers them.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

const VERSION_FILE: &str = include_str!("data/geoip-version.txt");
const XRAY_VERSION_FILE: &str = include_str!("data/xray-version.txt");
const URL: &str = "https://download.db-ip.com/free/dbip-country-lite-{version}.mmdb.gz";
const XRAY_BASE: &str = "https://github.com/XTLS/Xray-core/releases/download";
const MIN_VALID_BYTES: u64 = 100_000;

fn version() -> &'static str {
    VERSION_FILE.trim_end()
}

fn xray_version() -> &'static str {
    XRAY_VERSION_FILE.trim_end()
}

fn main() {
    println!("cargo:rerun-if-changed=data/geoip-version.txt");
    println!("cargo:rerun-if-changed=data/xray-version.txt");
    embed_geoip();
    bundle_xray_if_requested();
}

fn embed_geoip() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("geoip.mmdb");
    let cache = std::env::temp_dir().join(format!("cf-scanner-dbip-country-v{}.mmdb", version()));

    if !looks_valid(&cache) {
        match download(&URL.replace("{version}", version())) {
            Some(bytes) => {
                let mut decoder = GzDecoder::new(bytes.as_slice());
                let mut raw = Vec::new();
                if decoder.read_to_end(&mut raw).is_ok() && !raw.is_empty() {
                    let _ = std::fs::write(&cache, &raw);
                }
            }
            None => {
                eprintln!(
                    "warn: db-ip download failed; embedding empty geoip db \
                     (offline build?)"
                );
            }
        }
    }
    let _ = std::fs::copy(&cache, &dest);
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
        eprintln!("warn: no xray asset for target {target}; archive ships without xray");
        return;
    };
    let exe = if asset.contains("windows") {
        "xray.exe"
    } else {
        "xray"
    };
    let dest = PathBuf::from("data/bundled").join(exe);
    if !dest.exists() {
        eprintln!(
            "error: {} placeholder missing; refusing to write xray",
            dest.display()
        );
        std::process::exit(1);
    }
    if std::fs::metadata(&dest)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return; // already bundled by an earlier dist build
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
    let expected = dgst_hex(text.as_ref(), &asset).unwrap_or_else(|| {
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
    println!("bundled {asset} -> {}", dest.display());
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

/// XTLS `.dgst` text is labeled digests (`SHA2-256= <hex>`, no filename);
/// scoped to the first 64-char hex run on the SHA-256 line so format
/// variations are tolerated.
fn dgst_hex(text: &str, _asset: &str) -> Option<String> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("SHA2-256"))?;
    line.split(|c: char| !c.is_ascii_hexdigit())
        .find(|s| s.len() == 64)
        .map(str::to_owned)
}

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
        .args(["-fsSL", "--max-time", "180", "-o", "-", url])
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    Some(out.stdout)
}

fn looks_valid(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() >= MIN_VALID_BYTES)
        .unwrap_or(false)
}
