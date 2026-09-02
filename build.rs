use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

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

fn geoip_pin() -> &'static str {
    VERSION_FILE.lines().nth(1).unwrap_or("").trim_end()
}

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
    println!("cargo:rerun-if-changed=src/dgst.rs");
    println!("cargo:rerun-if-env-changed=CFSCANNER_OFFLINE_BUILD");
    embed_geoip();
    bundle_xray_if_requested();
}

fn embed_geoip() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("geoip.mmdb");
    if offline_build() {
        println!(
            "cargo:warning=CFSCANNER_OFFLINE_BUILD set: embedding placeholder geoip db; \
             country lookups will return None"
        );
        if std::fs::write(&dest, b"cf-scanner offline build: no geoip db\n").is_err() {
            eprintln!("error: could not write placeholder {}", dest.display());
            std::process::exit(1);
        }
        return;
    }
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
    let actual = dgst::hex_lower(&Sha256::digest(&bytes));
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
    let digest = dgst::hex_lower(&Sha256::digest(&raw));
    if let Err(err) = write_atomic(&sidecar, format!("{digest}\n").as_bytes()) {
        eprintln!(
            "error: could not write digest sidecar {}: {err}",
            sidecar.display()
        );
        std::process::exit(1);
    }
}

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
    dgst::hex_lower(&Sha256::digest(&bytes)) == expected
}

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

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_owned());
    let tmp = path.with_file_name(format!("{file_name}.tmp"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

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
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let stamp = out_dir.join("bundled-xray-version.txt");
    let stamped = std::fs::read_to_string(&stamp)
        .map(|v| v.trim() == xray_version())
        .unwrap_or(false);
    let dest_real = std::fs::metadata(&dest)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if stamped && dest_real {
        return;
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
    let actual = dgst::hex_lower(&Sha256::digest(&zip));
    if actual != expected {
        eprintln!("error: xray checksum mismatch: got {actual}, want {expected}");
        std::process::exit(1);
    }

    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_owned());
    let tmp = dest.with_file_name(format!("{file_name}.tmp"));
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
    let foreign = if exe == "xray.exe" {
        "xray"
    } else {
        "xray.exe"
    };
    let _ = std::fs::remove_file(PathBuf::from("data/bundled").join(foreign));
    println!("bundled {asset} -> {}", dest.display());
}

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
            "--proto-redir",
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
