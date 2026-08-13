//! Embed the db-ip Lite country mmdb at build time (Task 15). The official
//! host only ships gzipped builds, so download + decompress + cache. Offline
//! builds degrade: an empty file is embedded and `Geo::embedded()` handles it.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use flate2::read::GzDecoder;

const VERSION_FILE: &str = include_str!("data/geoip-version.txt");
const URL: &str = "https://download.db-ip.com/free/dbip-country-lite-{version}.mmdb.gz";
const MIN_VALID_BYTES: u64 = 100_000;

fn version() -> &'static str {
    VERSION_FILE.trim_end()
}

fn main() {
    println!("cargo:rerun-if-changed=data/geoip-version.txt");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("geoip.mmdb");
    let cache = std::env::temp_dir().join(format!("cf-scanner-dbip-country-v{}.mmdb", version()));

    if !looks_valid(&cache) {
        match download() {
            Some(bytes) => {
                let _ = std::fs::write(&cache, &bytes);
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

fn download() -> Option<Vec<u8>> {
    let url = URL.replace("{version}", version());
    let out = Command::new("curl")
        .args(["-fsSL", "--max-time", "120", "-o", "-", &url])
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    let mut decoder = GzDecoder::new(out.stdout.as_slice());
    let mut raw = Vec::new();
    decoder.read_to_end(&mut raw).ok()?;
    (!raw.is_empty()).then_some(raw)
}

fn looks_valid(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() >= MIN_VALID_BYTES)
        .unwrap_or(false)
}
