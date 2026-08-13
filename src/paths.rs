//! Runtime file locations (refreshed ranges, later: xray binary, WARP keys).

use std::path::PathBuf;

use anyhow::{Result, anyhow};

pub fn data_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "qmahyar", "cf-scanner")
        .ok_or_else(|| anyhow!("could not resolve a data directory"))?;
    Ok(dirs.data_dir().to_path_buf())
}

pub fn refreshed_ranges_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cf-ranges.txt"))
}

/// Data-dir copy of the refreshed IPv6 list (`ranges refresh --ipv6`).
pub fn refreshed_ranges_v6_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cf-ranges-v6.txt"))
}

/// Data-dir location of the xray binary (dev/downloaded fallback; release
/// archives bundle the binary next to the executable instead).
pub fn xray_binary_path() -> Result<PathBuf> {
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    Ok(data_dir()?.join(name))
}
