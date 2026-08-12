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
