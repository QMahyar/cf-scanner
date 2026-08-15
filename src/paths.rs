//! Runtime file locations (refreshed ranges, xray binary). Tests and
//! embedding flows redirect the whole data dir via `CF_SCANNER_DATA_DIR`.

use std::path::PathBuf;

use anyhow::{Result, anyhow};

pub fn data_dir() -> Result<PathBuf> {
    // Redirects the whole data directory (tests, embedding flows); the
    // refresh-ranges path, the xray binary path and the trial dirs all
    // resolve through this one function. warpgen's identity path honors the
    // same variable (its own entry point), so a test or embedder setting it
    // redirects the entire product data footprint.
    if let Ok(dir) = std::env::var("CF_SCANNER_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
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
    // Test-only seam, scoped to THIS path: lets the xray test module isolate
    // its binary/cache without mutating the process-wide env var. It must
    // not live in `data_dir()` — ranges' refresh tests resolve the shared
    // data dir at arbitrary moments, and a seam there would redirect (and
    // drop) their files mid-test. `xray_binary_path` is read only by xray's
    // own resolution/download code, so the seam is visible nowhere else.
    #[cfg(test)]
    if let Some(dir) = test_env::SEAM_DATA_DIR.lock().unwrap().clone() {
        return Ok(dir.join(name));
    }
    Ok(data_dir()?.join(name))
}

#[cfg(test)]
pub(crate) mod test_env {
    //! Isolated-data-dir harness for the paths and xray test modules.
    //!
    //! The xray tests redirect via [`SEAM_DATA_DIR`] (a test-only override
    //! consulted by `xray_binary_path` alone) so they never race the ranges
    //! refresh tests, which resolve the shared data dir mid-body. The paths
    //! tests exercise the real cross-module contract — the
    //! `CF_SCANNER_DATA_DIR` env var — using warpgen's exact pattern
    //! (warpgen.rs `isolated_identity_dir`): set the var to a fixed temp
    //! dir, never restore it. The variable only ever holds one of a handful
    //! of stable absolute paths, so any other test resolving the data dir
    //! sees a consistent value between two calls.

    use std::path::{Path, PathBuf};

    /// Serializes every test that mutates `CF_SCANNER_DATA_DIR` or the
    /// seam. A tokio mutex so async tests may hold the guard across awaits
    /// without deadlocking the runtime.
    pub(crate) static DATA_DIR_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// Test-only data dir consulted by `xray_binary_path()`; set instead of
    /// the env var so the xray tests never race the ranges refresh tests'
    /// env reads (or warpgen's own flips of the variable).
    pub(crate) static SEAM_DATA_DIR: std::sync::Mutex<Option<PathBuf>> =
        std::sync::Mutex::new(None);

    /// Points `CF_SCANNER_DATA_DIR` at a fresh temp dir; the variable stays
    /// set for the rest of the process (warpgen's pattern), so path fns
    /// resolve consistently from any test's point of view.
    pub(crate) struct IsolatedDataDir {
        dir: PathBuf,
    }

    impl IsolatedDataDir {
        pub(crate) fn new() -> Self {
            let dir = std::env::temp_dir().join("cf-scanner-paths-tests");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // Unsafe: process-global env mutation, sound because callers
            // serialize on DATA_DIR_LOCK and the value is a stable absolute
            // path any reader can safely use.
            unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.dir
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::test_env::{DATA_DIR_LOCK, IsolatedDataDir};

    #[test]
    fn data_dir_honors_cf_scanner_data_dir_override() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let isolated = IsolatedDataDir::new();
        let dir = isolated.path();
        assert_eq!(data_dir().unwrap(), dir);
        assert_eq!(refreshed_ranges_path().unwrap(), dir.join("cf-ranges.txt"));
        assert_eq!(
            refreshed_ranges_v6_path().unwrap(),
            dir.join("cf-ranges-v6.txt")
        );
        assert_eq!(xray_binary_path().unwrap().parent().unwrap(), dir);
    }

    #[test]
    fn xray_binary_path_uses_platform_exe_name() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let expected = if cfg!(windows) { "xray.exe" } else { "xray" };
        assert_eq!(
            xray_binary_path()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn default_data_dir_is_absolute() {
        // Without the override, the directories fallback must still resolve
        // to something usable (exact path is platform/user dependent). The
        // env var is deliberately NOT touched: any test-set value is an
        // absolute temp dir, so the assertion holds regardless.
        let _guard = DATA_DIR_LOCK.blocking_lock();
        assert!(data_dir().unwrap().is_absolute());
    }
}
