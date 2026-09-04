use std::path::PathBuf;

use anyhow::{Result, anyhow};

use crate::api::types::ScanConfig;
use crate::paths;

const LAST_SCAN_FILE: &str = "last-scan.json";

fn last_scan_path() -> Result<PathBuf> {
    Ok(paths::data_dir()?.join(LAST_SCAN_FILE))
}

/// Persist a scan config for `--retry-last`. Phase-2 configs carry proxy
/// credentials, so the whole phase2 block is dropped before writing.
pub fn save_config(cfg: &ScanConfig) -> Result<()> {
    let mut sanitized = cfg.clone();
    sanitized.phase2 = None;
    let json = serde_json::to_string_pretty(&sanitized)?;
    let _guard = paths::data_write_guard();
    paths::write_secret(&last_scan_path()?, json.as_bytes())?;
    Ok(())
}

pub fn load_config() -> Result<ScanConfig> {
    let path = last_scan_path()?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow!("no retryable scan saved ({}: {e})", path.display()))?;
    let cfg: ScanConfig = serde_json::from_str(&raw)
        .map_err(|e| anyhow!("saved scan config is corrupt ({}: {e})", path.display()))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Phase2Config, ScanTarget};
    use crate::paths::test_env::{DATA_DIR_LOCK, IsolatedDataDir};

    fn sample() -> ScanConfig {
        ScanConfig {
            target: ScanTarget::Count(7),
            ..ScanConfig::default()
        }
    }

    #[test]
    fn save_then_load_round_trips_without_phase2() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let mut cfg = sample();
        cfg.target = ScanTarget::Count(1234);
        cfg.phase2 = Some(Phase2Config {
            configs: vec!["vless://secret@host:443".to_owned()],
            ..Default::default()
        });
        save_config(&cfg).unwrap();
        let loaded = load_config().unwrap();
        assert_eq!(loaded.target, ScanTarget::Count(1234));
        assert!(loaded.phase2.is_none(), "phase2 configs must not persist");
        let on_disk = std::fs::read_to_string(last_scan_path().unwrap()).unwrap();
        assert!(
            !on_disk.contains("secret"),
            "credentials must never hit disk"
        );
    }

    #[test]
    fn load_without_a_saved_config_names_the_fix() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let err = load_config().unwrap_err().to_string();
        assert!(err.contains("no retryable scan saved"), "{err}");
    }
}
