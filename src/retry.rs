use std::path::PathBuf;

use anyhow::{Result, anyhow};

use crate::api::types::ScanConfig;
use crate::paths;

const LAST_SCAN_FILE: &str = "last-scan.json";

fn last_scan_path() -> Result<PathBuf> {
    Ok(paths::data_dir()?.join(LAST_SCAN_FILE))
}

/// Persist a scan config for `--retry-last`. Phase-2 configs carry proxy
/// credentials and `warp.wgconf` carries the WireGuard private key, so both
/// are dropped before writing (a retry with verify-on but no key would fail
/// validation; re-supply keys via flags).
pub fn save_config(cfg: &ScanConfig) -> Result<()> {
    let mut sanitized = cfg.clone();
    sanitized.phase2 = None;
    if let Some(warp) = sanitized.warp.as_mut() {
        warp.wgconf = None;
        warp.verify_with_wgconf = false;
    }
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
    cfg.validate().map_err(|e| {
        anyhow!(
            "saved scan config is invalid ({}: {e}) — re-run the scan",
            path.display()
        )
    })?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Mode, Phase2Config, Port, ScanTarget, WarpConfig};
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
    fn save_strips_warp_private_key() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let mut cfg = sample();
        cfg.mode = Mode::Warp;
        cfg.ports = vec![Port::new(2408)];
        cfg.warp = Some(WarpConfig {
            wgconf: Some("[Interface]\nPrivateKey = SUPERSECRETACTUALKEY1234567890=\n".to_owned()),
            verify_with_wgconf: true,
            ..Default::default()
        });
        save_config(&cfg).unwrap();
        let loaded = load_config().unwrap();
        let warp = loaded.warp.expect("warp block itself must persist");
        assert!(warp.wgconf.is_none(), "WARP keys must never be saved");
        assert!(
            !warp.verify_with_wgconf,
            "verify flag must reset when the key is stripped"
        );
        let on_disk = std::fs::read_to_string(last_scan_path().unwrap()).unwrap();
        assert!(
            !on_disk.contains("SUPERSECRETACTUALKEY"),
            "private key must never hit disk"
        );
    }

    fn warp_sample() -> ScanConfig {
        let mut cfg = sample();
        cfg.mode = Mode::Warp;
        cfg.ports = vec![Port::new(2408)];
        cfg.warp = Some(WarpConfig {
            wgconf: Some("[Interface]\nPrivateKey = K\n".to_owned()),
            verify_with_wgconf: true,
            ..Default::default()
        });
        cfg
    }

    #[test]
    fn load_tolerates_old_shape_without_newer_fields() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let mut v = serde_json::to_value(warp_sample()).unwrap();
        v.as_object_mut().unwrap().remove("neighbor_count");
        v["warp"]
            .as_object_mut()
            .unwrap()
            .remove("verify_with_wgconf");
        std::fs::write(
            last_scan_path().unwrap(),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        let loaded = load_config().unwrap();
        let warp = loaded.warp.expect("warp block must survive");
        assert!(!warp.verify_with_wgconf, "new flags default off");
        assert_eq!(loaded.neighbor_count, 0, "new scalars default");
        assert!(warp.wgconf.is_some(), "present keys must survive");
    }

    #[test]
    fn load_ignores_unknown_top_level_keys_but_not_nested_ones() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let mut v = serde_json::to_value(warp_sample()).unwrap();
        v["future_flag"] = serde_json::Value::Bool(true);
        std::fs::write(
            last_scan_path().unwrap(),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        load_config().expect("unknown top-level keys must be ignored");
        v["warp"]["future_nested"] = serde_json::Value::Bool(true);
        std::fs::write(
            last_scan_path().unwrap(),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
        load_config().expect_err("nested strictness must be preserved");
    }

    #[test]
    fn load_rejects_well_typed_but_invalid_config() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        save_config(&sample()).unwrap();
        let path = last_scan_path().unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("concurrency"), "precondition");
        let tampered = raw.replace("\"concurrency\": 64", "\"concurrency\": 0");
        assert_ne!(tampered, raw, "precondition: concurrency field present");
        std::fs::write(&path, tampered).unwrap();
        let err = load_config().unwrap_err().to_string();
        assert!(
            err.contains("invalid") && err.contains("re-run"),
            "must name the fix, got: {err}"
        );
    }

    #[test]
    fn load_without_a_saved_config_names_the_fix() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let err = load_config().unwrap_err().to_string();
        assert!(err.contains("no retryable scan saved"), "{err}");
    }

    #[test]
    fn load_without_any_saved_file_names_the_expected_path() {
        let _guard = crate::paths::test_env::DATA_DIR_LOCK.blocking_lock();
        let _isolated = crate::paths::test_env::IsolatedDataDir::new();
        let err = load_config().unwrap_err().to_string();
        assert!(err.contains("no retryable scan saved"), "{err}");
        assert!(err.contains("last-scan.json"), "{err}");
    }

    #[test]
    fn corrupt_saved_config_fails_with_a_corrupt_error_not_a_panic() {
        let _guard = crate::paths::test_env::DATA_DIR_LOCK.blocking_lock();
        let _isolated = crate::paths::test_env::IsolatedDataDir::new();
        let path = last_scan_path().unwrap();
        std::fs::write(&path, b"{ not json !!!").unwrap();
        let err = load_config().unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn concurrent_saves_serialize_and_keep_the_file_valid() {
        let _guard = crate::paths::test_env::DATA_DIR_LOCK.blocking_lock();
        let _isolated = crate::paths::test_env::IsolatedDataDir::new();
        let cfg = sample();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let mut cfg = cfg.clone();
                cfg.concurrency = 100 + i as u16;
                std::thread::spawn(move || save_config(&cfg).unwrap())
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // The file must be valid JSON (no interleaved torn writes).
        let cfg = load_config().unwrap();
        assert!((100..=107).contains(&cfg.concurrency));
    }
}
