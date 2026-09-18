//! Bounded setting search for the `tune` subcommand: try candidate values
//! head-to-head over small fixed samples and print a reusable scan command.
//!
//! The async driver (in the CLI) runs one fresh engine per value at a fixed
//! seed, so every value sees the same sample and no verdicts leak between
//! steps or into the last-scan store. Everything in this module is pure and
//! offline-testable: thresholds, config patchers, command renderers.

use crate::api::types::{FragmentPreset, Phase2Config, ScanConfig, WarpConfig};

/// Fixed seed for every tune step: identical samples make values comparable.
pub const TUNE_SEED: u64 = 7;
/// Junk datagram sizes while tuning counts (warpscout `-jmin`/`-jmax`
/// reference defaults); the count ladder is what varies.
pub const JUNK_TUNE_SIZES: (u16, u16) = (10, 50);
/// Upper bound on values tried in one tune run (cost stays user-visible).
pub const MAX_TUNE_VALUES: usize = 8;

/// Default junk-count ladder: cheap-to-heavy spread under the 128 cap.
pub fn default_junk_counts() -> Vec<u8> {
    vec![8, 32, 64]
}

/// Fragment presets in the order the tuner tries them.
pub fn fragment_ladder() -> Vec<FragmentPreset> {
    vec![
        FragmentPreset::Light,
        FragmentPreset::Medium,
        FragmentPreset::Heavy,
    ]
}

/// First step whose working count meets an absolute need.
pub fn first_meeting(working: &[u64], need: u64) -> Option<usize> {
    working.iter().position(|&w| w >= need)
}

/// First step whose working share meets a percentage threshold.
/// A step with zero scanned never qualifies, however low the bar.
pub fn first_meeting_pct(results: &[(u64, u64)], pct: u32) -> Option<usize> {
    results
        .iter()
        .position(|&(working, scanned)| scanned > 0 && working * 100 >= u64::from(pct) * scanned)
}

/// Best step so far (first maximum wins ties): the below-threshold fallback.
pub fn best_so_far(working: &[u64]) -> Option<usize> {
    working
        .iter()
        .enumerate()
        .max_by_key(|&(i, &w)| (w, std::cmp::Reverse(i)))
        .map(|(i, _)| i)
}

/// Upper-bound probe budget for the up-front cost line (concurrency makes
/// real time lower; this is the spend ceiling, not an estimate).
pub fn estimate_budget_ms(steps: usize, per_step: u32, timeout_ms: u64) -> u64 {
    steps as u64 * u64::from(per_step) * timeout_ms
}

/// Tune-step config builders: each sets exactly one knob on a base scan
/// config, leaving every other default in place. Builder style (owned
/// in/out) so call sites never default-then-assign field by field.
pub fn with_junk(cfg: ScanConfig, count: u8) -> ScanConfig {
    ScanConfig {
        warp: Some(WarpConfig {
            junk_count: count,
            junk_min: JUNK_TUNE_SIZES.0,
            junk_max: JUNK_TUNE_SIZES.1,
            ..Default::default()
        }),
        ..cfg
    }
}

pub fn with_probe_snis(cfg: ScanConfig, snis: Vec<String>) -> ScanConfig {
    ScanConfig {
        probe_snis: snis,
        ..cfg
    }
}

pub fn with_fragment(cfg: ScanConfig, config_uri: &str, preset: FragmentPreset) -> ScanConfig {
    ScanConfig {
        phase2: Some(Phase2Config {
            configs: vec![config_uri.to_owned()],
            fragment: preset,
            ..Default::default()
        }),
        ..cfg
    }
}

/// Reusable scan commands printed to stdout (copy-pasteable; the caller's own
/// keys stay in their own terminal — stdout is the artifact here).
pub fn junk_command(count: u8, candidates: u32) -> String {
    format!(
        "cf-scanner scan --mode warp --count {candidates} --warp-junk-count {count} --warp-junk-min {} --warp-junk-max {}",
        JUNK_TUNE_SIZES.0, JUNK_TUNE_SIZES.1
    )
}

pub fn sni_command(sni: &str) -> String {
    format!("cf-scanner scan --mode cdn --probe-snis {sni}")
}

pub fn fragment_command(config_uri: &str, preset: FragmentPreset) -> String {
    format!("cf-scanner scan --mode cdn --phase2-configs {config_uri} --phase2-fragment {preset}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_pick_first_winner_and_handle_empties() {
        assert_eq!(first_meeting(&[1, 3, 5], 3), Some(1));
        assert_eq!(first_meeting(&[1, 2], 3), None);
        assert_eq!(first_meeting(&[], 1), None);
        let results = [(10, 50), (15, 50), (5, 50)];
        assert_eq!(first_meeting_pct(&results, 30), Some(1));
        assert_eq!(first_meeting_pct(&results, 90), None);
        assert_eq!(first_meeting_pct(&[(0, 0)], 1), None);
        assert_eq!(first_meeting_pct(&[], 30), None);
    }

    #[test]
    fn best_so_far_prefers_first_maximum() {
        assert_eq!(best_so_far(&[1, 5, 5, 2]), Some(1));
        assert_eq!(best_so_far(&[]), None);
    }

    #[test]
    fn budget_is_steps_times_sample_times_timeout() {
        assert_eq!(estimate_budget_ms(4, 50, 3000), 600_000);
        assert_eq!(estimate_budget_ms(0, 50, 3000), 0);
    }

    #[test]
    fn builders_set_exactly_one_knob() {
        let cfg = with_junk(ScanConfig::default(), 32);
        let warp = cfg.warp.as_ref().expect("junk patch sets warp");
        assert_eq!(
            (warp.junk_count, warp.junk_min, warp.junk_max),
            (32, 10, 50)
        );
        assert_eq!(cfg.probe_snis, crate::api::types::default_probe_snis());

        let cfg = with_probe_snis(ScanConfig::default(), vec!["a.example.com".to_owned()]);
        assert_eq!(cfg.probe_snis, vec!["a.example.com".to_owned()]);
        assert!(cfg.warp.is_none() && cfg.phase2.is_none());

        let cfg = with_fragment(
            ScanConfig::default(),
            "vless://x@y:443",
            FragmentPreset::Medium,
        );
        let phase2 = cfg.phase2.as_ref().expect("fragment patch sets phase2");
        assert_eq!(phase2.fragment, FragmentPreset::Medium);
        assert_eq!(phase2.configs, vec!["vless://x@y:443".to_owned()]);
    }

    #[test]
    fn commands_carry_the_winning_values() {
        assert!(junk_command(32, 50).contains("--warp-junk-count 32"));
        assert!(sni_command("a.example.com").contains("--probe-snis a.example.com"));
        let cmd = fragment_command("vless://x@y:443", FragmentPreset::Heavy);
        assert!(cmd.contains("--phase2-fragment heavy"), "{cmd}");
    }

    #[test]
    fn ladders_stay_within_enforced_caps() {
        for count in default_junk_counts() {
            assert!((1..=128).contains(&count), "{count} exceeds the junk cap");
        }
        assert!(fragment_ladder().len() == 3);
    }
}
