use anyhow::{Result, anyhow, bail};
use cf_scanner::api;
use cf_scanner::api::types::{
    CdnPreset, Mode, NetworkProfile, Port, ProbeMode, ScanConfig, ScanTarget, StopCondition,
};

use super::{ModeArg, ProbeArg, ScanArgs};

#[cfg(test)]
mod tests;

pub(crate) fn build_scan_config(args: &ScanArgs) -> Result<ScanConfig> {
    if args.retry_last {
        let mut cfg = cf_scanner::retry::load_config()?;
        let ignored = retry_ignored_flags(args);
        if !ignored.is_empty() {
            eprintln!(
                "warning: {} ignored with --retry-last; using saved scan config (only --phase2-configs, --warp-wgconf-file, --adaptive-retries, --network-profile apply)",
                ignored.join(", ")
            );
        }
        apply_retry_overrides(&mut cfg, args)?;
        if let Some(warning) = cap_warning_for_stop(cfg.stop.found, cfg.stop.cap) {
            eprintln!("warning: {warning}");
        }
        cfg.validate()
            .map_err(|e| anyhow!("saved scan config is no longer valid: {e}"))?;
        validate_export_needs_phase2(
            args.export.as_ref(),
            args.export_format,
            cfg.phase2.as_ref(),
        )?;
        return Ok(cfg);
    }
    validate_basic_flags(args)?;
    let mode = Mode::from(args.mode);
    validate_mode_flags(args)?;
    validate_warp_flags(args)?;
    let colo_filter: Vec<String> = args
        .colo
        .iter()
        .map(|c| c.trim().to_ascii_uppercase())
        .collect();
    if colo_filter.iter().any(|c| c.is_empty()) {
        return Err(anyhow!("--colo entries must be non-empty IATA codes"));
    }
    // Canonical rotation list: trimmed + lowercased (DNS is case-insensitive,
    // so Example.COM and example.com must not rotate as distinct names).
    // Empty (flag absent) means unset; the config default fills it below.
    let probe_snis: Vec<String> = args
        .probe_snis
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    validate_phase2_flags(args)?;
    if let Some(warning) = cap_warning(args) {
        eprintln!("warning: {warning}");
    }

    let target = match (args.preset, args.count) {
        (Some(preset), None) => ScanTarget::Preset(CdnPreset::from(preset)),
        (None, Some(count)) => ScanTarget::Count(count),
        (None, None) if mode == Mode::Warp => {
            ScanTarget::Count(cf_scanner::warp::bundled_pool().host_count() as u32)
        }
        (None, None) => ScanTarget::Preset(CdnPreset::Quick),
        _ => unreachable!("clap enforces preset/count exclusivity"),
    };
    let phase2 = build_phase2(args)?;
    let wgconf = match args.warp_wgconf_file.as_deref() {
        Some(path) => Some(load_wgconf_file(path)?),
        None => None,
    };
    // Restricted-network preset (spec §P0-7(b)). Unset = today's defaults.
    // A knob the user set explicitly (any non-default value, or any
    // --warp-probes at all) always wins over the preset.
    let network_profile = args.network_profile.map(NetworkProfile::from);
    let mut concurrency = args.concurrency;
    let mut timeout_ms = args.timeout_ms;
    let mut idle_hold_ms = args.idle_hold_ms;
    let mut probes_per_endpoint = args.warp_probes.unwrap_or(api::DEFAULT_PROBES_PER_ENDPOINT);
    apply_profile_tuning(
        &mode,
        network_profile,
        timeout_ms != api::types::DEFAULT_TIMEOUT_MS,
        concurrency != api::types::DEFAULT_CONCURRENCY,
        idle_hold_ms != 0,
        args.warp_probes.is_some(),
        &mut timeout_ms,
        &mut concurrency,
        &mut idle_hold_ms,
        &mut probes_per_endpoint,
    );
    let warp = (mode == Mode::Warp).then(|| api::types::WarpConfig {
        custom_endpoints: args.warp_endpoints.clone(),
        probes_per_endpoint,
        wgconf,
        verify_with_wgconf: args.warp_verify,
        junk_count: args.warp_junk_count.unwrap_or(0),
        junk_min: args.warp_junk_min.unwrap_or(0),
        junk_max: args.warp_junk_max.unwrap_or(0),
        port_gate: args.warp_port_gate,
        ports_explicit: args.ports.as_ref().is_some_and(|p| !p.is_empty()),
    });
    // Explicit --warp-probes always wins: the pre-flight must never lower
    // (or second-guess) a user-chosen budget, so it is switched off here
    // with a stderr note and the engine never sees the combination.
    let mut adaptive_retries = args.adaptive_retries;
    if let Some(probes) = args.warp_probes
        && adaptive_retries
    {
        eprintln!("note: {}", adaptive_skip_note(probes));
        adaptive_retries = false;
    }
    let cfg = ScanConfig {
        mode,
        target,
        ports: match args.ports.clone() {
            Some(ports) if !ports.is_empty() => ports.into_iter().map(Port::new).collect(),
            _ if args.mode == ModeArg::Warp => api::types::DEFAULT_WARP_PORTS.to_vec(),
            _ => vec![Port::new(api::types::DEFAULT_PORT)],
        },
        stop: StopCondition {
            found: args.target,
            cap: args.cap,
        },
        exclude: args.exclude.clone(),
        custom_cidrs: args.custom_cidrs.clone(),
        include_v6: args.ipv6,
        concurrency,
        timeout_ms,
        phase2,
        warp,
        loss_threshold: args.loss_threshold,
        min_latency_ms: args.min_latency,
        idle_hold_ms,
        colo_filter,
        probe_mode: ProbeMode::from(args.probe),
        accepted_http_codes: args
            .http_status_code
            .clone()
            .unwrap_or_else(api::types::default_accepted_http_codes),
        probe_snis: if probe_snis.is_empty() {
            api::types::default_probe_snis()
        } else {
            probe_snis
        },
        speed_test: args.speed_test,
        min_speed_mbps: args.min_speed,
        neighbor_count: args.neighbor_scan,
        adaptive_retries,
        network_profile,
    };
    cfg.validate()
        .map_err(|e| anyhow!("invalid scan config: {e}"))?;
    validate_export_needs_phase2(
        args.export.as_ref(),
        args.export_format,
        cfg.phase2.as_ref(),
    )?;
    Ok(cfg)
}

fn validate_basic_flags(args: &ScanArgs) -> Result<()> {
    if args.target == 0 {
        bail!("--target must be at least 1");
    }
    if let Some(0) = args.count {
        bail!("--count must be at least 1");
    }
    if args.cap.is_some_and(|cap| cap == 0) {
        bail!("--cap must be at least 1");
    }
    if args.loss_threshold.is_some_and(|t| t > 100) {
        bail!("--loss-threshold must be 0-100");
    }
    if args
        .min_latency
        .is_some_and(|t| t == 0 || t > api::types::MAX_MIN_LATENCY_MS)
    {
        bail!("--min-latency must be 1-{}", api::types::MAX_MIN_LATENCY_MS);
    }
    if args.idle_hold_ms > api::types::MAX_IDLE_HOLD_MS {
        bail!("--idle-hold-ms must be 0-{}", api::types::MAX_IDLE_HOLD_MS);
    }
    for code in args.http_status_code.iter().flatten() {
        if !(100..=599).contains(code) {
            bail!("--http-status-code entries must be 100-599, got {code}");
        }
    }
    if args
        .http_status_code
        .as_ref()
        .is_some_and(|codes| codes.is_empty())
    {
        bail!("--http-status-code needs at least one status code");
    }
    if args.neighbor_scan > api::types::MAX_NEIGHBORS {
        bail!("--neighbor-scan must be 0-{}", api::types::MAX_NEIGHBORS);
    }
    Ok(())
}

fn validate_mode_flags(args: &ScanArgs) -> Result<()> {
    let mode = args.mode;
    if mode == ModeArg::Warp && args.preset.is_some() {
        return Err(anyhow!("--preset is CDN-only; WARP uses --count"));
    }
    if mode == ModeArg::Warp && args.probe != ProbeArg::Tls {
        return Err(anyhow!(
            "--probe is CDN-only; WARP uses WireGuard handshake probes"
        ));
    }
    if mode == ModeArg::Warp && !args.probe_snis.is_empty() {
        return Err(anyhow!(
            "--probe-snis is CDN-only; WARP uses WireGuard handshake probes"
        ));
    }
    if mode == ModeArg::Cdn && args.http_status_code.is_some() && args.probe != ProbeArg::Http {
        return Err(anyhow!("--http-status-code requires --probe http"));
    }
    if mode == ModeArg::Cdn
        && !args.probe_snis.is_empty()
        && args.probe != ProbeArg::Tls
        && args.probe != ProbeArg::Http
    {
        return Err(anyhow!("--probe-snis requires --probe tls|http"));
    }
    if mode == ModeArg::Warp && args.ipv6 {
        return Err(anyhow!("--ipv6 is CDN-only; WARP pools are IPv4"));
    }
    if mode == ModeArg::Warp && args.neighbor_scan > 0 {
        return Err(anyhow!(
            "--neighbor-scan is CDN-only; neighbor probing does not apply to WARP"
        ));
    }
    if mode == ModeArg::Warp && !args.custom_cidrs.is_empty() {
        return Err(anyhow!(
            "--custom-cidrs is CDN-only; WARP takes --warp-endpoints"
        ));
    }
    if mode == ModeArg::Warp && !args.colo.is_empty() {
        return Err(anyhow!("--colo is CDN-only; WARP endpoints have no colo"));
    }
    Ok(())
}

fn validate_warp_flags(args: &ScanArgs) -> Result<()> {
    let mode = args.mode;
    if mode == ModeArg::Cdn && !args.warp_endpoints.is_empty() {
        return Err(anyhow!("--warp-endpoints require --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_verify {
        return Err(anyhow!("--warp-verify requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_wgconf_file.is_some() {
        return Err(anyhow!("--warp-wgconf-file requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_probes.is_some() {
        return Err(anyhow!("--warp-probes requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_junk_count.is_some() {
        return Err(anyhow!("--warp-junk-count requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_junk_min.is_some() {
        return Err(anyhow!("--warp-junk-min requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_junk_max.is_some() {
        return Err(anyhow!("--warp-junk-max requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.adaptive_retries {
        return Err(anyhow!("--adaptive-retries requires --mode warp"));
    }
    if mode == ModeArg::Cdn && args.warp_port_gate {
        return Err(anyhow!("--warp-port-gate requires --mode warp"));
    }
    Ok(())
}

/// stderr note emitted when an explicit `--warp-probes` disables the
/// adaptive pre-flight. Pure so the wording stays pinned by tests.
pub(crate) fn adaptive_skip_note(probes: u8) -> String {
    format!("--adaptive-retries skipped (explicit --warp-probes {probes} wins; pre-flight not run)")
}

/// `--network-profile` tuning presets (spec §P0-7(b)). Unset = today's
/// defaults; any knob the user set explicitly keeps its value.
pub(crate) const PROFILE_BLOCKED_CDN_TIMEOUT_MS: u64 = 5000;
pub(crate) const PROFILE_BLOCKED_CDN_IDLE_HOLD_MS: u64 = 2000;
pub(crate) const PROFILE_SLOW_TIMEOUT_MS: u64 = 8000;
pub(crate) const PROFILE_BLOCKED_WARP_PROBES: u8 = 5;
pub(crate) const PROFILE_SLOW_WARP_PROBES: u8 = 3;

/// Apply the preset to already-resolved knob values. The `*_explicit` flags
/// say whether the user set that knob (fresh path: non-default CLI value,
/// or any `--warp-probes`; retry path: non-default saved value); explicit
/// knobs are never overwritten.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_profile_tuning(
    mode: &Mode,
    profile: Option<NetworkProfile>,
    timeout_explicit: bool,
    concurrency_explicit: bool,
    idle_explicit: bool,
    probes_explicit: bool,
    timeout_ms: &mut u64,
    concurrency: &mut u16,
    idle_hold_ms: &mut u64,
    probes_per_endpoint: &mut u8,
) {
    match (mode, profile) {
        (Mode::Cdn, Some(NetworkProfile::Blocked)) => {
            if !timeout_explicit {
                *timeout_ms = PROFILE_BLOCKED_CDN_TIMEOUT_MS;
            }
            if !idle_explicit {
                *idle_hold_ms = PROFILE_BLOCKED_CDN_IDLE_HOLD_MS;
            }
        }
        (Mode::Cdn, Some(NetworkProfile::Slow)) => {
            if !timeout_explicit {
                *timeout_ms = PROFILE_SLOW_TIMEOUT_MS;
            }
            if !concurrency_explicit {
                *concurrency = (*concurrency / 2).max(1);
            }
        }
        (Mode::Warp, Some(NetworkProfile::Blocked)) => {
            if !probes_explicit {
                *probes_per_endpoint = PROFILE_BLOCKED_WARP_PROBES;
            }
        }
        (Mode::Warp, Some(NetworkProfile::Slow)) => {
            if !probes_explicit {
                *probes_per_endpoint = PROFILE_SLOW_WARP_PROBES;
            }
            if !timeout_explicit {
                *timeout_ms = PROFILE_SLOW_TIMEOUT_MS;
            }
        }
        _ => {}
    }
}

fn validate_phase2_flags(args: &ScanArgs) -> Result<()> {
    let mode = args.mode;
    if mode == ModeArg::Warp && !args.phase2_configs.is_empty() {
        return Err(anyhow!(
            "--phase2-configs is CDN-only; xray verification does not apply to WARP"
        ));
    }
    if args.speed_test && mode == ModeArg::Warp {
        return Err(anyhow!(
            "--speed-test is CDN-only; it requires --phase2-configs"
        ));
    }
    if args.min_speed.is_some() && !args.speed_test {
        return Err(anyhow!("--min-speed requires --speed-test"));
    }
    Ok(())
}

/// Fail fast when a bundle/sharelink export is requested without phase-2
/// (story 7): those formats re-render verified endpoints, so waiting through
/// a full scan only to learn phase-2 was missing wastes minutes. Only applies
/// when `--export` is set; `--export-format` without `--export` already fails
/// at clap parse time.
fn validate_export_needs_phase2(
    export: Option<&std::path::PathBuf>,
    format: cf_scanner::export::ExportFormatArg,
    phase2: Option<&api::types::Phase2Config>,
) -> Result<()> {
    if export.is_none() {
        return Ok(());
    }
    if format.requires_phase2() && phase2.is_none() {
        return Err(anyhow!(
            "--export-format {} requires --phase2-configs (bundle formats re-render verified endpoints); add --phase2-configs or use --export-format csv|json",
            format.name()
        ));
    }
    Ok(())
}

fn load_wgconf_file(path: &str) -> Result<String> {
    let read = || cf_scanner::wgconf::read_wgconf_file(path, "--warp-wgconf-file");
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(read)
    } else {
        read()
    }
}

fn build_phase2(args: &ScanArgs) -> Result<Option<api::types::Phase2Config>> {
    if args.phase2_configs.is_empty() {
        return Ok(None);
    }
    let fragment = args
        .phase2_fragment
        .map(api::types::FragmentPreset::from)
        .unwrap_or(api::types::FragmentPreset::Off);
    let custom_fragment = match args.phase2_custom.as_deref() {
        Some(values) => {
            let fields: Vec<&str> = values.split(',').collect();
            if fields.len() != 2 {
                bail!(
                    "--phase2-custom takes exactly two comma-separated fields \"length,interval\" (packets is always \"tlshello\"), got {} field(s): {values:?}",
                    fields.len()
                );
            }
            Some(api::types::CustomFragment {
                packets: "tlshello".to_owned(),
                length: fields[0].trim().to_owned(),
                interval: fields[1].trim().to_owned(),
            })
        }
        None => None,
    };
    if args.phase2_custom.is_some()
        && (args.phase2_configs.is_empty() || fragment != api::types::FragmentPreset::Custom)
    {
        return Err(anyhow!(
            "--phase2-custom requires --phase2-configs and --phase2-fragment custom"
        ));
    }
    if fragment == api::types::FragmentPreset::Custom && custom_fragment.is_none() {
        return Err(anyhow!(
            "--phase2-fragment custom requires --phase2-custom \"length,interval\""
        ));
    }
    let probe_urls = args.phase2_probe_urls.clone();
    Ok(Some(api::types::Phase2Config {
        configs: args.phase2_configs.clone(),
        fragment,
        custom_fragment,
        snis: args.phase2_snis.clone(),
        probe_url: api::types::DEFAULT_PROBE_URL.to_owned(),
        probe_urls,
        concurrency: args
            .phase2_concurrency
            .unwrap_or(api::DEFAULT_PHASE2_CONCURRENCY),
    }))
}

/// Apply the documented `--retry-last` override subset to a loaded config:
/// `--phase2-configs` (re-supplied keys are never persisted),
/// `--warp-wgconf-file`/`--warp-verify`, `--adaptive-retries`, and
/// `--network-profile`. Everything else in [`retry_ignored_flags`] keeps the
/// saved value. Pure apart from the wgconf file read and stderr notes.
pub(crate) fn apply_retry_overrides(cfg: &mut ScanConfig, args: &ScanArgs) -> Result<()> {
    if !args.phase2_configs.is_empty() {
        let mut phase2 = cfg.phase2.take().unwrap_or_default();
        phase2.configs = args.phase2_configs.clone();
        cfg.phase2 = Some(phase2);
    }
    if let Some(path) = args.warp_wgconf_file.as_deref() {
        let content = load_wgconf_file(path)?;
        match cfg.warp.as_mut() {
            Some(warp) => {
                warp.wgconf = Some(content);
                warp.verify_with_wgconf = args.warp_verify;
            }
            None => {
                eprintln!(
                    "warning: --warp-wgconf-file ignored with --retry-last; saved scan is not WARP mode"
                );
            }
        }
    } else if args.warp_verify {
        eprintln!("warning: --warp-verify ignored with --retry-last; re-supply --warp-wgconf-file");
    }
    if args.adaptive_retries {
        if cfg.mode != Mode::Warp {
            bail!("--adaptive-retries requires --mode warp");
        }
        cfg.adaptive_retries = true;
    }
    if let Some(probes) = args.warp_probes
        && cfg.adaptive_retries
    {
        eprintln!("note: {}", adaptive_skip_note(probes));
        cfg.adaptive_retries = false;
    }
    // A --network-profile on a retry relabels the config and retunes
    // whatever still sits at defaults; saved non-default values count as
    // explicit and survive, mirroring the fresh-scan explicit-wins rule.
    // Without the flag the saved profile (if any) simply persists.
    if let Some(profile) = args.network_profile.map(NetworkProfile::from) {
        cfg.network_profile = Some(profile);
        let mut probes = cfg
            .warp
            .as_ref()
            .map(|w| w.probes_per_endpoint)
            .unwrap_or(api::DEFAULT_PROBES_PER_ENDPOINT);
        apply_profile_tuning(
            &cfg.mode,
            Some(profile),
            cfg.timeout_ms != api::types::DEFAULT_TIMEOUT_MS,
            cfg.concurrency != api::types::DEFAULT_CONCURRENCY,
            cfg.idle_hold_ms != 0,
            probes != api::DEFAULT_PROBES_PER_ENDPOINT,
            &mut cfg.timeout_ms,
            &mut cfg.concurrency,
            &mut cfg.idle_hold_ms,
            &mut probes,
        );
        if let Some(warp) = cfg.warp.as_mut() {
            warp.probes_per_endpoint = probes;
        }
    }
    Ok(())
}

pub(crate) fn cap_warning(args: &ScanArgs) -> Option<String> {
    cap_warning_for_stop(args.target, args.cap)
}

pub(crate) fn cap_warning_for_stop(found: u32, cap: Option<u32>) -> Option<String> {
    let cap = cap?;
    (cap < found).then(|| {
        format!(
            "--cap ({cap}) is below --target ({found}); the scan stops at the cap and may find fewer than {found} working endpoints"
        )
    })
}

/// Scan flags that `--retry-last` ignores (spec story 8). Pure so tests pin
/// the set without capturing stderr. The documented override subset
/// (`--phase2-configs`, `--warp-wgconf-file`/`--warp-verify`,
/// `--adaptive-retries`, `--network-profile`) plus run-time flags that still
/// apply (`--seed`, `--export`, `--export-live`, `--export-format`,
/// `--enrich-asn`) are intentionally absent: everything else reuses the saved
/// config and must warn.
pub(crate) fn retry_ignored_flags(args: &ScanArgs) -> Vec<&'static str> {
    let mut ignored = Vec::new();
    if args.mode != super::ModeArg::Cdn {
        ignored.push("--mode");
    }
    if args.preset.is_some() {
        ignored.push("--preset");
    }
    if args.count.is_some() {
        ignored.push("--count");
    }
    if args.target != 20 {
        ignored.push("--target");
    }
    if args.cap.is_some() {
        ignored.push("--cap");
    }
    if args.ports.as_ref().is_some_and(|p| !p.is_empty()) {
        ignored.push("--ports");
    }
    if args.concurrency != api::types::DEFAULT_CONCURRENCY {
        ignored.push("--concurrency");
    }
    if args.timeout_ms != api::types::DEFAULT_TIMEOUT_MS {
        ignored.push("--timeout-ms");
    }
    if args.loss_threshold.is_some() {
        ignored.push("--loss-threshold");
    }
    if args.min_latency.is_some() {
        ignored.push("--min-latency");
    }
    if args.idle_hold_ms != 0 {
        ignored.push("--idle-hold-ms");
    }
    if args.probe != super::ProbeArg::Tls {
        ignored.push("--probe");
    }
    if args.http_status_code.is_some() {
        ignored.push("--http-status-code");
    }
    if !args.probe_snis.is_empty() {
        ignored.push("--probe-snis");
    }
    if args.neighbor_scan != 0 {
        ignored.push("--neighbor-scan");
    }
    if !args.exclude.is_empty() {
        ignored.push("--exclude");
    }
    if !args.custom_cidrs.is_empty() {
        ignored.push("--custom-cidrs");
    }
    if !args.colo.is_empty() {
        ignored.push("--colo");
    }
    if args.ipv6 {
        ignored.push("--ipv6");
    }
    if args.phase2_fragment.is_some() {
        ignored.push("--phase2-fragment");
    }
    if args.phase2_custom.is_some() {
        ignored.push("--phase2-custom");
    }
    if !args.phase2_snis.is_empty() {
        ignored.push("--phase2-snis");
    }
    if !args.phase2_probe_urls.is_empty() {
        ignored.push("--phase2-probe-urls");
    }
    if args
        .phase2_concurrency
        .is_some_and(|v| v != api::DEFAULT_PHASE2_CONCURRENCY)
    {
        ignored.push("--phase2-concurrency");
    }
    if args.speed_test {
        ignored.push("--speed-test");
    }
    if args.min_speed.is_some() {
        ignored.push("--min-speed");
    }
    if args.warp_probes.is_some() {
        ignored.push("--warp-probes");
    }
    if !args.warp_endpoints.is_empty() {
        ignored.push("--warp-endpoints");
    }
    if args.warp_junk_count.is_some() {
        ignored.push("--warp-junk-count");
    }
    if args.warp_junk_min.is_some() {
        ignored.push("--warp-junk-min");
    }
    if args.warp_junk_max.is_some() {
        ignored.push("--warp-junk-max");
    }
    if args.warp_port_gate {
        ignored.push("--warp-port-gate");
    }
    ignored
}
