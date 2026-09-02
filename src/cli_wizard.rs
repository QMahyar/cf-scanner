use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::api::types::{
    self, CdnPreset, CustomFragment, DEFAULT_CONCURRENCY, DEFAULT_PORT, DEFAULT_PROBE_URL,
    DEFAULT_TIMEOUT_MS, DEFAULT_WARP_PORTS, FragmentPreset, MAX_CIDRS, MAX_CONFIG_ENTRY_BYTES,
    MAX_ENDPOINTS, MAX_PHASE2_ENTRIES, MAX_PROBE_URL_BYTES, MAX_SCAN_COUNT, MAX_SNI_BYTES,
    MAX_STOP_VALUE, MAX_WGCONF_BYTES, Mode, Phase2Config, Port, ScanConfig, ScanEvent, ScanSummary,
    ScanTarget, StopCondition, WarpConfig, parse_cidr, parse_endpoint, validate_fragment,
    validate_sni,
};
use crate::engine::ScanController;
use crate::warp;
use crate::warpgen;
use anyhow::{Context as _, Result, anyhow, bail};
use dialoguer::{Confirm, Input, Select};

fn prompt_warp() -> Result<ScanConfig> {
    let all_pools = u32::try_from(warp::bundled_pool().host_count())
        .unwrap_or(MAX_SCAN_COUNT)
        .min(MAX_SCAN_COUNT);
    let count: u32 = Input::new()
        .with_prompt(format!(
            "Candidate endpoints (1-{all_pools}; {all_pools} = all pools)"
        ))
        .validate_with(move |n: &u32| {
            (1..=all_pools)
                .contains(n)
                .then_some(())
                .ok_or_else(|| format!("must be 1-{all_pools}"))
        })
        .default(all_pools)
        .interact()?;
    let warp_ports = DEFAULT_WARP_PORTS
        .iter()
        .map(|p| p.get().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let ports = parse_ports(
        &Input::new()
            .with_prompt("UDP ports (comma-separated)")
            .default(warp_ports)
            .validate_with(|s: &String| parse_ports(s).map(|_| ()).map_err(|e| e.to_string()))
            .interact()?,
    )?;
    let found: u32 = Input::new()
        .with_prompt("Stop after N working endpoints")
        .validate_with(validate_stop_value)
        .default(20)
        .interact()?;
    let probes: u8 = Input::new()
        .with_prompt("Handshake probes per endpoint (1-10; higher = stricter 'working' — any dropped probe excludes the endpoint)")
        .validate_with(|n: &u8| (1..=10).contains(n).then_some(()).ok_or("must be 1-10"))
        .default(3)
        .interact()?;
    let custom =
        parse_list("Custom endpoints ip or ip:port (comma-separated; empty = bundled pools)")?;
    check_entries(
        &custom,
        MAX_ENDPOINTS,
        "custom endpoints",
        MAX_CONFIG_ENTRY_BYTES,
    )?;
    for endpoint in &custom {
        check_endpoint(endpoint)?;
    }
    let verify = Confirm::new()
        .with_prompt("Verify with your own wgconf (real keypair handshake)?")
        .default(false)
        .interact()?;
    let wgconf = if verify {
        let path: String = Input::new()
            .with_prompt("Path to a wg-quick / AmneziaWG config file")
            .interact()?;
        {
            use std::io::Read as _;
            let file =
                std::fs::File::open(&path).map_err(|e| anyhow!("could not read wgconf: {e}"))?;
            let mut buf = String::new();
            file.take(MAX_WGCONF_BYTES as u64 + 1)
                .read_to_string(&mut buf)
                .map_err(|e| anyhow!("could not read wgconf: {e}"))?;
            if buf.len() > MAX_WGCONF_BYTES {
                bail!("wgconf exceeds {MAX_WGCONF_BYTES} bytes");
            }
            Some(buf)
        }
    } else {
        None
    };
    let concurrency: u16 = Input::new()
        .with_prompt("Parallel probes (1-1000)")
        .validate_with(|n: &u16| (1..=1000).contains(n).then_some(()).ok_or("must be 1-1000"))
        .default(DEFAULT_CONCURRENCY)
        .interact()?;
    let timeout_ms: u64 = Input::new()
        .with_prompt("Probe timeout in ms (100-30000)")
        .validate_with(|n: &u64| {
            (100..=30_000)
                .contains(n)
                .then_some(())
                .ok_or("must be 100-30000")
        })
        .default(DEFAULT_TIMEOUT_MS)
        .interact()?;

    let cfg = ScanConfig {
        mode: Mode::Warp,
        target: ScanTarget::Count(count),
        ports,
        stop: StopCondition { found, cap: None },
        warp: Some(WarpConfig {
            custom_endpoints: custom,
            probes_per_endpoint: probes,
            wgconf,
            verify_with_wgconf: verify,
        }),
        concurrency,
        timeout_ms,
        ..ScanConfig::default()
    };
    cfg.validate().map_err(|e| anyhow!("invalid input: {e}"))?;
    Ok(cfg)
}

#[derive(Debug, thiserror::Error)]
#[error("interrupted")]
pub struct WizardInterrupted;

pub async fn run(controller: Arc<ScanController>) -> Result<()> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let ctrl_c = spawn_ctrl_c_listener(&controller, &interrupted);
    let result = run_wizard(controller, &interrupted).await;
    ctrl_c.abort();
    match result {
        Err(err) if is_user_exit(&err) => {
            if is_terminal_unusable(&err) {
                eprintln!("wizard needs an interactive terminal - exiting");
            }
            Err(WizardInterrupted.into())
        }
        other => other,
    }
}

fn spawn_ctrl_c_listener(
    controller: &Arc<ScanController>,
    interrupted: &Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let controller = controller.clone();
    let interrupted = interrupted.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                interrupted.store(true, Ordering::Relaxed);
                controller.cancel();
            }
            Err(err) => tracing::error!("could not listen for Ctrl+C: {err}"),
        }
    })
}

async fn run_wizard(controller: Arc<ScanController>, interrupted: &AtomicBool) -> Result<()> {
    eprintln!("CF-Scanner wizard — CDN/proxy scan with optional xray phase-2 verification");
    loop {
        let cfg = tokio::task::spawn_blocking(prompt_config)
            .await
            .map_err(|e| anyhow!("wizard task failed: {e}"))??;
        if interrupted.load(Ordering::Relaxed) {
            return Err(WizardInterrupted.into());
        }
        eprintln!();
        for line in config_recap(&cfg) {
            eprintln!("{line}");
        }
        let confirmed = tokio::task::spawn_blocking(|| {
            Confirm::new()
                .with_prompt("Start scan now?")
                .default(true)
                .interact()
        })
        .await
        .map_err(|e| anyhow!("wizard task failed: {e}"))??;
        if interrupted.load(Ordering::Relaxed) {
            return Err(WizardInterrupted.into());
        }
        if !confirmed {
            eprintln!("aborted");
            return Ok(());
        }
        let summary = run_scan(&controller, &cfg).await?;
        eprintln!(
            "done — scanned {}, found {} working in {} ms",
            summary.scanned, summary.found, summary.duration_ms
        );
        if summary.cancelled {
            eprintln!("cancelled — {} working endpoints retained", summary.found);
            return Ok(());
        }
        if interrupted.load(Ordering::Relaxed) {
            return Err(WizardInterrupted.into());
        }
        if cfg.mode == Mode::Warp {
            prompt_registration(&controller).await?;
        }
        let again = tokio::task::spawn_blocking(|| {
            Confirm::new()
                .with_prompt("Run another scan?")
                .default(false)
                .interact()
        })
        .await
        .map_err(|e| anyhow!("wizard task failed: {e}"))??;
        if interrupted.load(Ordering::Relaxed) || !again {
            return Ok(());
        }
    }
}

async fn run_scan(controller: &Arc<ScanController>, cfg: &ScanConfig) -> Result<ScanSummary> {
    controller
        .run_streaming(cfg.clone(), |e| match e {
            ScanEvent::Progress(p) => {
                let total = p.total.map(|t| format!(" / {t}")).unwrap_or_default();
                let (scanned, found) = (p.scanned, p.found);
                eprint!("\r\x1b[Kchecked {scanned}{total} — {found} working");
            }
            ScanEvent::Result(v) => {
                let phase2 = match &v.phase2 {
                    Some(p) if p.passed => format!("\t[phase2 ✓ {} {}]", p.fragment, p.sni),
                    Some(_) => "\t[phase2 ✗]".to_owned(),
                    None => String::new(),
                };
                use std::io::Write as _;
                let mut err = std::io::stderr().lock();
                let _ = writeln!(
                    err,
                    "\r\x1b[K{}\t{}ms{}",
                    v.ip,
                    v.latency_ms.unwrap_or(0),
                    phase2
                );
            }
            ScanEvent::Finished(_) => eprint!("\r\x1b[K"),
            ScanEvent::Phase2Progress(p) => {
                eprint!("\r\x1b[Kphase 2: {}/{} verified", p.done, p.total);
            }
            ScanEvent::Failed(payload) => {
                eprint!("\r\x1b[K");
                eprintln!("scan failed: {}", payload.reason);
            }
        })
        .await
        .map_err(|e| anyhow!("scan failed: {e:#}"))
}

async fn prompt_registration(controller: &ScanController) -> Result<()> {
    let proceed = tokio::task::spawn_blocking(|| {
        Confirm::new()
            .with_prompt(
                "Generate a WARP config (opt-in v0a884 registration via api.cloudflareclient.com)?",
            )
            .default(false)
            .interact()
    })
    .await
    .map_err(|e| anyhow!("wizard task failed: {e}"))??;
    if !proceed {
        return Ok(());
    }
    let best = controller
        .results()
        .into_iter()
        .min_by_key(|v| v.latency_ms.unwrap_or(u32::MAX))
        .map(|v| match v.ip {
            std::net::IpAddr::V6(_) => format!("[{}]:{}", v.ip, v.port),
            _ => format!("{}:{}", v.ip, v.port),
        });
    if let Some(endpoint) = &best {
        eprintln!("best scan result: {endpoint} — will be the WireGuard endpoint");
    }
    let (license, out) = tokio::task::spawn_blocking(|| -> dialoguer::Result<(String, String)> {
        let license: String = Input::new()
            .with_prompt("WARP+ license key (empty = free account)")
            .allow_empty(true)
            .interact()?;
        let out: String = Input::new()
            .with_prompt("Output path (empty = print to stdout)")
            .allow_empty(true)
            .interact()?;
        Ok((license, out))
    })
    .await
    .map_err(|e| anyhow!("wizard task failed: {e}"))??;
    let out = if out.trim().is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(out.trim()))
    };
    let license = (!license.trim().is_empty()).then_some(license.trim().to_owned());
    warpgen::generate(out.as_deref(), license.as_deref(), best.as_deref())
        .await
        .context("registration failed")?;
    match out {
        Some(path) => eprintln!("wgconf written to {}", path.display()),
        None => eprintln!("wgconf printed above"),
    }
    eprintln!(
        "tip: verify it with `cf-scanner scan --mode warp --warp-verify --warp-wgconf-file <saved>`"
    );
    Ok(())
}

fn dialoguer_io_kind(err: &anyhow::Error) -> Option<std::io::ErrorKind> {
    err.chain().find_map(|cause| {
        cause.downcast_ref::<dialoguer::Error>().map(|e| match e {
            dialoguer::Error::IO(io) => io.kind(),
        })
    })
}

fn is_user_exit(err: &anyhow::Error) -> bool {
    matches!(
        dialoguer_io_kind(err),
        Some(
            std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
        )
    )
}

fn is_terminal_unusable(err: &anyhow::Error) -> bool {
    matches!(
        dialoguer_io_kind(err),
        Some(std::io::ErrorKind::UnexpectedEof) | Some(std::io::ErrorKind::NotConnected)
    )
}

fn prompt_config() -> Result<ScanConfig> {
    if Select::new()
        .with_prompt("Mode")
        .item("CDN / proxy (phase 1)")
        .item("WARP")
        .default(0)
        .interact()?
        == 1
    {
        return prompt_warp();
    }

    let preset = Select::new()
        .with_prompt("Candidate target")
        .item("Preset Quick — 1 random IP per /24 (~4K probes)")
        .item("Preset Normal — 3 IPs per /24 (~12K probes)")
        .item("Preset Full — every bundled IP (~1.5M probes)")
        .item("Custom count")
        .default(0)
        .interact()?;
    let target = match preset {
        3 => {
            let count: u32 = Input::new()
                .with_prompt(format!("Candidate count (1-{MAX_SCAN_COUNT})"))
                .validate_with(|n: &u32| {
                    (1..=MAX_SCAN_COUNT)
                        .contains(n)
                        .then_some(())
                        .ok_or("must be 1-100000")
                })
                .default(350)
                .interact()?;
            ScanTarget::Count(count)
        }
        1 => ScanTarget::Preset(CdnPreset::Normal),
        2 => ScanTarget::Preset(CdnPreset::Full),
        _ => ScanTarget::Preset(CdnPreset::Quick),
    };

    let ports = parse_ports(
        &Input::new()
            .with_prompt("Ports (comma-separated)")
            .default(DEFAULT_PORT.to_string())
            .validate_with(|s: &String| parse_ports(s).map(|_| ()).map_err(|e| e.to_string()))
            .interact()?,
    )?;

    let found: u32 = Input::new()
        .with_prompt("Stop after N working endpoints")
        .validate_with(validate_stop_value)
        .default(20)
        .interact()?;
    let cap_raw: String = Input::new()
        .with_prompt("Hard probe cap (empty = none)")
        .allow_empty(true)
        .validate_with(|s: &String| parse_cap(s).map(|_| ()))
        .interact()?;
    let cap = parse_cap(&cap_raw).map_err(|e| anyhow!("{e}"))?;

    let concurrency: u16 = Input::new()
        .with_prompt("Parallel probes (1-1000)")
        .validate_with(|n: &u16| (1..=1000).contains(n).then_some(()).ok_or("must be 1-1000"))
        .default(DEFAULT_CONCURRENCY)
        .interact()?;
    let timeout_ms: u64 = Input::new()
        .with_prompt("Probe timeout in ms (100-30000)")
        .validate_with(|n: &u64| {
            (100..=30_000)
                .contains(n)
                .then_some(())
                .ok_or("must be 100-30000")
        })
        .default(DEFAULT_TIMEOUT_MS)
        .interact()?;

    let custom_cidrs = parse_cidr_list(
        "Custom CIDRs (comma-separated, replaces bundled ranges; empty = bundled)",
    )?;
    check_entries(
        &custom_cidrs,
        MAX_CIDRS,
        "custom CIDRs",
        MAX_CONFIG_ENTRY_BYTES,
    )?;
    for cidr in &custom_cidrs {
        check_cidr(cidr, true)?;
    }
    let exclude = parse_cidr_list("Excluded CIDRs (comma-separated; empty = none)")?;
    check_entries(
        &exclude,
        MAX_CIDRS,
        "excluded CIDRs",
        MAX_CONFIG_ENTRY_BYTES,
    )?;
    for cidr in &exclude {
        check_cidr(cidr, false)?;
    }

    let phase2 = if Confirm::new()
        .with_prompt("Verify candidates through xray (phase 2)?")
        .default(false)
        .interact()?
    {
        Some(prompt_phase2()?)
    } else {
        None
    };
    if phase2.is_some() && crate::verify::require_xray_binary().is_err() {
        eprintln!(
            "note: xray binary not found yet - it will be downloaded (checksum-verified) when phase 2 starts"
        );
    }

    let cfg = ScanConfig {
        mode: Mode::Cdn,
        target,
        ports,
        stop: StopCondition { found, cap },
        exclude,
        custom_cidrs,
        concurrency,
        timeout_ms,
        phase2,
        ..ScanConfig::default()
    };
    cfg.validate().map_err(|e| anyhow!("invalid input: {e}"))?;
    Ok(cfg)
}

fn prompt_phase2() -> Result<Phase2Config> {
    let configs = parse_list(
        "Configs (vless/trojan/vmess/ss URIs, subscription URLs, or xray JSON paths; comma-separated)",
    )?;
    check_entries(
        &configs,
        MAX_PHASE2_ENTRIES,
        "phase2 configs",
        MAX_CONFIG_ENTRY_BYTES,
    )?;
    if configs.is_empty() {
        return Err(anyhow!("at least one config required for phase 2"));
    }

    let fragment = match Select::new()
        .with_prompt("Fragment preset")
        .item("Off")
        .item("Light (100-200 bytes / 10-20 ms)")
        .item("Medium (50-200 bytes / 10-40 ms)")
        .item("Heavy (10-300 bytes / 5-50 ms)")
        .item("Custom")
        .default(0)
        .interact()?
    {
        1 => FragmentPreset::Light,
        2 => FragmentPreset::Medium,
        3 => FragmentPreset::Heavy,
        4 => FragmentPreset::Custom,
        _ => FragmentPreset::Off,
    };
    let custom_fragment = if fragment == FragmentPreset::Custom {
        let values: String = Input::new()
            .with_prompt("Custom fragment \"length,interval\" (e.g. 100-200,10-20)")
            .validate_with(|s: &String| {
                s.split_once(',')
                    .map(|_| ())
                    .ok_or("must be \"length,interval\"")
            })
            .interact()?;
        let parsed = parse_custom_fragment(&values)?;
        validate_fragment(&parsed).map_err(|e| anyhow!("{e}"))?;
        Some(parsed)
    } else {
        None
    };

    let snis =
        parse_list("SNI fronting variants (comma-separated; empty = each config's own SNI)")?;
    check_entries(&snis, MAX_PHASE2_ENTRIES, "SNI entries", MAX_SNI_BYTES)?;
    for sni in &snis {
        validate_sni(sni).map_err(|e| anyhow!("{e}"))?;
    }
    let probe_url: String = Input::new()
        .with_prompt("Probe URL fetched through the tunnel")
        .default(DEFAULT_PROBE_URL.to_owned())
        .validate_with(|s: &String| {
            (s.len() <= MAX_PROBE_URL_BYTES && s.starts_with("https://"))
                .then_some(())
                .ok_or("must be an https:// URL")
        })
        .interact()?;
    let concurrency: u8 = Input::new()
        .with_prompt("Parallel xray instances (1-8)")
        .validate_with(|n: &u8| (1..=8).contains(n).then_some(()).ok_or("must be 1-8"))
        .default(3)
        .interact()?;

    Ok(Phase2Config {
        configs,
        fragment,
        custom_fragment,
        snis,
        probe_url,
        probe_urls: Vec::new(),
        concurrency,
    })
}

fn config_recap(cfg: &ScanConfig) -> Vec<String> {
    let mode = match cfg.mode {
        Mode::Cdn => "cdn",
        Mode::Warp => "warp",
    };
    let target = match &cfg.target {
        ScanTarget::Preset(preset) => format!("preset {preset:?}"),
        ScanTarget::Count(n) => format!("{n} candidates"),
    };
    let ports = cfg
        .ports
        .iter()
        .map(|p| p.get().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let cap = cfg
        .stop
        .cap
        .map(|c| c.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let mut lines = vec![
        recap_line("mode", mode.to_owned()),
        recap_line("target", target),
        recap_line("ports", ports),
        recap_line("stop", format!("found={}, cap={}", cfg.stop.found, cap)),
        recap_line(
            "tuning",
            format!(
                "concurrency={}, timeout_ms={}",
                cfg.concurrency, cfg.timeout_ms
            ),
        ),
    ];
    if !cfg.custom_cidrs.is_empty() {
        lines.push(recap_line(
            "custom",
            format!("{} CIDRs", cfg.custom_cidrs.len()),
        ));
    }
    if !cfg.exclude.is_empty() {
        lines.push(recap_line(
            "exclude",
            format!("{} CIDRs", cfg.exclude.len()),
        ));
    }
    if let Some(p2) = &cfg.phase2 {
        lines.push(recap_line(
            "phase 2",
            format!(
                "{} config(s), fragment {}, {} SNI(s), {} xray instance(s)",
                p2.configs.len(),
                p2.fragment,
                p2.snis.len(),
                p2.concurrency
            ),
        ));
    }
    if let Some(warp) = &cfg.warp {
        lines.push(recap_line(
            "warp",
            format!(
                "{} custom endpoint(s), {} probe(s)/endpoint, wgconf verify {}",
                warp.custom_endpoints.len(),
                warp.probes_per_endpoint,
                if warp.verify_with_wgconf { "on" } else { "off" }
            ),
        ));
    }
    lines
}

fn recap_line(label: &str, value: String) -> String {
    format!("{:<12}{}", label, value)
}

fn parse_custom_fragment(values: &str) -> Result<CustomFragment> {
    let Some((length, interval)) = values.split_once(',') else {
        return Err(anyhow!(
            "custom fragment must be \"length,interval\", got: '{values}'"
        ));
    };
    Ok(CustomFragment {
        packets: "tlshello".to_owned(),
        length: length.trim().to_owned(),
        interval: interval.trim().to_owned(),
    })
}

fn validate_stop_value(n: &u32) -> Result<(), String> {
    (1..=MAX_STOP_VALUE)
        .contains(n)
        .then_some(())
        .ok_or_else(|| format!("must be 1-{MAX_STOP_VALUE}"))
}

fn parse_cap(raw: &str) -> Result<Option<u32>, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let cap: u32 = value
        .parse()
        .map_err(|_| "cap must be a number".to_owned())?;
    if cap == 0 || cap > MAX_STOP_VALUE {
        return Err(format!("cap must be 1-{MAX_STOP_VALUE}"));
    }
    Ok(Some(cap))
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_list(prompt: &str) -> Result<Vec<String>> {
    let raw: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact()?;
    Ok(split_list(&raw))
}

fn parse_cidr_list(prompt: &str) -> Result<Vec<String>> {
    let raw: String = Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact()?;
    Ok(split_list(&raw))
}

fn check_entries(entries: &[String], max: usize, label: &str, max_bytes: usize) -> Result<()> {
    if entries.len() > max {
        bail!("{label} exceed {max} entries");
    }
    if entries.iter().any(|e| e.len() > max_bytes) {
        bail!("{label} entry exceeds {max_bytes} bytes");
    }
    Ok(())
}

fn check_cidr(cidr: &str, reject_non_routable: bool) -> Result<()> {
    let (ip, _) = parse_cidr(cidr).map_err(|e| anyhow!("{e}"))?;
    if reject_non_routable && types::banned_ip(&ip) {
        bail!("CIDR {cidr} is not routable");
    }
    Ok(())
}

fn check_endpoint(endpoint: &str) -> Result<()> {
    let (ip, _) = parse_endpoint(endpoint).map_err(|e| anyhow!("{e}"))?;
    if types::banned_ip(&ip) {
        bail!("endpoint {endpoint} is not routable");
    }
    Ok(())
}

fn parse_ports(s: &str) -> Result<Vec<Port>> {
    let ports: Vec<u16> = s
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.parse::<u16>()
                .map_err(|_| anyhow!("port '{p}' is not a number"))
        })
        .collect::<Result<_>>()?;
    let ports: Vec<Port> = ports.into_iter().map(Port).collect();
    types::validate_ports(&ports).map_err(|e| anyhow!("{e}"))?;
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comma_ports() {
        assert_eq!(parse_ports("443").unwrap(), vec![Port::new(443)]);
        assert_eq!(
            parse_ports(" 2408, 500 ").unwrap(),
            vec![Port::new(2408), Port::new(500)]
        );
        assert!(parse_ports("").is_err());
        assert!(parse_ports("0,443").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn custom_fragment_parses_or_errors() {
        let f = parse_custom_fragment("100-200, 10-20").unwrap();
        assert_eq!(f.length, "100-200");
        assert_eq!(f.interval, "10-20");
        assert!(parse_custom_fragment("100-200").is_err());
        assert!(parse_custom_fragment("").is_err());
    }

    #[test]
    fn interrupt_eof_and_not_tty_prompt_errors_are_user_exits() {
        let make = |kind: std::io::ErrorKind| {
            anyhow::Error::new(dialoguer::Error::IO(std::io::Error::new(kind, "x")))
        };
        let interrupt = make(std::io::ErrorKind::Interrupted);
        let eof = make(std::io::ErrorKind::UnexpectedEof);
        let not_tty = make(std::io::ErrorKind::NotConnected);
        let other = make(std::io::ErrorKind::InvalidData);
        assert!(is_user_exit(&interrupt));
        assert!(is_user_exit(&eof));
        assert!(is_user_exit(&not_tty));
        assert!(!is_user_exit(&other));
        assert!(!is_user_exit(&anyhow!("boom")));
        assert!(!is_terminal_unusable(&interrupt));
        assert!(is_terminal_unusable(&eof));
        assert!(is_terminal_unusable(&not_tty));
    }

    #[test]
    fn wizard_interrupt_downcasts_from_run_error_shape() {
        let err: anyhow::Error = WizardInterrupted.into();
        assert_eq!(err.to_string(), "interrupted");
        assert!(err.is::<WizardInterrupted>());
        let raw = anyhow::Error::new(dialoguer::Error::IO(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "ctrl+c",
        )));
        assert!(!raw.is::<WizardInterrupted>());
    }

    #[test]
    fn stop_values_match_engine_bounds() {
        assert!(validate_stop_value(&1).is_ok());
        assert!(validate_stop_value(&MAX_STOP_VALUE).is_ok());
        assert!(validate_stop_value(&0).is_err());
        assert!(validate_stop_value(&(MAX_STOP_VALUE + 1)).is_err());
    }

    #[test]
    fn cap_parses_empty_and_bounded_numbers() {
        assert_eq!(parse_cap("").unwrap(), None);
        assert_eq!(parse_cap(" 500 ").unwrap(), Some(500));
        assert_eq!(
            parse_cap(&MAX_STOP_VALUE.to_string()).unwrap(),
            Some(MAX_STOP_VALUE)
        );
        assert!(parse_cap("0").is_err());
        assert!(parse_cap("abc").is_err());
        assert!(parse_cap(&(u64::from(MAX_STOP_VALUE) + 1).to_string()).is_err());
    }

    #[test]
    fn endpoint_entries_match_engine_rules() {
        assert!(check_endpoint("203.0.113.1:2408").is_ok());
        assert!(check_endpoint("203.0.113.1").is_ok());
        assert!(check_endpoint("192.168.1.1:2408").is_err());
        assert!(check_endpoint("::1").is_err());
        assert!(check_endpoint("203.0.113.1:0").is_err());
        assert!(check_endpoint("not-an-ip").is_err());
    }

    #[test]
    fn cidr_entries_match_engine_rules() {
        assert!(check_cidr("203.0.113.0/24", true).is_ok());
        assert!(check_cidr("10.0.0.0/8", true).is_err());
        assert!(check_cidr("10.0.0.0/8", false).is_ok());
        assert!(check_cidr("203.0.113.0", false).is_err());
        assert!(check_cidr("203.0.113.0/33", false).is_err());
    }

    #[test]
    fn entry_caps_enforced_inline() {
        let one = vec!["203.0.113.1".to_owned()];
        assert!(check_entries(&one, 1, "test", 64).is_ok());
        let too_many = vec!["203.0.113.1".to_owned(), "203.0.113.2".to_owned()];
        assert!(check_entries(&too_many, 1, "test", 64).is_err());
        let too_long = vec!["x".repeat(65)];
        assert!(check_entries(&too_long, 1, "test", 64).is_err());
    }

    #[test]
    fn split_list_trims_and_skips_empty() {
        assert_eq!(
            split_list(" a , b ,, c "),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
        assert!(split_list("").is_empty());
        assert!(split_list(" , , ").is_empty());
    }

    #[test]
    fn recap_describes_shape_without_leaking_payloads() {
        let cfg = ScanConfig {
            mode: Mode::Cdn,
            target: ScanTarget::Preset(CdnPreset::Quick),
            phase2: Some(Phase2Config {
                configs: vec!["vless://uuid@host:443?secret".to_owned()],
                fragment: FragmentPreset::Light,
                custom_fragment: None,
                snis: vec!["example.com".to_owned()],
                probe_url: DEFAULT_PROBE_URL.to_owned(),
                probe_urls: Vec::new(),
                concurrency: 3,
            }),
            ..ScanConfig::default()
        };
        let recap = config_recap(&cfg).join("\n");
        assert!(recap.contains("mode        cdn"));
        assert!(recap.contains("target      preset Quick"));
        assert!(recap.contains("ports       443"));
        assert!(recap.contains("stop        found=20, cap=none"));
        assert!(recap.contains("phase 2     1 config(s), fragment light"));
        assert!(!recap.contains("vless://"));
        assert!(!recap.contains("example.com"));

        let mut warp_cfg = ScanConfig {
            mode: Mode::Warp,
            target: ScanTarget::Count(3),
            warp: Some(WarpConfig {
                custom_endpoints: vec!["203.0.113.1:2408".to_owned()],
                probes_per_endpoint: 3,
                wgconf: Some("private-key = xyz".to_owned()),
                verify_with_wgconf: true,
            }),
            ..ScanConfig::default()
        };
        let recap = config_recap(&warp_cfg).join("\n");
        assert!(recap.contains("mode        warp"));
        assert!(recap.contains("1 custom endpoint(s)"));
        assert!(recap.contains("wgconf verify on"));
        assert!(!recap.contains("203.0.113.1"));
        assert!(!recap.contains("private-key"));
        warp_cfg.warp = None;
        let recap = config_recap(&warp_cfg).join("\n");
        assert!(!recap.contains("probe(s)/endpoint"));
    }
}
