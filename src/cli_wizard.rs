use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::api::types::{
    self, CdnPreset, CustomFragment, DEFAULT_ACCEPTED_HTTP_CODES, DEFAULT_CONCURRENCY,
    DEFAULT_PORT, DEFAULT_PROBE_URL, DEFAULT_TIMEOUT_MS, DEFAULT_WARP_PORTS, FragmentPreset,
    MAX_CIDRS, MAX_COLO_CODES, MAX_CONFIG_ENTRY_BYTES, MAX_ENDPOINTS, MAX_IDLE_HOLD_MS,
    MAX_MIN_LATENCY_MS, MAX_NEIGHBORS, MAX_PHASE2_ENTRIES, MAX_PROBE_URL_BYTES, MAX_SCAN_COUNT,
    MAX_SNI_BYTES, MAX_STOP_VALUE, MAX_WGCONF_BYTES, Mode, Phase2Config, Port, ProbeMode,
    ScanConfig, ScanEvent, ScanSummary, ScanTarget, StopCondition, WarpConfig, parse_cidr,
    parse_endpoint, validate_fragment, validate_sni,
};
use crate::engine::ScanController;
use crate::probe;
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

pub async fn run() -> Result<()> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let current: Arc<Mutex<Option<Arc<ScanController>>>> = Arc::new(Mutex::new(None));
    let ctrl_c = spawn_ctrl_c_listener(&current, &interrupted);
    let result = run_wizard(&current, &interrupted).await;
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
    current: &Arc<Mutex<Option<Arc<ScanController>>>>,
    interrupted: &Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let current = Arc::clone(current);
    let interrupted = Arc::clone(interrupted);
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                interrupted.store(true, Ordering::Relaxed);
                if let Some(controller) = current.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
                {
                    controller.cancel();
                }
            }
            Err(err) => tracing::error!("could not listen for Ctrl+C: {err}"),
        }
    })
}

async fn run_wizard(
    current: &Arc<Mutex<Option<Arc<ScanController>>>>,
    interrupted: &AtomicBool,
) -> Result<()> {
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
        let controller = Arc::new(ScanController::new(probe::transport_for(
            cfg.probe_mode,
            &cfg.accepted_http_codes,
        )));
        *current.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&controller));
        let summary = run_scan(&controller, &cfg).await?;
        *current.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
                let status = match (&v.fail_reason, v.latency_ms) {
                    (Some(reason), _) => format!("failed ({reason})"),
                    (None, latency) => format!("{}ms", latency.unwrap_or(0)),
                };
                let _ = writeln!(err, "\r\x1b[K{}\t{status}{phase2}", v.ip);
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

    let loss_threshold_raw: String = Input::new()
        .with_prompt("Loss-rate threshold (0-100, empty = keep everything)")
        .allow_empty(true)
        .validate_with(|s: &String| parse_loss_threshold(s).map(|_| ()))
        .interact()?;
    let loss_threshold = parse_loss_threshold(&loss_threshold_raw).map_err(|e| anyhow!("{e}"))?;
    let idle_hold_raw: String = Input::new()
        .with_prompt("Idle-hold stability probe in ms (0-60000, empty = off)")
        .allow_empty(true)
        .validate_with(|s: &String| parse_idle_hold(s).map(|_| ()))
        .interact()?;
    let idle_hold_ms = parse_idle_hold(&idle_hold_raw).map_err(|e| anyhow!("{e}"))?;

    let probe_mode = match Select::new()
        .with_prompt("Phase-1 probe protocol")
        .item("TLS handshake (default)")
        .item("TCP connect only")
        .item("HTTP trace (GET /cdn-cgi/trace, captures colo)")
        .default(0)
        .interact()?
    {
        1 => ProbeMode::Tcp,
        2 => ProbeMode::Http,
        _ => ProbeMode::Tls,
    };
    let accepted_http_codes = if probe_mode == ProbeMode::Http {
        let raw: String = Input::new()
            .with_prompt("HTTP status codes that count as working (comma-separated)")
            .default(
                DEFAULT_ACCEPTED_HTTP_CODES
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .validate_with(|s: &String| parse_http_codes(s).map(|_| ()))
            .interact()?;
        parse_http_codes(&raw).map_err(|e| anyhow!("{e}"))?
    } else {
        crate::api::types::default_accepted_http_codes()
    };

    let min_latency_raw: String = Input::new()
        .with_prompt("Minimum latency in ms (drop faster results, empty = off)")
        .allow_empty(true)
        .validate_with(|s: &String| parse_min_latency(s).map(|_| ()))
        .interact()?;
    let min_latency_ms = parse_min_latency(&min_latency_raw).map_err(|e| anyhow!("{e}"))?;

    let colo_raw: String = Input::new()
        .with_prompt("Keep only these colo codes, e.g. HKG,NRT (empty = all regions)")
        .allow_empty(true)
        .validate_with(|s: &String| parse_colo_filter(s).map(|_| ()))
        .interact()?;
    let colo_filter = parse_colo_filter(&colo_raw).map_err(|e| anyhow!("{e}"))?;

    let neighbor_raw: String = Input::new()
        .with_prompt("Neighbor scan breadth 0-64 (0 = off)")
        .allow_empty(true)
        .validate_with(|s: &String| parse_neighbor_scan(s).map(|_| ()))
        .interact()?;
    let neighbor_count = parse_neighbor_scan(&neighbor_raw).map_err(|e| anyhow!("{e}"))?;

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
    let (speed_test, min_speed_mbps) = if phase2.is_some()
        && Confirm::new()
            .with_prompt(
                "Throughput-test the passing endpoints after the scan (8 MiB sample each)?",
            )
            .default(false)
            .interact()?
    {
        let min_raw: String = Input::new()
            .with_prompt("Minimum speed in MB/s (empty = keep everything)")
            .allow_empty(true)
            .validate_with(|s: &String| parse_min_speed(s).map(|_| ()))
            .interact()?;
        (true, parse_min_speed(&min_raw).map_err(|e| anyhow!("{e}"))?)
    } else {
        (false, None)
    };

    let cfg = ScanConfig {
        mode: Mode::Cdn,
        target,
        ports,
        stop: StopCondition { found, cap },
        exclude,
        custom_cidrs,
        concurrency,
        timeout_ms,
        loss_threshold,
        idle_hold_ms,
        min_latency_ms,
        colo_filter,
        probe_mode,
        accepted_http_codes,
        speed_test,
        min_speed_mbps,
        neighbor_count,
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
        recap_line(
            "loss filter",
            match cfg.loss_threshold {
                Some(t) => format!("drop results above {t}% loss"),
                None => "off".to_owned(),
            },
        ),
        recap_line(
            "idle hold",
            match cfg.idle_hold_ms {
                0 => "off".to_owned(),
                ms => format!("{ms} ms stability probe"),
            },
        ),
        recap_line(
            "probe",
            match cfg.probe_mode {
                ProbeMode::Tcp => "tcp connect".to_owned(),
                ProbeMode::Tls => "tls handshake".to_owned(),
                ProbeMode::Http => format!(
                    "http trace (accepts {})",
                    cfg.accepted_http_codes
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            },
        ),
        recap_line(
            "min latency",
            match cfg.min_latency_ms {
                Some(t) => format!("drop results below {t} ms"),
                None => "off".to_owned(),
            },
        ),
        recap_line(
            "colo",
            if cfg.colo_filter.is_empty() {
                "all regions".to_owned()
            } else {
                format!("only {}", cfg.colo_filter.join(","))
            },
        ),
        recap_line(
            "neighbors",
            match cfg.neighbor_count {
                0 => "off".to_owned(),
                n => format!("{n} per hit"),
            },
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
    if cfg.speed_test {
        lines.push(recap_line(
            "speed test",
            match cfg.min_speed_mbps {
                Some(min) => format!("8 MiB sample, keep {min} MB/s and up"),
                None => "8 MiB sample, no minimum".to_owned(),
            },
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

fn parse_loss_threshold(raw: &str) -> Result<Option<u32>, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let t: u32 = value
        .parse()
        .map_err(|_| "loss threshold must be a number".to_owned())?;
    if t > 100 {
        return Err("loss threshold must be 0-100".to_owned());
    }
    Ok(Some(t))
}

fn parse_idle_hold(raw: &str) -> Result<u64, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(0);
    }
    let ms: u64 = value
        .parse()
        .map_err(|_| "idle hold must be a number".to_owned())?;
    if ms > MAX_IDLE_HOLD_MS {
        return Err(format!("idle hold must be 0-{MAX_IDLE_HOLD_MS}"));
    }
    Ok(ms)
}

fn parse_min_latency(raw: &str) -> Result<Option<u32>, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let ms: u32 = value
        .parse()
        .map_err(|_| "minimum latency must be a number".to_owned())?;
    if ms == 0 || ms > MAX_MIN_LATENCY_MS {
        return Err(format!("minimum latency must be 1-{MAX_MIN_LATENCY_MS}"));
    }
    Ok(Some(ms))
}

fn parse_colo_filter(raw: &str) -> Result<Vec<String>, String> {
    let mut codes: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let code = part.trim().to_uppercase();
        if code.is_empty() {
            continue;
        }
        let valid = (3..=5).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphabetic());
        if !valid {
            return Err(format!("invalid colo code {part:?}: expected 3-5 letters"));
        }
        codes.push(code);
    }
    if codes.len() > MAX_COLO_CODES {
        return Err(format!("at most {MAX_COLO_CODES} colo codes"));
    }
    Ok(codes)
}

fn parse_neighbor_scan(raw: &str) -> Result<u32, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(0);
    }
    let n: u32 = value
        .parse()
        .map_err(|_| "neighbor scan must be a number".to_owned())?;
    if n > MAX_NEIGHBORS {
        return Err(format!("neighbor scan must be 0-{MAX_NEIGHBORS}"));
    }
    Ok(n)
}

fn parse_http_codes(raw: &str) -> Result<Vec<u16>, String> {
    let mut codes: Vec<u16> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let code: u16 = part
            .parse()
            .map_err(|_| format!("invalid status code {part:?}"))?;
        if !(100..=599).contains(&code) {
            return Err(format!("status code {code} must be 100-599"));
        }
        codes.push(code);
    }
    if codes.is_empty() {
        return Err("at least one status code required".to_owned());
    }
    Ok(codes)
}

fn parse_min_speed(raw: &str) -> Result<Option<f32>, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let speed: f32 = value
        .parse()
        .map_err(|_| "minimum speed must be a number".to_owned())?;
    if !speed.is_finite() || speed <= 0.0 {
        return Err("minimum speed must be greater than 0".to_owned());
    }
    Ok(Some(speed))
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
    fn loss_threshold_parses_empty_and_bounded_numbers() {
        assert_eq!(parse_loss_threshold("").unwrap(), None);
        assert_eq!(parse_loss_threshold(" 40 ").unwrap(), Some(40));
        assert_eq!(parse_loss_threshold("0").unwrap(), Some(0));
        assert_eq!(parse_loss_threshold("100").unwrap(), Some(100));
        assert!(parse_loss_threshold("101").is_err());
        assert!(parse_loss_threshold("abc").is_err());
    }

    #[test]
    fn idle_hold_parses_empty_and_bounded_numbers() {
        assert_eq!(parse_idle_hold("").unwrap(), 0);
        assert_eq!(parse_idle_hold(" 1500 ").unwrap(), 1500);
        assert_eq!(parse_idle_hold("0").unwrap(), 0);
        assert_eq!(
            parse_idle_hold(&MAX_IDLE_HOLD_MS.to_string()).unwrap(),
            MAX_IDLE_HOLD_MS
        );
        assert!(parse_idle_hold(&(MAX_IDLE_HOLD_MS + 1).to_string()).is_err());
        assert!(parse_idle_hold("abc").is_err());
    }

    #[test]
    fn min_latency_parses_empty_and_bounded_numbers() {
        assert_eq!(parse_min_latency("").unwrap(), None);
        assert_eq!(parse_min_latency(" 250 ").unwrap(), Some(250));
        assert_eq!(
            parse_min_latency(&MAX_MIN_LATENCY_MS.to_string()).unwrap(),
            Some(MAX_MIN_LATENCY_MS)
        );
        assert!(parse_min_latency("0").is_err());
        assert!(parse_min_latency(&(MAX_MIN_LATENCY_MS + 1).to_string()).is_err());
        assert!(parse_min_latency("abc").is_err());
    }

    #[test]
    fn colo_filter_parses_and_normalizes_codes() {
        assert!(parse_colo_filter("").unwrap().is_empty());
        assert_eq!(
            parse_colo_filter(" hkg ,Nrt ").unwrap(),
            vec!["HKG".to_owned(), "NRT".to_owned()]
        );
        assert!(parse_colo_filter("HK").is_err());
        assert!(parse_colo_filter("HKGNRT").is_err());
        assert!(parse_colo_filter("H1G").is_err());
        assert!(parse_colo_filter("hk-g").is_err());
    }

    #[test]
    fn neighbor_scan_parses_empty_and_bounded_numbers() {
        assert_eq!(parse_neighbor_scan("").unwrap(), 0);
        assert_eq!(parse_neighbor_scan(" 4 ").unwrap(), 4);
        assert_eq!(
            parse_neighbor_scan(&MAX_NEIGHBORS.to_string()).unwrap(),
            MAX_NEIGHBORS
        );
        assert!(parse_neighbor_scan(&(MAX_NEIGHBORS + 1).to_string()).is_err());
        assert!(parse_neighbor_scan("abc").is_err());
    }

    #[test]
    fn http_codes_parse_comma_lists_and_validate_range() {
        assert_eq!(
            parse_http_codes("200,301,302").unwrap(),
            vec![200, 301, 302]
        );
        assert_eq!(parse_http_codes(" 200 ").unwrap(), vec![200]);
        assert!(parse_http_codes("").is_err());
        assert!(parse_http_codes("99").is_err());
        assert!(parse_http_codes("600").is_err());
        assert!(parse_http_codes("abc").is_err());
    }

    #[test]
    fn min_speed_parses_empty_and_positive_numbers() {
        assert_eq!(parse_min_speed("").unwrap(), None);
        assert_eq!(parse_min_speed(" 2.5 ").unwrap(), Some(2.5));
        assert!(parse_min_speed("0").is_err());
        assert!(parse_min_speed("-1").is_err());
        assert!(parse_min_speed("abc").is_err());
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
        assert!(recap.contains("probe       tls handshake"));
        assert!(recap.contains("min latency off"));
        assert!(recap.contains("colo        all regions"));
        assert!(recap.contains("neighbors   off"));
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

        let tuned = ScanConfig {
            mode: Mode::Cdn,
            target: ScanTarget::Count(10),
            probe_mode: ProbeMode::Http,
            accepted_http_codes: vec![200, 204],
            min_latency_ms: Some(50),
            colo_filter: vec!["HKG".to_owned()],
            neighbor_count: 4,
            speed_test: true,
            min_speed_mbps: Some(2.5),
            phase2: Some(Phase2Config {
                configs: vec!["vless://uuid@host:443".to_owned()],
                fragment: FragmentPreset::Off,
                custom_fragment: None,
                snis: Vec::new(),
                probe_url: DEFAULT_PROBE_URL.to_owned(),
                probe_urls: Vec::new(),
                concurrency: 1,
            }),
            ..ScanConfig::default()
        };
        let recap = config_recap(&tuned).join("\n");
        assert!(recap.contains("probe       http trace (accepts 200,204)"));
        assert!(recap.contains("min latency drop results below 50 ms"));
        assert!(recap.contains("colo        only HKG"));
        assert!(recap.contains("neighbors   4 per hit"));
        assert!(recap.contains("speed test  8 MiB sample, keep 2.5 MB/s and up"));
    }
}
