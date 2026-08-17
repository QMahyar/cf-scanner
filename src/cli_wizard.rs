//! Interactive wizard: friendly prompts that drive the same engine and API
//! contract the browser UI and CLI use. Non-json output lives on stderr so
//! stdout stays machine-readable.

use std::sync::Arc;

use crate::api::types::{
    CdnPreset, DEFAULT_CONCURRENCY, FragmentPreset, Mode, Phase2Config, ScanConfig, ScanEvent,
    ScanTarget, StopCondition, WarpConfig,
};
use crate::engine::ScanController;
use crate::warp;
use crate::warpgen;
use anyhow::{Context as _, Result, anyhow};
use dialoguer::{Confirm, Input, Select};

/// WARP prompts: candidate count / full pools, ports, probes per endpoint,
/// custom endpoints, optional wgconf verification. Registration lands with
/// Task 14.
fn prompt_warp() -> Result<ScanConfig> {
    let all_pools = warp::bundled_pool().host_count();
    let count: u32 = Input::new()
        .with_prompt(format!(
            "Candidate endpoints (1-{all_pools}; {} = all pools)",
            all_pools
        ))
        .validate_with(|n: &u32| (*n >= 1).then_some(()).ok_or("must be >= 1"))
        .default(all_pools as u32)
        .interact()?;
    let ports = parse_ports(
        &Input::new()
            .with_prompt("UDP ports (comma-separated)")
            .default("2408".to_owned())
            .validate_with(|s: &String| parse_ports(s).map(|_| ()).map_err(|e| e.to_string()))
            .interact()?,
    )?;
    let found: u32 = Input::new()
        .with_prompt("Stop after N working endpoints")
        .validate_with(|n: &u32| (*n >= 1).then_some(()).ok_or("must be >= 1"))
        .default(20)
        .interact()?;
    let probes: u8 = Input::new()
        .with_prompt("Handshake probes per endpoint (1-10, drives loss %)")
        .validate_with(|n: &u8| (1..=10).contains(n).then_some(()).ok_or("must be 1-10"))
        .default(3)
        .interact()?;
    let custom =
        parse_list("Custom endpoints ip or ip:port (comma-separated; empty = bundled pools)")?;
    let verify = Confirm::new()
        .with_prompt("Verify with your own wgconf (real keypair handshake)?")
        .default(false)
        .interact()?;
    let wgconf = if verify {
        let path: String = Input::new()
            .with_prompt("Path to a wg-quick / AmneziaWG config file")
            .interact()?;
        Some(std::fs::read_to_string(&path).map_err(|e| anyhow!("could not read wgconf: {e}"))?)
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
        .default(3000)
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

pub async fn run(controller: Arc<ScanController>) -> Result<()> {
    match run_wizard(controller).await {
        Err(err) if is_interrupt(&err) => Err(anyhow!("interrupted")),
        other => other,
    }
}

async fn run_wizard(controller: Arc<ScanController>) -> Result<()> {
    eprintln!("CF-Scanner wizard — CDN/proxy scan with optional xray phase-2 verification");
    let cfg = prompt_config()?;
    eprintln!();
    if !Confirm::new()
        .with_prompt("Start scan now?")
        .default(true)
        .interact()?
    {
        eprintln!("aborted");
        return Ok(());
    }
    let is_warp = cfg.mode == Mode::Warp;
    let cancel_on_ctrl_c = {
        let controller = controller.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                controller.cancel();
            }
        })
    };
    let summary = controller
        .run_streaming(cfg, |e| match e {
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
            ScanEvent::Failed(msg) => {
                eprint!("\r\x1b[K");
                eprintln!("scan failed: {msg}");
            }
        })
        .await
        .map_err(|e| anyhow!("scan failed: {e:#}"));
    cancel_on_ctrl_c.abort();
    let summary = summary?;
    eprintln!(
        "done — scanned {}, found {} working in {} ms",
        summary.scanned, summary.found, summary.duration_ms
    );
    if summary.cancelled {
        eprintln!("cancelled — {} working endpoints retained", summary.found);
        return Ok(());
    }
    if is_warp {
        prompt_registration(&controller).await?;
    }
    Ok(())
}

/// Task 14 opt-in: after a WARP scan, offer to register an identity with
/// Cloudflare's client API and export a ready-to-use wgconf. The exported
/// endpoint bakes in the best endpoint the scan just found.
async fn prompt_registration(controller: &ScanController) -> Result<()> {
    if !Confirm::new()
        .with_prompt(
            "Generate a WARP config (opt-in v0a884 registration via api.cloudflareclient.com)?",
        )
        .default(false)
        .interact()?
    {
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
    let license: String = Input::new()
        .with_prompt("WARP+ license key (empty = free account)")
        .allow_empty(true)
        .interact()?;
    let out: String = Input::new()
        .with_prompt("Output path (empty = print to stdout)")
        .allow_empty(true)
        .interact()?;
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

/// A Ctrl+C during a prompt surfaces as `dialoguer::Error::IO(Interrupted)`
/// in the error chain; report it as a plain "interrupted" instead of a raw
/// IO error.
fn is_interrupt(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<dialoguer::Error>().is_some_and(|e| {
            matches!(e, dialoguer::Error::IO(io) if io.kind() == std::io::ErrorKind::Interrupted)
        })
    })
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
                .with_prompt("Candidate count")
                .validate_with(|n: &u32| (*n >= 1).then_some(()).ok_or("must be >= 1"))
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
            .default("443".to_owned())
            .validate_with(|s: &String| parse_ports(s).map(|_| ()).map_err(|e| e.to_string()))
            .interact()?,
    )?;

    let found: u32 = Input::new()
        .with_prompt("Stop after N working endpoints")
        .validate_with(|n: &u32| (*n >= 1).then_some(()).ok_or("must be >= 1"))
        .default(20)
        .interact()?;
    let cap_raw: String = dialoguer::Input::new()
        .with_prompt("Hard probe cap (empty = none)")
        .allow_empty(true)
        .interact()?;
    let cap = match cap_raw.trim() {
        "" => None,
        s => Some(
            s.parse::<u32>()
                .map_err(|_| anyhow!("cap must be a number"))?,
        ),
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
        .default(3000)
        .interact()?;

    let custom_cidrs = parse_cidr_list(
        "Custom CIDRs (comma-separated, replaces bundled ranges; empty = bundled)",
    )?;
    let exclude = parse_cidr_list("Excluded CIDRs (comma-separated; empty = none)")?;

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

/// Phase-2 prompts: configs, fragment preset, SNIs, probe target.
fn prompt_phase2() -> Result<Phase2Config> {
    let configs = parse_list(
        "Configs (vless/trojan/vmess/ss URIs, subscription URLs, or xray JSON paths; comma-separated)",
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
        Some(parse_custom_fragment(&values)?)
    } else {
        None
    };

    let snis =
        parse_list("SNI fronting variants (comma-separated; empty = each config's own SNI)")?;
    let probe_url: String = Input::new()
        .with_prompt("Probe URL fetched through the tunnel")
        .default(crate::api::types::DEFAULT_PROBE_URL.to_owned())
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

/// Parse `"length,interval"` into a custom fragment; the prompt validator
/// already guarantees the comma, but user input must never unwrap.
fn parse_custom_fragment(values: &str) -> Result<crate::api::types::CustomFragment> {
    let Some((length, interval)) = values.split_once(',') else {
        return Err(anyhow!(
            "custom fragment must be \"length,interval\", got: '{values}'"
        ));
    };
    Ok(crate::api::types::CustomFragment {
        packets: "tlshello".to_owned(),
        length: length.trim().to_owned(),
        interval: interval.trim().to_owned(),
    })
}

fn parse_list(prompt: &str) -> Result<Vec<String>> {
    let raw: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact()?;
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect())
}

fn parse_ports(s: &str) -> Result<Vec<u16>> {
    let ports: Vec<u16> = s
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.parse::<u16>()
                .map_err(|_| anyhow!("port '{p}' is not a number"))
        })
        .collect::<Result<_>>()?;
    if ports.is_empty() {
        return Err(anyhow!("at least one port required"));
    }
    if ports.contains(&0) {
        return Err(anyhow!("port 0 is not allowed"));
    }
    Ok(ports)
}

fn parse_cidr_list(prompt: &str) -> Result<Vec<String>> {
    let raw: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact()?;
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comma_ports() {
        assert_eq!(parse_ports("443").unwrap(), vec![443]);
        assert_eq!(parse_ports(" 2408, 500 ").unwrap(), vec![2408, 500]);
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
    fn only_interrupted_prompt_errors_are_interrupts() {
        let err = anyhow::Error::new(dialoguer::Error::IO(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "ctrl+c",
        )));
        assert!(is_interrupt(&err));
        let err = anyhow::Error::new(dialoguer::Error::IO(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "not a terminal",
        )));
        assert!(!is_interrupt(&err));
        assert!(!is_interrupt(&anyhow!("boom")));
    }
}
