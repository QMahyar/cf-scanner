//! Interactive wizard: friendly prompts that drive the same engine and API
//! contract the browser UI and CLI use. Non-json output lives on stderr so
//! stdout stays machine-readable. Phase-2 config import lands with Task 9;
//! WARP with Task 12.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use dialoguer::{Confirm, Input, Select};

use crate::api::types::{CdnPreset, Mode, ScanConfig, ScanEvent, ScanTarget, StopCondition};
use crate::engine::ScanController;

const WARP_NOT_YET: &str = "WARP mode arrives in a later build; using CDN mode.";

pub async fn run(controller: Arc<ScanController>) -> Result<()> {
    println!("CF-Scanner wizard — CDN/proxy phase-1 scan (config import arrives in a later build)");
    let cfg = prompt_config()?;
    println!();
    if !Confirm::new()
        .with_prompt("Start scan now?")
        .default(true)
        .interact()?
    {
        println!("aborted");
        return Ok(());
    }
    let summary = controller
        .run_streaming(cfg, |e| match e {
            ScanEvent::Progress(p) => {
                let total = p.total.map(|t| format!(" / {t}")).unwrap_or_default();
                let (scanned, found) = (p.scanned, p.found);
                eprint!("\r\x1b[Kchecked {scanned}{total} — {found} working");
            }
            ScanEvent::Result(v) => {
                println!("\r\x1b[K{}\t{}ms", v.ip, v.latency_ms.unwrap_or(0));
            }
            ScanEvent::Finished(_) => print!("\r\x1b[K"),
        })
        .await
        .map_err(|e| anyhow!("scan failed: {e:#}"))?;
    eprintln!(
        "done — scanned {}, found {} working in {} ms",
        summary.scanned, summary.found, summary.duration_ms
    );
    Ok(())
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
        println!("{WARP_NOT_YET}");
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
        .default(200)
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

    let cfg = ScanConfig {
        mode: Mode::Cdn,
        target,
        ports,
        stop: StopCondition { found, cap },
        exclude,
        custom_cidrs,
        concurrency,
        timeout_ms,
        ..ScanConfig::default()
    };
    cfg.validate().map_err(|e| anyhow!("invalid input: {e}"))?;
    Ok(cfg)
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
}
