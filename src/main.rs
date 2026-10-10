use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use cf_scanner::api::types::{ScanEvent, Verdict};
use cf_scanner::{cli_wizard, engine, enrich, export, paths, probe, ranges, tune, warpgen, wgconf};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

mod cli;
use cli::scan_args::build_scan_config;
use cli::{Cli, Command, RangesAction, ScanArgs, TuneAction, WarpConfigAction};

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let json_errors =
                std::env::args().any(|a| a == "--json-errors" || a.starts_with("--json-errors="));
            if let Some(line) = cli::parse_error_line(&e, json_errors) {
                let _ = write_stdout_line(&line);
            }
            e.exit();
        }
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter(
            cli.verbose,
            std::env::var("RUST_LOG").ok().as_deref(),
        ))
        .init();

    let json_errors = cli.json_errors;
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // T07 story 16: a scan failure already streamed its single `Failed`
            // envelope on stdout — a generic `{"type":"error"}` here would be
            // a second shape for the same failure. Pre-scan failures (config,
            // export, clap) never streamed, so they still get the envelope.
            let streamed = err.downcast_ref::<ScanFailedStreamed>().is_some();
            if json_errors && !streamed {
                let line =
                    serde_json::json!({ "type": "error", "error": err.to_string() }).to_string();
                let _ = write_stdout_line(&line);
            }
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Marker for scan failures whose single `Failed` envelope was already
/// streamed on stdout by the engine. `main` spots it to skip the generic
/// `--json-errors` duplicate (T07 story 16). Displays as the inner message so
/// stderr keeps today's human text.
#[derive(Debug)]
struct ScanFailedStreamed(String);

impl std::fmt::Display for ScanFailedStreamed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ScanFailedStreamed {}

fn env_filter(verbose: bool, rust_log: Option<&str>) -> EnvFilter {
    let directive = match rust_log.map(str::trim).filter(|s| !s.is_empty()) {
        Some(dirs) => dirs.to_owned(),
        None if verbose => "info".to_owned(),
        None => "error".to_owned(),
    };
    EnvFilter::builder()
        .with_default_directive(LevelFilter::ERROR.into())
        .parse_lossy(directive)
}

fn clear_ticker_line() {
    if std::io::stderr().is_terminal() {
        eprint!("\r\x1b[K");
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Scan { args } => run_scan(*args, cli.verbose).await,
        Command::CheckSub { url, timeout_ms } => run_check_sub(&url, timeout_ms).await,
        Command::Wizard => match cli_wizard::run().await {
            Ok(()) => Ok(()),
            Err(err) if err.is::<cli_wizard::WizardInterrupted>() => Ok(()),
            Err(err) => Err(err),
        },
        Command::Ranges { action } => match action {
            RangesAction::Refresh { ipv6 } => {
                let (n, v6_path) = if ipv6 {
                    let n = ranges::refresh_v6_to_disk(&ranges::RealHttp).await?;
                    (n, Some(paths::refreshed_ranges_v6_path()?))
                } else {
                    let n = ranges::refresh_to_disk(&ranges::RealHttp).await?;
                    (n, None)
                };
                let family = if ipv6 { "IPv6" } else { "IPv4" };
                eprintln!(
                    "refreshed {n} {family} ranges -> {}",
                    v6_path.unwrap_or(paths::refreshed_ranges_path()?).display()
                );
                Ok(())
            }
        },
        Command::ExportConfig {
            config,
            ip,
            port,
            sni,
        } => {
            let uri = run_export_config(&config, ip, port, sni.as_deref())?;
            println!("{uri}");
            Ok(())
        }
        Command::WarpConfig { action } => match action {
            WarpConfigAction::Generate {
                out,
                license,
                endpoint,
                show_link,
            } => {
                let out = out.as_deref().map(PathBuf::from);
                let text =
                    warpgen::generate(out.as_deref(), license.as_deref(), endpoint.as_deref())
                        .await?;
                if let Some(link) = warp_config_output(&text, show_link)?.1 {
                    eprintln!("{link}");
                }
                match out {
                    Some(path) => {
                        eprintln!("identity registered; wgconf written to {}", path.display())
                    }
                    None => eprintln!("identity registered; wgconf printed above"),
                }
                Ok(())
            }
            WarpConfigAction::Export {
                out,
                endpoint,
                bind_best,
                show_link,
            } => {
                let out = out.as_deref().map(PathBuf::from);
                // WHY: this subcommand runs in a fresh process with no scan,
                // so the in-memory last scan is empty by construction
                // (results are never persisted — the NO-history invariant).
                // Resolve before any identity or network access so
                // `--bind-best` without `--endpoint` fails fast without
                // touching secrets or the API; the stamping branch mirrors
                // the wizard selection and is pinned by unit tests below.
                let (endpoint, note) =
                    plan_warp_export_endpoint(endpoint.as_deref(), bind_best, &[])?;
                let text = warpgen::export(out.as_deref(), endpoint.as_deref()).await?;
                if let Some(link) = warp_config_output(&text, show_link)?.1 {
                    eprintln!("{link}");
                }
                if let Some(note) = note {
                    eprintln!("{note}");
                }
                match out {
                    Some(path) => eprintln!("wgconf written to {}", path.display()),
                    None => eprintln!("wgconf printed above"),
                }
                Ok(())
            }
        },
        Command::Tune { action } => run_tune(action).await,
    }
}

fn check_row_json(row: &cf_scanner::check_sub::CheckRow) -> serde_json::Value {
    serde_json::json!({
        "type": "check_result",
        "config_index": row.config_index,
        "tag": row.tag,
        "server": row.server,
        "ok": row.ok,
        "latency_ms": row.latency_ms,
        "error": row.error,
    })
}

async fn run_check_sub(url: &str, timeout_ms: u64) -> Result<()> {
    use cf_scanner::check_sub;
    use cf_scanner::verify::HybridTunnelProbe;

    let rows = check_sub::check_subscription(
        url,
        &cf_scanner::configs::RealSubFetch,
        &HybridTunnelProbe::new(Arc::new(cf_scanner::verify::XrayTunnelProbe)),
        timeout_ms,
    )
    .await?;
    let mut ok = 0usize;
    for row in &rows {
        if row.ok {
            ok += 1;
        }
        let entry = check_row_json(row);
        println!("{entry}");
    }
    eprintln!("check-sub: {ok}/{} config(s) verified", rows.len());
    check_sub_verdict(ok, rows.len())?;
    Ok(())
}

/// WHY: an empty subscription verifies nothing, so it fails like any other
/// zero-pass run (documented "non-zero exit when nothing verifies").
/// Kept as a named helper so the contract is pinned by unit test.
fn check_sub_verdict(ok: usize, total: usize) -> Result<()> {
    if ok == 0 {
        anyhow::bail!("no subscription config verified ({ok}/{total})");
    }
    Ok(())
}

fn transport_for_scan_config(
    cfg: &cf_scanner::api::types::ScanConfig,
) -> Result<std::sync::Arc<dyn probe::Transport>> {
    let snis =
        probe::parse_probe_snis(&cfg.probe_snis).map_err(|e| anyhow!("invalid probe SNI: {e}"))?;
    Ok(probe::transport_for(
        cfg.probe_mode,
        &cfg.accepted_http_codes,
        &snis,
    ))
}

/// One Ctrl+C handler task per run: cancelling is idempotent and the caller
/// aborts the task when its run ends, so stacked tune steps never pile up.
fn spawn_cancel_on_ctrl_c(
    controller: &std::sync::Arc<engine::ScanController>,
) -> tokio::task::JoinHandle<()> {
    let controller = controller.clone();
    tokio::spawn(async move {
        loop {
            match tokio::signal::ctrl_c().await {
                Ok(()) => controller.cancel(),
                Err(err) => {
                    tracing::error!("could not listen for Ctrl+C: {err}");
                    break;
                }
            }
        }
    })
}

async fn run_scan(args: ScanArgs, verbose: bool) -> Result<()> {
    // WHY: stdout already streams NDJSON; both stdout exports are rejected
    // before any probe runs (stories 5-6) so a bad flag fails in ms, not
    // after minutes of scanning.
    reject_stdout_export(args.export.as_deref())?;
    reject_stdout_live_export(args.export_live.as_deref())?;
    let cfg = build_scan_config(&args)?;
    // Fail fast on an unwritable live target: every later row would fail too.
    let mut live = args
        .export_live
        .as_deref()
        .map(export::LiveExport::create)
        .transpose()
        .map_err(|e| anyhow!("could not open live export file: {e:#}"))?;
    let mut live_error: Option<anyhow::Error> = None;
    let transport = transport_for_scan_config(&cfg)?;
    let controller = Arc::new(engine::ScanController::new(transport));
    let cancel_on_ctrl_c = spawn_cancel_on_ctrl_c(&controller);
    let scan_controller = controller.clone();
    let write_line = |line: &str| {
        if write_stdout_line(line).is_err() {
            eprintln!("output pipe closed; cancelling scan");
            scan_controller.cancel();
        }
    };
    let stderr_is_tty = std::io::stderr().is_terminal();
    // T07 story 15: dropped NDJSON rows are counted so `summary.found`
    // reconciles with emitted rows; the total surfaces once on stderr below.
    // Atomics (shared with the streaming borrow) so the count survives the
    // run call that consumes the closure's borrows.
    let serialize_drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let emitted_results = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let drops_c = serialize_drops.clone();
    let emitted_c = emitted_results.clone();
    let streaming = |e: ScanEvent| match &e {
        ScanEvent::Result(v) => {
            if verbose {
                clear_ticker_line();
                eprintln!("{}", export::diagnostic_line(v));
            }
            let mut local_drops = drops_c.load(std::sync::atomic::Ordering::Relaxed);
            let line = serialize_event_counted(&e, &mut local_drops);
            drops_c.store(local_drops, std::sync::atomic::Ordering::Relaxed);
            if let Some(line) = line {
                emitted_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                write_line(&line);
                if let Some(live) = live.as_mut()
                    && let Err(err) = live.push_line(&line)
                {
                    eprintln!("live export write failed; cancelling scan: {err:#}");
                    live_error.get_or_insert(anyhow!("live export failed: {err:#}"));
                    scan_controller.cancel();
                }
            }
        }
        ScanEvent::Finished(_) | ScanEvent::Failed(_) => {
            let mut local_drops = drops_c.load(std::sync::atomic::Ordering::Relaxed);
            let line = serialize_event_counted(&e, &mut local_drops);
            drops_c.store(local_drops, std::sync::atomic::Ordering::Relaxed);
            if let Some(line) = line {
                write_line(&line);
            }
        }
        ScanEvent::Phase2Progress(p) => {
            if stderr_is_tty {
                eprintln!("phase 2: {}/{} verified", p.done, p.total);
            }
        }
        ScanEvent::Progress(p) => {
            if stderr_is_tty {
                match p.total {
                    Some(total) => eprint!(
                        "\r\x1b[Kchecked {}/{} — {} working",
                        p.scanned, total, p.found
                    ),
                    None => {
                        eprint!("\r\x1b[Kchecked {} — {} working", p.scanned, p.found)
                    }
                }
            }
        }
    };
    let result = match args.seed {
        Some(seed) => {
            controller
                .run_streaming_seeded(cfg.clone(), seed, streaming)
                .await
        }
        None => controller.run_streaming(cfg.clone(), streaming).await,
    }
    .map_err(|e| anyhow!("scan failed: {e:#}"));
    cancel_on_ctrl_c.abort();
    let drops = serialize_drops.load(std::sync::atomic::Ordering::Relaxed);
    let emitted = emitted_results.load(std::sync::atomic::Ordering::Relaxed);
    let summary = match result {
        Ok(summary) => summary,
        Err(err) => {
            clear_ticker_line();
            if drops > 0 {
                eprintln!(
                    "warning: {drops} result row(s) dropped (serialization failed); \
                     {emitted} row(s) emitted before the failure"
                );
            }
            if let Some(live) = live.as_mut() {
                let _ = live.finish();
            }
            // T07 story 16: the engine already streamed a single `Failed`
            // envelope for this run — mark it so main skips its generic
            // `--json-errors` duplicate and stdout keeps exactly one shape.
            return Err(anyhow::Error::new(ScanFailedStreamed(err.to_string())));
        }
    };
    if drops > 0 {
        eprintln!(
            "warning: {drops} result row(s) dropped (serialization failed); \
             {emitted} row(s) emitted, summary found {} working",
            summary.found
        );
    }
    clear_ticker_line();
    eprintln!(
        "scanned {} hosts, found {} working in {} ms",
        summary.scanned, summary.found, summary.duration_ms
    );
    if summary.cancelled {
        eprintln!(
            "scan cancelled — {} working endpoints retained",
            summary.found
        );
    }
    if let Err(err) = cf_scanner::retry::save_config(&cfg) {
        tracing::warn!("could not save last-scan config; --retry-last will not repeat it: {err:#}");
    }
    if args.enrich_asn {
        let enriched = enrich::enrich_working(&controller).await;
        eprintln!("asn enrichment: {enriched} endpoint annotations");
    }
    if let Some(path) = args.export.as_deref() {
        export::write_export(&controller, path, args.export_format)?;
    }
    // Flush + fsync promptly (before process exit paths below): a crash after
    // this point still leaves a parseable file.
    if let Some(live) = live.as_mut()
        && let Err(err) = live.finish()
    {
        eprintln!("live export fsync failed: {err:#}");
        live_error.get_or_insert(anyhow!("live export failed: {err:#}"));
    }
    if let Some(err) = live_error {
        return Err(err);
    }
    Ok(())
}

/// One tune trial: progress label, config to run, command to print on win.
struct TuneTrial {
    label: String,
    cfg: cf_scanner::api::types::ScanConfig,
    command: String,
}

/// Winner bar: percentage of scanned (junk/sni) or absolute passes (fragment).
enum TuneNeed {
    Pct(u32),
    Abs(u32),
}

fn tune_base_cdn(candidates: u32, timeout_ms: u64) -> cf_scanner::api::types::ScanConfig {
    use cf_scanner::api::types::{
        DEFAULT_CONCURRENCY, DEFAULT_PORT, Mode, Port, ScanConfig, ScanTarget, StopCondition,
    };
    ScanConfig {
        mode: Mode::Cdn,
        target: ScanTarget::Count(candidates),
        ports: vec![Port::new(DEFAULT_PORT)],
        stop: StopCondition {
            found: candidates,
            cap: None,
        },
        timeout_ms,
        concurrency: DEFAULT_CONCURRENCY,
        ..Default::default()
    }
}

fn tune_base_warp(candidates: u32, timeout_ms: u64) -> cf_scanner::api::types::ScanConfig {
    use cf_scanner::api::types::{
        DEFAULT_CONCURRENCY, DEFAULT_WARP_PORTS, Mode, ScanConfig, ScanTarget, StopCondition,
    };
    ScanConfig {
        mode: Mode::Warp,
        target: ScanTarget::Count(candidates),
        ports: DEFAULT_WARP_PORTS.to_vec(),
        stop: StopCondition {
            found: candidates,
            cap: None,
        },
        timeout_ms,
        concurrency: DEFAULT_CONCURRENCY,
        ..Default::default()
    }
}

/// Bounded setting search (`tune`): one fresh engine per candidate value at a
/// fixed seed, so every value sees the same sample and nothing leaks between
/// steps or into the last-scan store (no retry-save, no enrich, no NDJSON).
/// Human progress goes to stderr; stdout carries exactly one reusable scan
/// command — the first value meeting the bar, else best-so-far.
/// WHY: the tune reject paths are pure input validation; extracted from
/// `run_tune` so unit tests can pin every reject without spinning an engine.
fn validate_junk_tune(counts: &Option<Vec<u8>>, need_pct: u32) -> Result<Vec<u8>> {
    if !(1..=100).contains(&need_pct) {
        anyhow::bail!("--need-pct must be 1-100");
    }
    let counts = counts.clone().unwrap_or_else(tune::default_junk_counts);
    if counts.is_empty() || counts.len() > tune::MAX_TUNE_VALUES {
        anyhow::bail!("--counts takes 1-{} values", tune::MAX_TUNE_VALUES);
    }
    if counts
        .iter()
        .any(|&c| c == 0 || c > cf_scanner::api::types::MAX_WARP_JUNK_COUNT)
    {
        anyhow::bail!("--counts entries must be 1-128 (0 would measure junk-off)");
    }
    Ok(counts)
}

/// WHY: see `validate_junk_tune`.
fn validate_sni_tune(snis: &[String], need_pct: u32) -> Result<()> {
    if !(1..=100).contains(&need_pct) {
        anyhow::bail!("--need-pct must be 1-100");
    }
    if snis.is_empty() || snis.len() > tune::MAX_TUNE_VALUES {
        anyhow::bail!("--snis takes 1-{} hostnames", tune::MAX_TUNE_VALUES);
    }
    Ok(())
}

/// WHY: see `validate_junk_tune`.
fn validate_fragment_tune(need: u32) -> Result<()> {
    if need == 0 {
        anyhow::bail!("--need must be at least 1");
    }
    Ok(())
}

async fn run_tune(action: TuneAction) -> Result<()> {
    let (trials, per_step, timeout_ms, need): (Vec<TuneTrial>, u32, u64, TuneNeed) = match action {
        TuneAction::Junk {
            counts,
            candidates,
            need_pct,
            timeout_ms,
        } => {
            let counts = validate_junk_tune(&counts, need_pct)?;
            let mut trials = Vec::with_capacity(counts.len());
            for count in counts {
                let cfg = tune::with_junk(tune_base_warp(candidates, timeout_ms), count);
                cfg.validate()
                    .map_err(|e| anyhow!("invalid tune config: {e}"))?;
                trials.push(TuneTrial {
                    label: format!("junk={count}"),
                    command: tune::junk_command(count, candidates),
                    cfg,
                });
            }
            (trials, candidates, timeout_ms, TuneNeed::Pct(need_pct))
        }
        TuneAction::Sni {
            snis,
            candidates,
            need_pct,
            timeout_ms,
        } => {
            validate_sni_tune(&snis, need_pct)?;
            let mut trials = Vec::with_capacity(snis.len());
            for sni in snis {
                let cfg =
                    tune::with_probe_snis(tune_base_cdn(candidates, timeout_ms), vec![sni.clone()]);
                cfg.validate()
                    .map_err(|e| anyhow!("invalid tune config: {e}"))?;
                trials.push(TuneTrial {
                    label: format!("sni={sni}"),
                    command: tune::sni_command(&sni),
                    cfg,
                });
            }
            (trials, candidates, timeout_ms, TuneNeed::Pct(need_pct))
        }
        TuneAction::Fragment {
            config,
            candidates,
            need,
            timeout_ms,
        } => {
            validate_fragment_tune(need)?;
            let mut trials = Vec::with_capacity(3);
            for preset in tune::fragment_ladder() {
                let cfg = tune::with_fragment(
                    tune_base_cdn(candidates, timeout_ms),
                    &config,
                    preset.clone(),
                );
                cfg.validate()
                    .map_err(|e| anyhow!("invalid tune config: {e}"))?;
                trials.push(TuneTrial {
                    label: format!("fragment={preset}"),
                    command: tune::fragment_command(&config, preset),
                    cfg,
                });
            }
            (trials, candidates, timeout_ms, TuneNeed::Abs(need))
        }
    };

    let budget = tune::estimate_budget_ms(trials.len(), per_step, timeout_ms);
    eprintln!(
        "tune: {} values × {} endpoints (spend ceiling ≈{} ms); Ctrl+C keeps best-so-far",
        trials.len(),
        per_step,
        budget
    );
    let mut working: Vec<u64> = Vec::with_capacity(trials.len());
    let mut scanned: Vec<u64> = Vec::with_capacity(trials.len());
    for trial in &trials {
        let transport = transport_for_scan_config(&trial.cfg)?;
        let controller = Arc::new(engine::ScanController::new(transport));
        let cancel_on_ctrl_c = spawn_cancel_on_ctrl_c(&controller);
        let summary = controller
            .run_streaming_seeded(trial.cfg.clone(), tune::TUNE_SEED, |_: ScanEvent| {})
            .await
            .map_err(|e| anyhow!("tune step failed: {e:#}"))?;
        cancel_on_ctrl_c.abort();
        eprintln!(
            "{}: {}/{} working",
            trial.label, summary.found, summary.scanned
        );
        working.push(summary.found);
        scanned.push(summary.scanned);
        if summary.cancelled {
            eprintln!("tune cancelled — keeping best-so-far");
            break;
        }
    }
    if working.is_empty() {
        anyhow::bail!("tune measured nothing (cancelled before the first step finished)");
    }
    let winner = match need {
        TuneNeed::Pct(pct) => {
            let pairs: Vec<(u64, u64)> = working
                .iter()
                .copied()
                .zip(scanned.iter().copied())
                .collect();
            tune::first_meeting_pct(&pairs, pct)
        }
        TuneNeed::Abs(n) => tune::first_meeting(&working, u64::from(n)),
    };
    match winner {
        Some(i) => {
            eprintln!(
                "winner: {} ({}/{} working)",
                trials[i].label, working[i], scanned[i]
            );
            println!("{}", trials[i].command);
            Ok(())
        }
        None => match tune::best_so_far(&working) {
            Some(i) if scanned[i] > 0 => {
                eprintln!(
                    "no value met the bar — best-so-far: {} ({}/{} working)",
                    trials[i].label, working[i], scanned[i]
                );
                println!("{}", trials[i].command);
                Ok(())
            }
            _ => anyhow::bail!("tune measured nothing usable (no endpoints scanned)"),
        },
    }
}

fn serialize_event<T: serde::Serialize>(value: &T) -> Option<String> {
    match serde_json::to_string(value) {
        Ok(line) => Some(line),
        Err(err) => {
            eprintln!("could not serialize scan event: {err}");
            None
        }
    }
}

/// T07 story 15: counted wrapper so dropped rows reconcile with
/// `summary.found` — the caller surfaces the total once on stderr.
fn serialize_event_counted<T: serde::Serialize>(value: &T, drops: &mut u64) -> Option<String> {
    match serialize_event(value) {
        Some(line) => Some(line),
        None => {
            *drops += 1;
            None
        }
    }
}

fn write_stdout_line(line: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()
}

/// Pure `warp-config export --bind-best` decision (spec P0-8): an explicit
/// `--endpoint` always wins; otherwise `--bind-best` stamps the
/// lowest-latency working result, mirroring the wizard's interactive stamp
/// (bracketed IPv6 included); neither without results is a hard error.
/// Returns the override for `warpgen::export` plus the human note for
/// stderr — stdout keeps exactly the conf body, so the note never touches
/// stdout and secrets never reach either stream (only `ip:port` text).
fn plan_warp_export_endpoint(
    endpoint: Option<&str>,
    bind_best: bool,
    results: &[Verdict],
) -> Result<(Option<String>, Option<String>)> {
    if let Some(endpoint) = endpoint {
        let note = bind_best.then(|| {
            format!("--bind-best: explicit --endpoint {endpoint} wins; no scan lookup needed")
        });
        return Ok((Some(endpoint.to_owned()), note));
    }
    if !bind_best {
        return Ok((None, None));
    }
    let best = results
        .iter()
        .filter(|v| v.latency_ms.is_some())
        .min_by_key(|v| v.latency_ms.unwrap_or(u32::MAX))
        .map(|v| match v.ip {
            std::net::IpAddr::V6(_) => format!("[{}]:{}", v.ip, v.port),
            _ => format!("{}:{}", v.ip, v.port),
        })
        .ok_or_else(|| {
            anyhow!("--bind-best found no working scan results to bind; pass --endpoint explicitly")
        })?;
    let note = format!("--bind-best: bound Endpoint to best scan result {best}");
    Ok((Some(best), Some(note)))
}

/// Split a warp-config output into its stdout body and optional stderr link.
/// Pure so the stdout/stderr contract is unit-pinned: stdout keeps exactly the
/// wgconf text; the link (re-parsed from that text) travels only as a
/// returned String the caller routes to stderr.
fn warp_config_output(text: &str, show_link: bool) -> Result<(String, Option<String>)> {
    if !show_link {
        return Ok((text.to_owned(), None));
    }
    let cfg =
        wgconf::parse_wg_entry(text).map_err(|e| anyhow!("could not render share link: {e:#}"))?;
    let uri =
        wgconf::render_awg_uri(&cfg).map_err(|e| anyhow!("could not render share link: {e:#}"))?;
    Ok((text.to_owned(), Some(uri)))
}

fn reject_stdout_live_export(path: Option<&std::path::Path>) -> Result<()> {
    if path.is_some_and(|p| p.as_os_str() == "-") {
        anyhow::bail!("--export-live - is redundant: NDJSON results already stream on stdout");
    }
    Ok(())
}

fn reject_stdout_export(path: Option<&std::path::Path>) -> Result<()> {
    if path.is_some_and(|p| p.as_os_str() == "-") {
        anyhow::bail!(
            "--export - would mix the export blob into the NDJSON stream on stdout; write to a file instead (e.g. --export results.csv)"
        );
    }
    Ok(())
}

fn run_export_config(
    config: &str,
    ip: std::net::Ipv4Addr,
    port: u16,
    sni: Option<&str>,
) -> Result<String> {
    if port == 0 {
        return Err(anyhow!("--port must be in 1..=65535"));
    }
    let uri = cf_scanner::configs::export_config_uri(config, ip, port, sni, None).map_err(|e| {
        anyhow!(
            "export failed: {}",
            cf_scanner::configs::sanitize_error_text(&format!("{e:#}"))
        )
    })?;
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_scanner::api;
    use clap::Parser;

    #[test]
    fn check_sub_verdict_fails_when_nothing_verifies_including_empty() {
        assert!(
            check_sub_verdict(0, 0).is_err(),
            "empty run verifies nothing"
        );
        assert!(check_sub_verdict(0, 3).is_err());
        assert!(check_sub_verdict(2, 3).is_ok());
    }

    #[test]
    fn tune_validators_reject_bad_flags_and_accept_good_ones() {
        assert!(validate_junk_tune(&None, 30).is_ok(), "defaults are valid");
        assert!(validate_junk_tune(&Some(vec![8, 32]), 1).is_ok());
        assert!(validate_junk_tune(&Some(vec![8]), 0).is_err(), "need-pct 0");
        assert!(
            validate_junk_tune(&Some(vec![8]), 101).is_err(),
            "need-pct 101"
        );
        assert!(
            validate_junk_tune(&Some(vec![]), 30).is_err(),
            "empty counts"
        );
        assert!(
            validate_junk_tune(&Some(vec![0]), 30).is_err(),
            "junk 0 measures junk-off"
        );
        assert!(
            validate_junk_tune(&Some(vec![129]), 30).is_err(),
            "junk above the cap"
        );
        assert!(
            validate_junk_tune(&Some(vec![8; tune::MAX_TUNE_VALUES + 1]), 30).is_err(),
            "counts above the length cap"
        );
        assert!(validate_sni_tune(&["a.example.com".to_owned()], 30).is_ok());
        assert!(validate_sni_tune(&[], 30).is_err(), "empty snis");
        assert!(validate_sni_tune(&["a.example.com".to_owned()], 101).is_err());
        assert!(validate_fragment_tune(3).is_ok());
        assert!(validate_fragment_tune(0).is_err());
    }

    #[test]
    fn export_config_subcommand_renders_a_ready_uri() {
        let argv = [
            "cf-scanner",
            "export-config",
            "--config",
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443?security=tls&sni=orig.example.com&fp=chrome",
            "--ip",
            "203.0.113.7",
            "--port",
            "2096",
            "--sni",
            "b.me",
        ];
        let uri = match Cli::try_parse_from(argv).unwrap().command {
            Command::ExportConfig {
                config,
                ip,
                port,
                sni,
            } => run_export_config(&config, ip, port, sni.as_deref()).unwrap(),
            _ => unreachable!(),
        };
        assert!(
            uri.starts_with("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@203.0.113.7:2096?"),
            "{uri}"
        );
        assert!(
            uri.contains("sni=b.me") && uri.contains("fp=chrome"),
            "{uri}"
        );
    }

    #[test]
    fn export_config_rejects_bad_port_or_config() {
        let err = run_export_config(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443",
            "203.0.113.7".parse().unwrap(),
            0,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--port"), "{err}");
        let err =
            run_export_config("not a uri", "203.0.113.7".parse().unwrap(), 443, None).unwrap_err();
        assert!(err.to_string().contains("export failed"), "{err}");
    }

    #[test]
    fn verbose_defaults_log_filter_to_info() {
        assert_eq!(env_filter(true, None).to_string(), "info");
        assert_eq!(env_filter(false, None).to_string(), "error");
    }

    #[test]
    fn rust_log_wins_over_verbose() {
        assert_eq!(env_filter(true, Some("warn")).to_string(), "warn");
        assert_eq!(
            env_filter(false, Some("cf_scanner=debug")).to_string(),
            "cf_scanner=debug"
        );
        assert_eq!(env_filter(true, Some("")).to_string(), "info");
        assert_eq!(env_filter(false, Some("")).to_string(), "error");
        assert_eq!(env_filter(true, Some("  ")).to_string(), "info");
    }

    #[test]
    fn check_sub_rows_emit_config_index_for_ndjson() {
        // Contract guard for the check-sub NDJSON shape: config_index maps a
        // row back to its config position (null only for aggregate rows);
        // every row carries the "check_result" type envelope so one NDJSON
        // parser handles both scan and check-sub streams. No keys or
        // subscription content are emitted.
        let real_row = cf_scanner::check_sub::CheckRow {
            config_index: Some(0),
            tag: "a".to_owned(),
            server: "1.2.3.4:443".to_owned(),
            ok: true,
            latency_ms: Some(42),
            error: None,
        };
        let aggregate_row = cf_scanner::check_sub::CheckRow {
            config_index: None,
            tag: "<unparseable lines>".to_owned(),
            server: "-".to_owned(),
            ok: false,
            latency_ms: None,
            error: Some("1 line(s) ignored, 0 parse error(s)".to_owned()),
        };
        let line = check_row_json(&real_row).to_string();
        assert!(line.contains("\"config_index\":0"), "{line}");
        assert!(line.contains("\"ok\":true"), "{line}");
        assert!(
            line.contains("\"type\":\"check_result\""),
            "every row carries the type envelope: {line}"
        );
        let line = check_row_json(&aggregate_row).to_string();
        assert!(
            line.contains("\"config_index\":null"),
            "aggregate sentinel must be JSON-safe null, got: {line}"
        );
        assert!(
            line.contains("\"type\":\"check_result\""),
            "aggregate rows carry the envelope too: {line}"
        );
        assert!(
            !line.contains("18446744073709551615"),
            "usize::MAX must never reach NDJSON: {line}"
        );
        // JSON-safe: the aggregate value parses and is null, not a
        // precision-losing integer above JS 2^53.
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(parsed.get("config_index").is_some_and(|v| v.is_null()));
        assert_eq!(
            parsed.get("type").and_then(|v| v.as_str()),
            Some("check_result")
        );
    }

    #[test]
    fn serialize_event_never_panics() {
        struct Fails;
        impl serde::Serialize for Fails {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        let verdict = api::types::Verdict {
            ip: "1.2.3.4".parse().unwrap(),
            port: 443,
            latency_ms: Some(12),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        let line = serialize_event(&verdict).unwrap();
        assert!(line.contains("\"ip\":\"1.2.3.4\""), "{line}");
        assert!(serialize_event(&Fails).is_none());
    }

    #[test]
    fn serialize_drops_are_counted_for_stderr_reconciliation() {
        struct Fails;
        impl serde::Serialize for Fails {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        let mut drops = 0u64;
        assert!(serialize_event_counted(&Fails, &mut drops).is_none());
        assert_eq!(drops, 1, "a failed row must increment the drop counter");
        assert!(serialize_event_counted(&Fails, &mut drops).is_none());
        assert_eq!(
            drops, 2,
            "drops accumulate so the summary warning reconciles"
        );
        let verdict = api::types::Verdict {
            ip: "1.2.3.4".parse().unwrap(),
            port: 443,
            latency_ms: Some(12),
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
            asn: None,
            isp: None,
        };
        assert!(serialize_event_counted(&verdict, &mut drops).is_some());
        assert_eq!(drops, 2, "good rows must not move the counter");
    }

    #[test]
    fn streamed_scan_failures_skip_the_generic_json_duplicate() {
        // T07 story 16 pin: engine-streamed failures carry the marker, so
        // main's `{"type":"error"}` duplicate stays off and stdout keeps one
        // shape; pre-scan errors have no marker and keep the envelope.
        let streamed = anyhow::Error::new(ScanFailedStreamed("scan failed: nope".to_owned()));
        assert!(
            streamed.downcast_ref::<ScanFailedStreamed>().is_some(),
            "streamed failures must be recognizable"
        );
        assert_eq!(
            streamed.to_string(),
            "scan failed: nope",
            "stderr keeps the human text"
        );
        let plain: anyhow::Error = anyhow!("concurrency must be nonzero");
        assert!(
            plain.downcast_ref::<ScanFailedStreamed>().is_none(),
            "pre-scan failures must still get the generic envelope"
        );
    }

    fn bind_verdict(ip: &str, port: u16, latency_ms: Option<u32>) -> Verdict {
        Verdict {
            ip: ip.parse().unwrap(),
            port,
            latency_ms,
            country: None,
            colo: None,
            phase2: None,
            sent: 1,
            received: u32::from(latency_ms.is_some()),
            loss_pct: Some(if latency_ms.is_some() { 0 } else { 100 }),
            fail_reason: None,
            asn: None,
            isp: None,
        }
    }

    #[test]
    fn bind_best_stamps_lowest_latency_working_result() {
        let results = vec![
            bind_verdict("203.0.113.1", 2408, Some(50)),
            bind_verdict("203.0.113.2", 2408, Some(10)),
            bind_verdict("203.0.113.3", 2408, None),
        ];
        let (endpoint, note) = plan_warp_export_endpoint(None, true, &results).unwrap();
        assert_eq!(endpoint.as_deref(), Some("203.0.113.2:2408"));
        let note = note.expect("stamping must produce a stderr note");
        assert!(
            note.contains("203.0.113.2:2408"),
            "the note names the bound endpoint, got: {note}"
        );
    }

    #[test]
    fn explicit_endpoint_wins_over_bind_best() {
        let results = vec![bind_verdict("203.0.113.2", 2408, Some(10))];
        let (endpoint, note) =
            plan_warp_export_endpoint(Some("198.51.100.9:500"), true, &results).unwrap();
        assert_eq!(endpoint.as_deref(), Some("198.51.100.9:500"));
        let note = note.expect("the fallback must stay visible on stderr");
        assert!(
            note.contains("explicit --endpoint") && note.contains("198.51.100.9:500"),
            "got: {note}"
        );
        let (endpoint, note) =
            plan_warp_export_endpoint(Some("198.51.100.9:500"), false, &results).unwrap();
        assert_eq!(endpoint.as_deref(), Some("198.51.100.9:500"));
        assert!(
            note.is_none(),
            "no flag, no note: today's behavior is untouched"
        );
    }

    #[test]
    fn bind_best_without_working_results_is_a_hard_error() {
        let err = plan_warp_export_endpoint(None, true, &[]).unwrap_err();
        assert!(err.to_string().contains("--bind-best"), "{err:#}");
        let dead = vec![bind_verdict("203.0.113.3", 2408, None)];
        let err = plan_warp_export_endpoint(None, true, &dead).unwrap_err();
        assert!(
            err.to_string().contains("--bind-best"),
            "dead-only results bind nothing: {err:#}"
        );
    }

    #[test]
    fn export_without_bind_best_keeps_the_registered_default() {
        let results = vec![bind_verdict("203.0.113.2", 2408, Some(10))];
        let (endpoint, note) = plan_warp_export_endpoint(None, false, &results).unwrap();
        assert_eq!(endpoint, None);
        assert_eq!(note, None);
    }

    #[test]
    fn bind_best_brackets_ipv6_endpoints() {
        let results = vec![
            bind_verdict("203.0.113.2", 2408, Some(10)),
            bind_verdict("2001:db8::1", 2408, Some(5)),
        ];
        let (endpoint, _) = plan_warp_export_endpoint(None, true, &results).unwrap();
        assert_eq!(endpoint.as_deref(), Some("[2001:db8::1]:2408"));
    }

    #[test]
    fn bind_best_notes_travel_as_data_never_stdout() {
        // Contract pin: the planner is pure (results in, data out) — the
        // human note is a returned String the caller routes to stderr, so
        // export-to-stdout keeps exactly one artifact (the conf body).
        let results = vec![bind_verdict("203.0.113.2", 2408, Some(10))];
        let (_, stamp_note) = plan_warp_export_endpoint(None, true, &results).unwrap();
        let (_, fallback_note) =
            plan_warp_export_endpoint(Some("198.51.100.9:500"), true, &results).unwrap();
        let (_, silent) = plan_warp_export_endpoint(None, false, &results).unwrap();
        assert!(stamp_note.is_some() && fallback_note.is_some());
        assert!(silent.is_none());
    }

    const LINK_CONF: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nReserved = 7, 8, 9\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = 8.47.69.246:7103\n";

    #[test]
    fn warp_config_output_pins_stdout_stderr_split() {
        // Contract pin: stdout keeps exactly the wgconf body; the link
        // travels only as a returned String the caller routes to stderr.
        let (body, link) = warp_config_output(LINK_CONF, false).unwrap();
        assert_eq!(body, LINK_CONF);
        assert_eq!(link, None);
        let (body, link) = warp_config_output(LINK_CONF, true).unwrap();
        assert_eq!(body, LINK_CONF, "stdout keeps exactly the wgconf body");
        let link = link.expect("show-link must produce a stderr link");
        assert!(link.starts_with("wireguard://8.47.69.246:7103?"), "{link}");
        assert!(link.contains("reserved="), "{link}");
        assert!(link.contains("private_key="), "{link}");
        let back = cf_scanner::wgconf::parse_wg_entry(&link).expect("link must re-parse");
        assert_eq!(back.reserved, Some([7, 8, 9]));
    }

    #[test]
    fn warp_config_output_without_endpoint_is_a_hard_error() {
        let conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n";
        let err = warp_config_output(conf, true).unwrap_err();
        assert!(err.to_string().contains("share link"), "{err:#}");
    }

    #[test]
    fn reject_stdout_live_export_rejects_dash_only() {
        assert!(reject_stdout_live_export(None).is_ok());
        assert!(reject_stdout_live_export(Some(std::path::Path::new("live.jsonl"))).is_ok());
        let err = reject_stdout_live_export(Some(std::path::Path::new("-"))).unwrap_err();
        assert!(err.to_string().contains("--export-live"), "{err:#}");
    }

    #[test]
    fn reject_stdout_export_rejects_dash_with_actionable_error() {
        assert!(reject_stdout_export(None).is_ok());
        assert!(reject_stdout_export(Some(std::path::Path::new("results.csv"))).is_ok());
        let err = reject_stdout_export(Some(std::path::Path::new("-"))).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--export"), "{err:#}");
        assert!(msg.contains("NDJSON"), "{err:#}");
        assert!(msg.contains("results.csv"), "{err:#}");
    }
}
