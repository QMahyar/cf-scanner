use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use cf_scanner::api::types::ScanEvent;
use cf_scanner::{cli_wizard, engine, export, paths, probe, ranges, warpgen};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

mod cli;
use cli::scan_args::build_scan_config;
use cli::{Cli, Command, RangesAction, ScanArgs, WarpConfigAction};

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
            if json_errors {
                let line = serde_json::json!({ "error": err.to_string() }).to_string();
                let _ = write_stdout_line(&line);
            }
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

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
        Command::Scan { args } => run_scan(*args).await,
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
            } => {
                let out = out.as_deref().map(PathBuf::from);
                warpgen::generate(out.as_deref(), license.as_deref(), endpoint.as_deref()).await?;
                match out {
                    Some(path) => {
                        eprintln!("identity registered; wgconf written to {}", path.display())
                    }
                    None => eprintln!("identity registered; wgconf printed above"),
                }
                Ok(())
            }
            WarpConfigAction::Export { out, endpoint } => {
                let out = out.as_deref().map(PathBuf::from);
                warpgen::export(out.as_deref(), endpoint.as_deref()).await?;
                match out {
                    Some(path) => eprintln!("wgconf written to {}", path.display()),
                    None => eprintln!("wgconf printed above"),
                }
                Ok(())
            }
        },
    }
}

async fn run_scan(args: ScanArgs) -> Result<()> {
    let cfg = build_scan_config(&args)?;
    let transport = probe::transport_for(cfg.probe_mode, &cfg.accepted_http_codes);
    let controller = Arc::new(engine::ScanController::new(transport));
    let cancel_on_ctrl_c = {
        let controller = controller.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => controller.cancel(),
                Err(err) => tracing::error!("could not listen for Ctrl+C: {err}"),
            }
        })
    };
    let scan_controller = controller.clone();
    let write_line = |line: &str| {
        if write_stdout_line(line).is_err() {
            eprintln!("output pipe closed; cancelling scan");
            scan_controller.cancel();
        }
    };
    let stderr_is_tty = std::io::stderr().is_terminal();
    let streaming = |e: ScanEvent| match &e {
        ScanEvent::Result(_) | ScanEvent::Finished(_) | ScanEvent::Failed(_) => {
            if let Some(line) = serialize_event(&e) {
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
        Some(seed) => controller.run_streaming_seeded(cfg, seed, streaming).await,
        None => controller.run_streaming(cfg, streaming).await,
    }
    .map_err(|e| anyhow!("scan failed: {e:#}"));
    cancel_on_ctrl_c.abort();
    let summary = match result {
        Ok(summary) => summary,
        Err(err) => {
            clear_ticker_line();
            return Err(err);
        }
    };
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
    if let Some(path) = args.export.as_deref() {
        export::write_export(&controller, path, args.export_format)?;
    }
    Ok(())
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

fn write_stdout_line(line: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()
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
        };
        let line = serialize_event(&verdict).unwrap();
        assert!(line.contains("\"ip\":\"1.2.3.4\""), "{line}");
        assert!(serialize_event(&Fails).is_none());
    }
}
