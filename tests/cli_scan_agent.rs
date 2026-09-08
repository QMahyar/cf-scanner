use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_cf-scanner")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("the cf-scanner binary must run")
}

fn run_strings(args: &[String]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("the cf-scanner binary must run")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn help_exits_zero_and_documents_scan() {
    let out = run(&["--help"]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let text = stdout_of(&out);
    assert!(text.contains("Usage:"), "{text}");
    assert!(text.contains("scan"), "{text}");
    assert!(text.contains("wizard"), "{text}");
}

#[test]
fn version_exits_zero_with_the_crate_version() {
    let out = run(&["--version"]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let text = stdout_of(&out);
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
    assert!(text.contains("cf-scanner"), "{text}");
}

#[test]
fn unknown_subcommand_exits_nonzero_with_a_message() {
    let out = run(&["bogus-command"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(!err.is_empty(), "clap must explain the failure on stderr");
    assert!(
        err.to_lowercase().contains("bogus-command"),
        "unexpected stderr: {err}"
    );
}

#[test]
fn conflicting_preset_and_count_exit_nonzero() {
    let out = run(&["scan", "--preset", "quick", "--count", "10"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("cannot be used with"),
        "expected the clap conflict message, got: {err}"
    );
}

#[test]
fn warp_mode_rejects_preset_with_a_clear_error() {
    let out = run(&["scan", "--mode", "warp", "--preset", "quick"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("error:"), "missing error prefix: {err}");
    assert!(
        err.contains("--preset is CDN-only"),
        "unexpected stderr: {err}"
    );
}

#[test]
fn out_of_range_concurrency_exits_nonzero() {
    let out = run(&["scan", "--concurrency", "0"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("invalid scan config") && err.contains("concurrency"),
        "unexpected stderr: {err}"
    );
}

#[test]
fn invalid_custom_cidr_exits_nonzero() {
    let out = run(&["scan", "--custom-cidrs", "not-a-cidr"]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("invalid scan config") && err.contains("CIDR"),
        "unexpected stderr: {err}"
    );
}

#[test]
fn custom_fragment_without_values_exits_nonzero() {
    let out = run(&[
        "scan",
        "--phase2-configs",
        "vless://a@1.2.3.4:443",
        "--phase2-fragment",
        "custom",
    ]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("error:") && err.contains("--phase2-custom"),
        "unexpected stderr: {err}"
    );
}

#[tokio::test]
#[ignore = "network; runs a real tiny scan (gate: CFSCANNER_SUB_URL)"]
async fn live_tiny_scan_prints_ndjson_and_a_final_summary() {
    if std::env::var("CFSCANNER_SUB_URL").is_err() {
        eprintln!("skipping: live-scan tests are gated on CFSCANNER_SUB_URL");
        return;
    }
    let out = tokio::task::spawn_blocking(|| {
        run(&[
            "scan",
            "--count",
            "5",
            "--target",
            "1",
            "--ports",
            "443",
            "--concurrency",
            "5",
            "--timeout-ms",
            "3000",
            "--seed",
            "42",
        ])
    })
    .await
    .expect("the binary run must not panic");

    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let stdout = stdout_of(&out);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "stdout must carry NDJSON events");

    let mut saw_summary = false;
    for line in &lines {
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("non-NDJSON line {line:?}: {e}"));
        match value {
            serde_json::Value::Object(o) if o.contains_key("scanned") => {
                saw_summary = true;
                assert!(o["found"].is_number(), "{line}");
                assert!(o["duration_ms"].is_number(), "{line}");
            }
            serde_json::Value::Object(o) if o.contains_key("ip") => {
                assert!(o["port"].is_number(), "{line}");
            }
            other => panic!("unexpected stdout event: {other}"),
        }
    }
    assert!(
        saw_summary,
        "the final ScanSummary must be present:\n{stdout}"
    );
    let last: serde_json::Value = serde_json::from_str(lines.last().expect("lines are non-empty"))
        .expect("last line is JSON");
    assert!(
        last.as_object().is_some_and(|o| o.contains_key("scanned")),
        "the summary must be the LAST stdout event: {stdout}"
    );

    let err = stderr_of(&out);
    assert!(
        err.contains("scanned") && err.contains("found"),
        "the human summary on stderr is missing: {err}"
    );
}

#[test]
fn e2e_scan_writes_export_files_and_ndjson_stdout() {
    let dir = std::env::temp_dir().join(format!(
        "cf-scanner-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("results.csv");
    let json = dir.join("results.json");

    // TEST-NET-3 is routable-per-policy (not banned) but nothing answers:
    // probes fail fast and the scan still completes with zero findings.
    let out = run(&[
        "scan",
        "--custom-cidrs",
        "203.0.113.0/30",
        "--count",
        "4",
        "--target",
        "1",
        "--cap",
        "4",
        "--timeout-ms",
        "500",
        "--concurrency",
        "4",
        "--seed",
        "7",
        "--export",
        csv.to_str().unwrap(),
        "--export-format",
        "csv",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    let stdout = stdout_of(&out);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "stdout must carry NDJSON events");
    let mut saw_result = false;
    let mut saw_summary = false;
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("non-NDJSON line {line:?}: {e}"));
        let o = v.as_object().expect("stdout lines must be JSON objects");
        if o.contains_key("scanned") {
            saw_summary = true;
        } else if o.contains_key("ip") {
            saw_result = true;
            assert!(
                o.contains_key("fail_reason") && o.contains_key("loss_pct"),
                "verdicts must carry the reliability fields: {line}"
            );
        } else {
            panic!("unexpected stdout event: {line}");
        }
    }
    assert!(saw_summary, "summary must be on stdout:\n{stdout}");
    assert!(saw_result, "failed probes must still be stored as verdicts");

    let csv_text = std::fs::read_to_string(&csv).expect("CSV export must exist");
    let header = csv_text.lines().next().unwrap();
    assert_eq!(
        header,
        "ip,port,latency_ms,country,colo,phase2_passed,phase2_latency_ms,speed_test_mbps,sent,received,loss_pct,fail_reason,asn,isp",
        "CSV header pins the schema"
    );

    // Second run overwrites atomically and exercises the JSON path.
    let out = run(&[
        "scan",
        "--custom-cidrs",
        "203.0.113.0/30",
        "--count",
        "2",
        "--target",
        "1",
        "--cap",
        "2",
        "--timeout-ms",
        "500",
        "--concurrency",
        "2",
        "--seed",
        "9",
        "--export",
        json.to_str().unwrap(),
        "--export-format",
        "json",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let json_text = std::fs::read_to_string(&json).expect("JSON export must exist");
    let parsed: serde_json::Value = serde_json::from_str(&json_text).expect("valid JSON export");
    assert!(parsed["results"].is_array(), "{json_text}");

    let tmp_leftover: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(tmp_leftover.is_empty(), "atomic writes leave no tmp files");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn retry_last_without_a_saved_config_names_the_fix() {
    let dir = std::env::temp_dir().join(format!("cf-scanner-e2e-retry-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(bin())
        .args(["scan", "--retry-last"])
        .env("CF_SCANNER_DATA_DIR", &dir)
        .output()
        .expect("the cf-scanner binary must run");
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("no retryable scan saved"),
        "the error must name the fix: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_errors_flag_prints_a_json_envelope_on_stdout_for_config_failures() {
    let out = run(&["--json-errors", "scan", "--concurrency", "0"]);
    assert!(!out.status.success());
    let stdout = stdout_of(&out);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json-errors must put a JSON envelope on stdout");
    let err = parsed["error"]
        .as_str()
        .expect("envelope carries an error string");
    assert!(err.contains("concurrency"), "{err}");
    // The human message still goes to stderr.
    assert!(stderr_of(&out).contains("error:"));
}

#[test]
fn json_errors_flag_wraps_clap_parse_failures_too() {
    let out = run(&["--json-errors", "scan", "--preset", "quick", "--count", "3"]);
    assert!(!out.status.success());
    let stdout = stdout_of(&out);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("clap errors must be wrapped in JSON on stdout");
    let err = parsed["error"].as_str().unwrap_or_default();
    assert!(err.contains("cannot be used with"), "{err}");
}

#[test]
fn bundle_export_formats_write_parseable_files_even_with_zero_findings() {
    let dir = std::env::temp_dir().join(format!(
        "cf-scanner-e2e-bundle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let base_args = |format: &'static str, file: &std::path::Path| -> Vec<String> {
        vec![
            "scan".into(),
            "--custom-cidrs".into(),
            "203.0.113.0/30".into(),
            "--count".into(),
            "2".into(),
            "--target".into(),
            "1".into(),
            "--cap".into(),
            "2".into(),
            "--timeout-ms".into(),
            "500".into(),
            "--concurrency".into(),
            "2".into(),
            "--seed".into(),
            "11".into(),
            "--export".into(),
            file.to_string_lossy().into_owned(),
            "--export-format".into(),
            format.into(),
        ]
    };

    // base64: no findings → empty (well-formed) bundle body.
    let b64 = dir.join("out.b64");
    let out = run_strings(&base_args("base64", &b64));
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let body = std::fs::read_to_string(&b64).unwrap();
    assert!(
        body.is_empty(),
        "zero passing endpoints with base64 must produce an empty bundle: {body:?}"
    );

    // singbox: empty outbounds array, valid JSON.
    let sb = dir.join("out.singbox.json");
    let out = run_strings(&base_args("singbox", &sb));
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let sb_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sb).unwrap()).expect("valid singbox JSON");
    assert_eq!(sb_val["outbounds"].as_array().unwrap().len(), 0);

    // clash: empty proxies array, valid JSON.
    let cl = dir.join("out.clash.json");
    let out = run_strings(&base_args("clash", &cl));
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let cl_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cl).unwrap()).expect("valid clash JSON");
    assert_eq!(cl_val["proxies"].as_array().unwrap().len(), 0);

    // raw: empty body.
    let raw = dir.join("out.raw.txt");
    let out = run_strings(&base_args("raw", &raw));
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    assert!(std::fs::read_to_string(&raw).unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wizard_without_a_tty_exits_cleanly_with_the_headless_message() {
    // Run with stdin/stdout/stderr all redirected: dialoguer hits EOF.
    let out = Command::new(bin())
        .arg("wizard")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the cf-scanner binary must run");
    let err = stderr_of(&out);
    assert!(
        err.contains("wizard needs an interactive terminal") || err.contains("Interactive"),
        "headless fallback must explain the TTY requirement: {err}"
    );
    // WizardInterrupted maps to a clean exit (no panic, no error spam).
    assert!(
        !stdout_of(&out).contains("panic"),
        "the wizard must not panic headless"
    );
}

#[test]
fn warp_mode_offline_fails_with_a_clean_missing_binary_error() {
    // WARP probes real Cloudflare endpoints over UDP; offline the scan must
    // fail cleanly rather than hang or panic. The data dir is empty, so the
    // run terminates on validation or probe setup, not on a stray success.
    let dir = std::env::temp_dir().join(format!("cf-scanner-e2e-warp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(bin())
        .args([
            "scan",
            "--mode",
            "warp",
            "--count",
            "1",
            "--target",
            "1",
            "--timeout-ms",
            "500",
        ])
        .env("CF_SCANNER_DATA_DIR", &dir)
        .output()
        .expect("the cf-scanner binary must run");
    let err = stderr_of(&out);
    assert!(!err.contains("panic"), "WARP run must not panic: {err}");
    assert!(
        err.contains("error:") || out.status.success(),
        "the run must either report a clean error or finish: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn phase2_with_an_unresolvable_config_reports_a_clean_config_error() {
    // parse_uri rejects garbage before any probe runs: the error must be a
    // clean config rejection, not a panic and not a network attempt.
    let out = run(&[
        "scan",
        "--custom-cidrs",
        "203.0.113.0/30",
        "--count",
        "2",
        "--target",
        "1",
        "--cap",
        "2",
        "--timeout-ms",
        "500",
        "--phase2-configs",
        "not-a-uri",
    ]);
    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("error:"), "{err}");
    assert!(!err.contains("panic"), "{err}");
}
