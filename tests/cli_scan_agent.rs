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
