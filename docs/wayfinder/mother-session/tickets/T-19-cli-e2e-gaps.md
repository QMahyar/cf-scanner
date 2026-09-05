# T-19 — cli-e2e-gaps (F-19)

## Gaps (`tests/cli_scan_agent.rs` harness exists — extend it)
- `--export-format base64|raw|singbox|clash` file-content checks.
- `--json-errors` failure-envelope assertion.
- `--wizard` smoke (non-interactive path? if wizard needs a TTY, test the
  headless fallback/error, not the prompts).
- WARP mode via CLI (loopback/fake transport wiring if the harness supports
  it; else TEST-NET-shaped offline mode).
- Phase-2 via CLI with FakeTunnelProbe wiring or loopback xray fake.

## Fix
Extend the existing E2E harness; follow its TEST-NET/offline pattern. No
network. If a mode cannot run offline, assert the clean offline error instead.

## Files
`tests/cli_scan_agent.rs` (+ harness helpers).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
