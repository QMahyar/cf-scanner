## Question

How do we expose per-IP failure diagnostics so power users can tune scan
parameters without guessing?

## Scope

**Gap**: XIU2 cfst and WaldonCFscanner both print exact failure modes per IP
(reset / 403 / timeout / TLS mismatch / cert expired). CF-Scanner stores
`fail_reason` in the verdict but the CLI only prints a progress ticker.
Users can't distinguish TLS-fail from timeout from HTTP-rejection when tuning
`--loss-threshold` or `--idle-hold-ms`.

**Design**:
- Add `--verbose` flag to `scan` command
- In verbose mode, print per-IP diagnostic lines to stderr:
  `IP:PORT — refused (connection refused after 12ms)`
  `IP:PORT — tls_failed (handshake timeout after 3000ms)`
  `IP:PORT — http_status (got 403, want 200/301/302)`
  `IP:PORT — timeout (no response after 3000ms)`
- Also print `fail_reason` + `loss_pct` in the NDJSON output (already in
  verdict — just ensure it's serialized)
- Non-verbose mode unchanged (progress ticker only)

## Acceptance

- [ ] `--verbose` prints per-IP failure lines to stderr
- [ ] Failure lines include IP:port, reason, and timing detail
- [ ] NDJSON output includes `fail_reason` / `loss_pct` in verbose and normal
- [ ] Wizard prompts for verbose mode (yes/no, default no)
- [ ] Docs: README documents `--verbose` with example output
- [ ] Tests: verbose output format pinned by at least one test
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Never log configs, keys, or full URLs in verbose output
- Stderr only for human noise (stdout stays NDJSON-clean for agents)
- New CLI flag needs `#[serde(default)]` if it touches `ScanConfig`
