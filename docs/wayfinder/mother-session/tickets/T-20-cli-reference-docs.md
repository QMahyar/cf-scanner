# T-20 — cli-reference-docs (F-20)

## Gaps
- README Commands table omits ~20 flags (`--phase2-*`, `--warp-*`,
  `--concurrency/--timeout-ms/--exclude/--custom-cidrs/--seed/--http-status-code`,
  `export-config --sni`, `warp-config` sub-flags, scan `--ipv6`).
- 15 flags have ZERO `--help` text (`--json-errors` included);
  `--min-latency` misleads; `--target` vs `--cap` undocumented; preset sizes
  undescribed; `--phase2-fragment` values lack byte/timing details;
  `--enrich-asn` wrong heading; `--neighbor-scan` jargon; EXAMPLES conflicts;
  `export-config` vague.
- Zero WARP/phase-2 troubleshooting; missing key-workflow examples.

## Fix
1. `src/cli.rs`: write/repair every help string (each `long` flag gets a
   real description; document `--target` vs `--cap`, preset sizes,
   fragment byte/timing values, `probe_url` precedence).
2. README: full Commands reference synced to `--help` + Troubleshooting
   section (WARP no-results, phase-2 xray download/glibc, ranges refresh
   failure, SmartScreen/Termux pointers) + 3-5 key-workflow examples.
3. CI gate: grep test that every `long = "` flag in `src/cli.rs` appears in
   README AND has a non-empty `help = "`/`long_help`. (Keeps this from
   rotting again.)

## Files
`src/cli.rs`, `README.md`, `.github/workflows/checks.yml` (+ gate script).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
