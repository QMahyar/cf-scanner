## Question

How do we let users say "give me N fast endpoints" instead of "give me N
endpoints and let me filter"?

## Scope

**Gap**: XIU2 cfst supports "keep scanning until N IPs satisfy `--sl`
(min speed)" as a stop condition. Morteza CFScanner has download/upload
thresholds. CF-Scanner's stop conditions are count/cap/duration only —
never quality-gated. Users who need "20 working IPs above 5 MB/s" must
manually export and filter.

**Design**:
- Extend `StopCondition` (or add a post-filter) so `--min-speed` and
  `--min-latency` / `--loss-threshold` can gate the *found count*, not just
  filter after the fact
- `stop.found` counts only IPs that pass all quality gates
- The scan continues past low-quality hits until N quality hits are found
  (or cap/timeout stops it)
- Applies to phase-1 quality signals (latency, loss) AND phase-2 speed test

**Also in scope** (same ticket, small): persist last-scan config to disk
(SenPaiScanner's "Retry Last Scan"). Store the `ScanConfig` JSON in the data
dir after each successful scan; add `scan --retry-last` flag that loads it.
Users stop re-entering parameters every run.

## Acceptance

- [ ] `--min-speed` gates the found count (scan continues until N fast IPs)
- [ ] `--min-latency` / `--loss-threshold` gate the found count
- [ ] Summary reports both "scanned" and "quality-found" counts
- [ ] `scan --retry-last` replays the previous scan's config
- [ ] Wizard offers "repeat last scan" on startup if a saved config exists
- [ ] Tests: quality-gated stop verified with mock transports
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Default behavior unchanged (no quality gates unless flags are passed)
- `StopCondition` changes need `#[serde(default)]` + ask-first (contract)
- Saved config must not include secrets (phase2 configs contain credentials —
  redact or exclude them from the saved file)
