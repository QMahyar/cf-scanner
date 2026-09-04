## Question

How do we prove the full CLI pipeline works (args → scan → export) and that
speed-test verdicts flip correctly through the real engine?

## Scope

Three test gaps from the 2026-09-06 review:

1. **No end-to-end CLI test**: `main.rs` tests only cover `build_scan_config`
   (args → config). No test runs `scan` end-to-end with `--export` and
   verifies the output file. Add an integration test (via `assert_cmd` or
   direct `run()` invocation with mock transports) that exercises:
   `scan --preset quick --count 5 --export out.csv --export-format csv`
   → verify CSV contents.

2. **FakeSpeedTester not wired through engine**: `speed.rs` has a `FakeTester`
   used only in isolated `measure_endpoint` tests. No test injects it into
   `ScanController` and verifies the full flow: passing measurement recorded,
   below-`--min-speed` verdict flipped to `!passed`. Wire it through and test
   both paths.

3. **Missing edge cases**:
   - `ScanConfig` serde round-trip (no test today)
   - `cidr_split` proptest with random inner/outer pairs
   - `trial_dir_guard` timing test uses `sleep(20ms)` — replace with retry loop
   - `live_smoke.rs` entirely `#[ignore]` without env gate — add
     `CFSCANNER_LIVE_SMOKE=1` gate + README note
   - Plan edge: `count=1` with `/32` pool, `count > pool` degradation

## Acceptance

- [ ] E2E CLI test: scan → export → verify file contents
- [ ] Speed test through engine: pass records Mbps, slow flips verdict
- [ ] `ScanConfig` serde round-trip test
- [ ] `cidr_split` proptest
- [ ] No `sleep()`-based timing in tests (retry loops only)
- [ ] Coverage gate raised from 70% → 80% lines in `checks.yml`
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Tests never touch the network (injectable transports only)
- Don't delete tests to make CI green
- `#[ignore]`-gated live tests stay `#[ignore]` by default
