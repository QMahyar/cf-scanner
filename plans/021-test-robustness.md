# Plan 021: De-flake async tests and property-test the credential-rendering side

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/engine/mod.rs src/server/mod.rs tests/property_tests.rs src/configs.rs src/dgst.rs src/ranges.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: S–M
- **Risk**: MED for the sleep replacements (naive rewrites can deadlock — every wait gets a timeout), LOW for the property tests
- **Depends on**: none
- **Category**: tests
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The tests guarding the v0.8.0 dispatch invariants synchronize with
wall-clock sleeps: `src/engine/mod.rs:676` and `:721` sleep 50 ms then
assert `is_running()`/reset behavior; `:849-851` busy-polls with 2 ms
sleeps; `src/server/mod.rs:1036, 1096, 1695` sleep 50–100 ms before acting;
`:1912` uses a BLOCKING `std::thread::sleep(150ms)` inside an async test.
On a loaded CI runner those windows close and the invariant tests flake.
Separately, the parser side of URI handling is property-tested
(`tests/property_tests.rs:390-502`) but the PRODUCER side —
`render_uri`/`export_config_uri` (`src/configs.rs:1127-1193`) — which
percent-encodes user credentials into share links, has only four
hand-picked cases. A missed metacharacter class there leaks or corrupts
passwords in exported configs.

## Current state

- Sleep sites (read each before touching):
  - `src/engine/mod.rs:676` — `sleep(50ms)` then `assert!(c.is_running())`
  - `src/engine/mod.rs:721` — same pattern around reset
  - `src/engine/mod.rs:849-851` — `while c.is_running() { sleep(2ms) }` busy-poll
  - `src/server/mod.rs:1036, 1096, 1695` — 50–100 ms sleeps before requests
  - `src/server/mod.rs:1912` — `std::thread::sleep(150ms)` in async test
- The GOOD pattern already in the suite:
  `run_streaming_recovers_verdicts_an_overflowing_consumer_dropped`
  (`src/engine/mod.rs:824-854`) synchronizes through a CHANNEL, not time.
- FakeTransport scripting helpers: `src/engine/mod.rs:589-621`
  (`ok_cfg`/`controller`).
- Server test harness: real spawned axum over raw TCP
  (`src/server/mod.rs:706`), registrar fakes at `:729-783`
  (`serve_with_registrar`).
- Property tests: `tests/property_tests.rs` — proptest; existing strategies
  for parse_uri/CIDR/wgconf INI at :390-502; `render_vless` helper at ~369.
- Producer under test: `src/configs.rs:1127-1193` — `render_uri` /
  `export_config_uri` (read them; note the hostile-password test at ~1154
  for style).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Targeted | `cargo test engine server property` | all pass incl. new |
| Repeat-flake check | `cargo test engine server -- --test-threads=8` (run 3×) | green every run |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/engine/mod.rs` (test module only)
- `src/server/mod.rs` (test module only)
- `tests/property_tests.rs` (new property tests)
- `src/configs.rs`, `src/dgst.rs`, `src/ranges.rs` — ONLY if a property test
  exposes a real bug (fix it in a separate commit and flag it)

**Out of scope** (do NOT touch):
- Production code (except a genuine bug found by the new property tests)
- Test harness construction (`serve_with_registrar`, FakeTransport) beyond
  adding wait helpers
- CI workflow files

## Git workflow

- Branch: `advisor/021-test-robustness`
- Commits: `test(engine): replace wall-clock sleeps with event-driven waits`, `test(server): same for server tests`, `test: property-test uri rendering and the dgst grammar`

## Steps

### Step 1: Add a bounded wait helper (engine tests)

In the engine test module add:

```rust
async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !pred() {
        assert!(tokio::time::Instant::now() < deadline, "condition not met in {timeout:?}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
```

Replace `:676` and `:721`'s `sleep(50ms)` with
`wait_until(Duration::from_secs(2), || c.is_running())` (or the actual
predicate each test needs — read them). Replace the `:849-851` busy-poll
with `wait_until(..., || !c.is_running())`.

**Verify**: `cargo test engine` green; run the engine tests 3× with
`--test-threads=8` — green every time.

### Step 2: Same for server tests

1. For `:1036, :1096, :1695`: identify what each sleep is WAITING for (a
   scan reaching running state, an SSE terminal, a registration call) and
   replace with a bounded poll of the observable (e.g. poll the status
   endpoint until `running == true`, timeout 2 s) — mirror how the test
   already talks to the spawned server (raw TCP requests at :706).
2. For `:1912` (blocking sleep in async): replace with the registrar fake
   signaling via `tokio::sync::Notify` (the registrar fake at :729-783 is
   injectable — add a Notify the fake notifies when called; the test waits
   `notify.notified()` wrapped in `tokio::time::timeout(2s)`).

**Verify**: `cargo test server` green; 3× repeat with high parallelism.

### Step 3: Property-test the URI producer

In `tests/property_tests.rs` add:

```rust
proptest! {
    #[test]
    fn render_uri_roundtrips_userinfo(
        user in r"[a-zA-Z0-9]{1,32}",
        password in any_password_strategy(),  // see below
        host in r"[a-zA-Z0-9.]{1,32}",
        port in 1u16..=65535,
    ) {
        // render a vless URI via the same helper the existing tests use,
        // re-parse with parse_uri, assert user_id == original and no
        // delimiter leakage into other fields.
    }
}
```

For `any_password_strategy`: generate over the hostile classes — build from
a strategy mixing alphanumerics with `&/?#@:%` and control chars
`\x00-\x1f`, plus a few multi-byte unicode samples (mirror the existing
strategies' style in the file; proptest string regexes don't do unicode
classes well — use `prop::collection::vec(any::<char>(), 0..32)` filtered
to exclude nothing, then assert the ROUND TRIP, which is the actual
property). Also add:
- a dgst grammar property: generated hex strings + junk → `dgst_sha256_hex`
  (or the parser's public fn — read `src/dgst.rs`) accepts exactly the
  documented grammar;
- a `validate_fetch_url` property: generated hosts — loopback/link-local
  v4 and mapped-v6 literals always refused, public IPs and domain names
  always allowed (mirror the table at `src/ranges.rs:691-704` as
  strategies).

**Verify**: `cargo test property` green. IF ANY PROPERTY FAILS: that is a
real bug — write a minimal regression test, apply the smallest fix in the
production file, put it in its OWN commit titled `fix(...): <what the
property caught>`, and flag it at the top of the report.

## Done criteria

- [ ] `rg -n "thread::sleep|sleep(Duration::from_millis(50|100|150)" src/engine/mod.rs src/server/mod.rs` → no test-side hits (production sleeps untouched)
- [ ] The blocking `std::thread::sleep` in async tests is gone
- [ ] Three new property tests exist and pass (uri round-trip, dgst grammar, fetch-url classes)
- [ ] 3× high-parallelism runs green
- [ ] Full gates green; any property-caught bug fixed in its own commit and flagged

## STOP conditions

- A wait helper cannot observe the needed condition (no exposed state) —
  add the narrowest test-only accessor (e.g. a `#[cfg(test)]` fn) rather
  than sleeping; if even that is impossible, report the site and SKIP it
  (list it in the report as remaining).
- The uri round-trip property fails on inputs the CURRENT renderer was
  never claimed to support (e.g. empty user) — narrow the strategy to the
  supported domain, note the boundary, and report it (empty-credential URIs
  may be invalid by design).
- Property test runtime explodes (>10 s for the suite) — reduce case counts
  (`proptest_config` cases) and note it.

## Maintenance notes

- `wait_until` is now the house pattern for async test synchronization —
  new tests must not sleep.
- The uri round-trip property is the security net for credential encoding —
  any change to `render_uri` runs it.
- Reviewer scrutiny: every replaced sleep must wait on the SAME condition
  the sleep was approximating (read the original test's intent comment if
  any); a changed predicate is a behavior change, not a de-flake.
