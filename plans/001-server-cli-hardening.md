# Plan 001: Server + CLI hardening (review domains API, CLI, security)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> This repo's LSP diagnostics are UNRELIABLE (phantom errors on tracing!,
> sha2 arrays, array coercions). **`cargo check` / `cargo test` are the only
> truth.** When done, commit on your branch and report: commit hash, final
> `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt
> --check` outputs, and any deviation.

## Status

- **Priority**: P1 — **Effort**: L — **Risk**: MED
- **Depends on**: none
- **Category**: bug, security
- **Planned at**: commit `cd4e3a5`, 2026-08-16

## Why this matters

Review findings on the localhost HTTP API and CLI: an SSE consumer that
falls behind loses the stream tail with no recovery; a page load after a
finished run never sees the terminal event; `/api/warp/register` is
unthrottled and clobbers an existing identity; the API accepts non-routable
custom scan ranges (a self-scan SSRF-ish footgun); API WARP scans default to
port 443; and the CLI has six UX/correctness gaps (WARP default target,
phase-2 flag guards, `--cap 0`, broken-pipe handling, shutdown hang,
duplicate error prints, wizard stdout leaks, Ctrl+C exit code).

## Current state

All line numbers were checked at the base commit `cd4e3a5`.

- `src/server.rs` — axum app. Key locations:
  - `events` handler (line ~450): `BroadcastStream::new(...).filter_map(...)`
    with `Err(_lagged) => None` — silently drops, never recovers.
  - `start_scan` (line ~408): validates, spawns `controller.run(cfg)`, returns
    202. Errors inside the spawned task are logged only — a client that
    disconnected mid-run never sees `Failed`.
  - `warp_register` (line ~541): no throttle, no identity-overwrite check.
    `RegisterRequest` (line ~517) has only `license`.
  - `AppState` (line ~180): has `controller`, `sse_connections`, `warp_register`,
    `ranges`, `start_lock`. `ScanEvent` is `Clone` (check the derive in
    `src/engine/mod.rs` — `#[derive(Clone)]` is present on the enum).
  - Test helpers: `cfg(count, found)` (line ~833) builds configs with
    `custom_cidrs: vec!["10.0.0.0/29"]` and the fakes are scripted on
    `10.0.0.x`; `post_scan(addr, body)` (line ~939) POSTs `/api/scan`.
- `src/main.rs`:
  - `build_scan_config` (line ~242): `target` defaults to
    `ScanTarget::Preset(CdnPreset::Quick)` for WARP mode too (line 262-267) —
    WARP must default to the FULL pool. `bundled_pool().host_count()` is 2048.
  - `build_phase2` (line ~310): `--phase2-custom` is silently ignored when
    `--phase2-configs` is absent or `--phase2-fragment` != custom (only the
    reverse is checked at line 331-335).
  - `run_scan` (line ~443): `ScanEvent::Failed(msg)` arm prints
    `scan failed: {msg}` (line 470-472) AND the outer `.map_err(...)` (line
    479) wraps it again → the failure is printed twice.
  - `write_stdout_line` (line ~510): swallows write errors — a closed pipe
    keeps the scan running pointlessly.
  - `shutdown_signal` (line ~554): on `ctrl_c()` error it parks on
    `std::future::pending::<()>().await` forever (line 558) — the server can
    then never shut down.
  - `run()` (line ~384): `Command::Wizard` propagates the wizard's
    "interrupted" error → main prints `error: interrupted` and exits 1.
- `src/cli_wizard.rs` — module contract: "Non-json output lives on stderr so
  stdout stays machine-readable." Violations: `println!` at lines 104, 106,
  112 (intro/aborted prose), line 139 (live scan result lines via
  `std::io::stdout().lock()`), 196 ("best scan result …"), 219 ("wgconf
  printed above"), 326 (export confirmation). **KEEP on stdout**: the actual
  wgconf text printed when no output path is given (the machine-readable
  export) and dialoguer's own prompts.

## User decisions (binding)

- No API auth token. Minimal hardening only (items S3, S4, S6 below).
- CLI stays unrestricted for ranges/ports — the non-routable rejection is
  API-only.
- WARP CLI default target = full pool.

## Commands you will need

| Purpose   | Command                          | Expected on success |
|-----------|----------------------------------|---------------------|
| Check     | `cargo check`                    | exit 0              |
| Tests     | `cargo test`                     | all pass            |
| Lint      | `cargo clippy --all-targets -- -D warnings` | exit 0    |
| Format    | `cargo fmt --check`              | exit 0              |

## Scope

**In scope**:
- `src/server.rs` (+ its tests module)
- `src/main.rs` (+ its tests module)
- `src/cli_wizard.rs`
- `src/warpgen.rs` — ONLY add `pub fn has_identity() -> bool` (3 lines)

**Out of scope** (do NOT touch, even though they look related):
- `src/api/types.rs`, `src/engine/*`, `src/configs.rs`, `src/xray.rs`,
  `src/verify.rs`, `src/warp.rs` — engine/API contract work landed in the
  base commit; do not modify.
- `embed/index.html` — separate plan.
- Adding the `webbrowser` dependency (not approved).
- Version bump (integrator does it).

## Git workflow

- Branch: `review/r3-server-cli` from `main` (`cd4e3a5`).
- Commit per logical unit; message style: `review: <what>` (see `git log`).
- Do NOT push, do NOT merge, do NOT touch `main`.

## Steps

### Step 1: SSE Lagged closes the stream

In `events` (src/server.rs ~456): a lagging consumer has irrecoverably lost
events; keep the connection open only while events flow.

Change:
```rust
let stream = BroadcastStream::new(state.controller.subscribe())
    .take_while(|item| item.is_ok())   // a Lagged receiver ends the stream
    .filter_map(move |event| { ... same mapping, but the Err arm is now unreachable; drop it ... });
```
`take_while` needs `futures_util` (already imported — `use futures_util::StreamExt` is present; the file already uses `StreamExt` for `filter_map`/`keep_alive`). Check the exact imports; add `StreamExt` if missing.

**Verify**: `cargo check` → exit 0.

### Step 2: Run epoch + terminal replay on SSE connect

Goal: a client that connects after a run ended (page load, reconnect after
Step 1's close) still receives the terminal event exactly once per run.

1. `AppState` (line ~180): add
   - `run_epoch: Arc<AtomicU64>` — incremented when a run STARTS
   - `last_terminal: Arc<Mutex<Option<(u64, ScanEvent)>>>` — Finished/Failed
     of the latest run, tagged with its epoch.
2. `start_scan`: before spawning, `let epoch = state.run_epoch.fetch_add(1, Ordering::SeqCst) + 1;`
   In the spawned task, after `controller.run(cfg).await`:
   - `Ok(summary)` → `*last_terminal.lock()... = Some((epoch, ScanEvent::Finished(summary)))`
   - `Err(err)` → sanitize the message via
     `crate::configs::sanitize_error_text(&format!("{err:#}"))` (already used
     in the file) and store `ScanEvent::Failed(msg)`.
3. `events` handler: before building the stream, if `!state.controller.is_running()`:
   ```rust
   let replay = state.last_terminal.lock().unwrap_or_else(|e| e.into_inner()).clone();
   let replay = replay.filter(|(ep, _)| *ep == state.run_epoch.load(Ordering::SeqCst));
   ```
   Map the replayed event with the same `Event::default().event(...).json_data(...)` shape as the live mapper (factor a small helper `fn map_event(ev: ScanEvent) -> Option<Event>` used by both), and prepend it:
   `let replay = futures_util::stream::once(async move { Ok(map_event(ev).unwrap()) });` then `Sse::new(replay.chain(stream)...)`. If `controller.is_running()`, no replay.

**Verify**: `cargo test --lib server` → all pass.

### Step 3: `POST /api/warp/register` rate limit (1 per 60 s)

In `warp_register`: check-and-set before doing work:
```rust
const REGISTER_COOLDOWN: Duration = Duration::from_secs(60);
let last = state.last_register.lock().unwrap_or_else(|e| e.into_inner());
if let Some(at) = *last {
    if at.elapsed() < REGISTER_COOLDOWN {
        return Err(ApiError::too_many("registration is rate-limited to one attempt per 60 s"));
    }
}
*last = Some(Instant::now());
```
Add `last_register: Mutex<Option<Instant>>` to `AppState` (default `None`).

**Verify**: `cargo test --lib server` → all pass (existing register tests still pass — check none double-fire).

### Step 4: Overwrite guard for an existing identity

1. `src/warpgen.rs`: add
   ```rust
   /// True when a registration identity is already persisted.
   pub fn has_identity() -> bool {
       load_identity().is_ok()
   }
   ```
   (Place near `persisted_server_public_key`.)
2. `RegisterRequest`: add `#[serde(default)] overwrite: Option<bool>`.
3. In `warp_register`, before the rate-limit check:
   ```rust
   if crate::warpgen::has_identity() && !req.overwrite.unwrap_or(false) {
       return Err(ApiError::conflict(
           "identity already registered; pass {\"overwrite\":true} to replace it",
       ));
   }
   ```
   (First-time registration keeps its happy path: no identity → proceed.)

**Verify**: `cargo test --lib server` → all pass. Add tests (see Test plan).

### Step 5: WARP port default over the API

In `start_scan`, after `cfg.validate()`:
```rust
// The UI's default port 443 is meaningless for WARP (UDP); substitute the
// canonical WARP ports so API-driven WARP scans probe the right ones.
if cfg.mode == Mode::Warp && cfg.ports.as_slice() == [api::types::DEFAULT_PORT] {
    cfg.ports = api::types::DEFAULT_WARP_PORTS.to_vec();
}
```
`DEFAULT_PORT`/`DEFAULT_WARP_PORTS` are in `crate::api::types` (already imported in server.rs). If you prefer testability, extract `fn apply_warp_port_default(cfg: ScanConfig) -> ScanConfig` and unit-test it directly.

**Verify**: `cargo test --lib server` → all pass.

### Step 6: API-only rejection of non-routable custom ranges/endpoints

In `start_scan`, after Step 5:

```rust
fn reject_non_routable(cfg: &ScanConfig) -> Result<(), String> {
    // Banned networks (first address must fall in one): 0.0.0.0/8,
    // 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
    // 192.168.0.0/16, ::1/128, ::/128, fc00::/7, fe80::/10.
    match cfg.mode {
        Mode::Cdn => for cidr in &cfg.custom_cidrs {
            let net = cidr.split('/').next().unwrap_or(cidr);
            if banned(net) { return Err(format!("custom_cidrs entry {cidr:?} is not routable over the API (CLI is unrestricted)")); }
        },
        Mode::Warp => for ep in &cfg.warp.clone().unwrap_or_default().custom_endpoints {
            let ip = parse_endpoint(ep).map(|(ip, _)| ip).map_err(|_| format!("bad endpoint {ep:?}"))?;
            if banned_ip(&ip) { return Err(...); }
        },
    }
    Ok(())
}
```
Implement `banned`/`banned_ip` with `std::net::IpAddr` methods (`is_loopback`, `is_link_local`, `is_unspecified`, `is_private`) PLUS the explicit 0.0.0.0/8 check (`Ipv4Addr::from(0).is_unspecified()` covers only 0.0.0.0 — check `addr.octets()[0] == 0`). `parse_endpoint` lives in `crate::api::types` (returns `(IpAddr, Option<u16>)`). Return 400 via `ApiError::bad_request(...)`.

**UPDATE THE SERVER TESTS** — the ban breaks every test that POSTs
`custom_cidrs: 10.0.0.0/29` through `post_scan` (the API would 400). Switch
the server tests' scripted pool from `10.0.0.0/29`/`10.0.0.x` to
`203.0.113.0/29`/`203.0.113.x` (TEST-NET-3, not banned):
- `cfg()` helper (line ~833): `custom_cidrs: vec!["203.0.113.0/29"]`
- Every `FakeTransport` script `.ok("10.0.0.x"...)` → `.ok("203.0.113.x"...)`
  in the server tests module (grep `10\.0\.0\.` in `src/server.rs` — engine
  tests keep 10.0.0.0/29; ONLY server.rs's own tests change).
- `warp_cfg_with_wgconf` (line ~1692): `custom_endpoints: ["10.0.0.1"]` →
  `["203.0.113.1"]`.
- The events test asserting hosts/verdicts — update expected IPs if asserted
  literally (check).

**Verify**: `cargo test --lib server` → all pass.

### Step 7: CLI — WARP default target = full pool

`build_scan_config` (src/main.rs line ~262):
```rust
let target = match (args.preset, args.count) {
    (Some(preset), None) => ScanTarget::Preset(CdnPreset::from(preset)),
    (None, Some(count)) => ScanTarget::Count(count),
    (None, None) if mode == Mode::Warp => ScanTarget::Count(crate::warp::bundled_pool().host_count()),
    (None, None) => ScanTarget::Preset(CdnPreset::Quick),
    _ => unreachable!("clap enforces preset/count exclusivity"),
};
```
(`crate::warp::bundled_pool().host_count()` = 2048.) Note `--preset` + WARP is already rejected at line 244, so the `(Some(preset), None)` arm can't reach WARP.

**Verify**: add a main.rs unit test `warp_defaults_to_the_full_pool` (see Test plan) and run it.

### Step 8: CLI — phase-2 flag guards

1. In `build_scan_config` (before `build_phase2`):
   ```rust
   if args.phase2_only {
       return Err(anyhow!("--phase2-only needs phase-1 results from a running scan; one-shot scans cannot use it"));
   }
   ```
2. In `build_phase2` (line ~318):
   ```rust
   if args.phase2_custom.is_some()
       && (args.phase2_configs.is_empty() || fragment != api::types::FragmentPreset::Custom)
   {
       return Err(anyhow!("--phase2-custom requires --phase2-configs and --phase2-fragment custom"));
   }
   ```
   (Keep the existing reverse check at 331-335.)

**Verify**: add unit tests for both rejections; run them.

### Step 9: CLI — reject `--cap 0`

In `build_scan_config`:
```rust
if args.cap == Some(0) {
    return Err(anyhow!("--cap must be at least 1"));
}
```
**Verify**: unit test + run.

### Step 10: CLI — broken stdout pipe cancels the scan

`write_stdout_line` (src/main.rs ~510) → return `std::io::Result<()>`:
```rust
fn write_stdout_line(line: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()
}
```
In `run_scan`'s streaming closure, capture `controller` (it's in scope):
```rust
ScanEvent::Result(v) => {
    if let Some(line) = serialize_event(&v) {
        if write_stdout_line(&line).is_err() {
            eprintln!("output pipe closed; cancelling scan");
            controller.cancel();
        }
    }
}
```
(and the same for `Finished`). `cancel()` is safe from the closure (it is
`FnMut`, controller is `Arc<ScanController>`).

**Verify**: `cargo build` + `cargo test --lib` → all pass. Manual check:
`cf-scanner scan ... | head -1` exits without panic (no automated test
needed — the closure compiles and the cancel path is exercised by `cancel`
tests).

### Step 11: CLI — fix shutdown hang

`shutdown_signal` (src/main.rs ~554): replace the park-forever with a plain
return:
```rust
async fn shutdown_signal(controller: Arc<engine::ScanController>) {
    if let Err(err) = tokio::signal::ctrl_c().await {
        // A broken Ctrl+C hook must not hang shutdown; serve's graceful
        // shutdown proceeds immediately.
        tracing::error!("could not listen for Ctrl+C: {err}");
        return;
    }
    tracing::info!("shutting down; cancelling any active scan");
    controller.cancel();
}
```
**Verify**: `cargo check` → exit 0.

### Step 12: CLI — wizard Ctrl+C exits 0, no error spam

`Command::Wizard` in `run()` (src/main.rs ~388):
```rust
Command::Wizard => {
    let controller = ...;
    match cli_wizard::run(controller).await {
        Ok(()) => Ok(()),
        // Ctrl+C during the wizard is a user choice, not a failure.
        Err(err) if err.to_string() == "interrupted" => Ok(()),
        Err(err) => Err(err),
    }
}
```
**Verify**: `cargo build`; manual: run wizard, Ctrl+C → exit code 0, no
"error: interrupted" (no automated test — note it in your report).

### Step 13: CLI — duplicate "scan failed" print

In `run_scan` remove the `eprintln!("scan failed: {msg}")` from the
`ScanEvent::Failed(msg)` arm (line ~470-472); the outer
`.map_err(|e| anyhow!("scan failed: {e:#}"))` (line 479) already produces
the single failure line via main's `error: {err:#}`.
**Verify**: `cargo test --lib` → all pass (check no test asserts the double
print).

### Step 14: Wizard prose → stderr

In `src/cli_wizard.rs`, convert to `eprintln!`/`eprint!` (or write to
`std::io::stderr()`): lines 104, 106, 112, 196, 219, 326, and the live scan
result lines at 138-145 (the `writeln!(out, ...)` on `std::io::stdout()`).
**Keep on stdout**: the wgconf text printed when the output path is empty
(the machine-readable export), and dialoguer's own prompts.
**Verify**: `cargo test --lib` → all pass; `cargo build --release` compiles.

## Test plan

In `src/server.rs` tests module (follow existing patterns — `serve`,
`post_scan`, `events` stream helpers):
- `events_replays_the_terminal_event_on_connect`: POST a scan (fake
  transport), consume the stream to Finished, then open a second
  `/api/events` connection → first event is `finished` with the summary.
- `register_is_rate_limited`: two `post_register` calls in quick succession →
  second is 429 (use `canned_registrar`).
- `register_refuses_overwrite_without_consent`: register once with
  `serve_with_dir` (isolated temp dir so `has_identity()` is scoped), second
  `post_register` → 409; third with `{"overwrite":true}` → 200.
- `scan_rejects_non_routable_custom_cidrs`: POST `/api/scan` with
  `custom_cidrs: ["127.0.0.1/32"]` and `["169.254.0.0/16"]` and
  `["0.0.0.0/8"]` → 400 each; and WARP with `custom_endpoints:["127.0.0.1"]`
  → 400.
- `warp_scan_over_api_uses_warp_ports`: if you extracted
  `apply_warp_port_default`, unit-test it directly (ports [443] → WARP
  ports); else POST a WARP config with ports [443] → 202 (indirect).
- Update existing tests per Step 6 (10.0.0.0/29 → 203.0.113.0/29).

In `src/main.rs` tests module:
- `warp_defaults_to_the_full_pool`: `build_scan_config` with
  `mode: ModeArg::Warp`, no preset/count → `target == ScanTarget::Count(2048)`.
- `phase2_only_is_rejected_in_one_shot_scans`
- `phase2_custom_requires_configs_and_custom_fragment` (both missing-configs
  and missing-custom-fragment variants)
- `cap_zero_is_rejected`

## Done criteria

ALL must hold:
- [ ] `cargo test` exits 0 (all suites, incl. new tests)
- [ ] `cargo clippy --all-targets -- -D warnings` exits 0
- [ ] `cargo fmt --check` exits 0
- [ ] `git status` shows ONLY the 4 in-scope files changed
- [ ] `grep -rn "10\\.0\\.0\\." src/server.rs` returns no matches (test pool moved)
- [ ] `grep -rn "std::future::pending" src/main.rs` returns no matches
- [ ] Commit(s) on `review/r3-server-cli`; report hash + verification output

## STOP conditions

- The code at the cited locations doesn't match the excerpts (drift).
- A step's verification fails twice after a reasonable fix attempt.
- You need to touch an out-of-scope file (e.g. the ban requires changes in
  `api/types.rs` — it doesn't; if you believe it does, stop).
- `ScanEvent` turns out not to be `Clone` (then stop and report before Step 2).
- A server test other than the ones listed here breaks on Step 6 and can't be
  fixed by moving its pool to 203.0.113.x.

## Maintenance notes

- The SSE replay relies on the single-run-at-a-time contract (controller
  rejects concurrent runs); if concurrency is ever added, `last_terminal`
  needs a map keyed by epoch.
- The register rate limit is process-wide (single-user localhost app);
  revisit if the API is ever exposed beyond loopback.
- `bundled_pool().host_count()` is a compile-time constant (2048); the WARP
  default count changes only when the bundled pools change.