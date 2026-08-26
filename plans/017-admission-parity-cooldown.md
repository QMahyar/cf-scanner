# Plan 017: One admission point for scan-config safety guards, plus an xray-download cooldown

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/server/mod.rs src/main.rs src/api/types.rs src/xray.rs src/server/state.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (Step 1 changes CLI behavior — the plan includes an explicit
  decision step; do not skip it)
- **Depends on**: none (land BEFORE plan 023's api/types split so the moved
  code is final)
- **Category**: security / consistency
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Two enforcement gaps, both verified:

1. **The non-routable-target guard exists only on the HTTP path.**
   `reject_non_routable`/`reject_default_warp_ports` are applied inside the
   `start_scan` handler only (`src/server/mod.rs:177-234`); the CLI path
   (`src/main.rs:610` `run_scan` → `build_scan_config` → `cfg.validate()`)
   never runs them. Identical config: accepted via
   `cf-scanner scan --cidr 192.168.x.x/x`, rejected via `POST /api/scan`.
   The UI mirrors the rules a third time client-side
   (`ui/src/lib/validators.ts:144`). A safety invariant enforced
   per-entry-point will be skipped by the next client.
2. **`POST /api/xray/download` has no cooldown.** The register endpoint got
   a process-wide 60 s gate for exactly this pattern (`server/state.rs:21-23`,
   `server/mod.rs:365-373`); the download handler (`server/mod.rs:493-508`)
   calls `xray::ensure_binary` directly — failures deliberately not memoized
   (`xray.rs:473-500`) — so a stuck client can loop download attempts
   indefinitely, each serialized behind one mutex held across the whole
   download window.

## Current state

- `src/server/mod.rs:177-178` — handler applies the two guards; `banned()`
  at :270-289; `reject_default_warp_ports` at :222; `reject_non_routable`
  at :234. Referenced nowhere else (grep to confirm).
- `src/main.rs:610` — `run_scan` builds the config and calls
  `cfg.validate()` (defined in `src/api/types.rs`) with no routability
  check. `src/cli_wizard.rs` similarly ends in `cfg.validate()`.
- `src/api/types.rs::ScanConfig::validate()` — the shared validation all
  three clients already call. This is the natural single admission point.
- AGENTS.md boundary: "Never scan ranges other than official CF lists, WARP
  pools, **or explicit user input**." — the CLI accepting explicit private
  CIDRs may be DELIBERATE (consenting user vs. untrusted local web page).
  Step 1 resolves this explicitly; do not skip it.
- Cooldown exemplar: `src/server/state.rs:21-23` (the register-gate fields)
  + `src/server/mod.rs:365-373` (the check-and-set + 429 mapping with code
  `rate_limited`).
- Download handler: `src/server/mod.rs:493-508`; `ensure_binary`'s
  no-memoize-on-failure comment at `xray.rs:473-500`.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Targeted | `cargo test server main cli` | all pass incl. new |

## Scope

**In scope**:
- `src/api/types.rs` (guard logic moved INTO `validate()` — struct/field
  shapes unchanged; this is behavior of validation, not the wire contract)
- `src/server/mod.rs` (handler drops its now-duplicate guards; cooldown added)
- `src/server/state.rs` (cooldown fields)
- `src/main.rs`, `src/cli_wizard.rs` (only to adapt error handling if
  validate() now rejects more)
- `docs/decisions/` — NO: record the decision as an ADR only if the
  maintainer asks; instead the decision is captured in the WHY comment and
  this plan's report.

**Out of scope** (do NOT touch):
- `ui/src/lib/validators.ts` (the UI mirror stays; it is UX, not enforcement)
- `src/xray.rs` download logic itself (only the server-side gate)
- The mapped-v6 normalization of `banned()` (plan 015 owns it; if 015
  landed, keep its version)

## Git workflow

- Branch: `advisor/017-admission-cooldown`
- Commits: `fix(api): enforce non-routable and warp-port guards at validate() for every client`, `fix(server): cooldown on xray download like registration`

## Steps

### Step 1: DECIDE the CLI policy (do this first, record it)

Read `AGENTS.md`'s boundary line (quoted above) and the current handler
guards. Two options:

- **Option A (recommended):** `ScanConfig::validate()` enforces
  non-routable + default-WARP-port rules for EVERYONE. CLI users scanning
  explicit private CIDRs lose that ability (they can still scan any public
  range; the tool's purpose is CF ranges anyway). One enforcement point.
- **Option B:** CLI stays permissive (explicit user input), server keeps
  its guards. Then instead EXTRACT the guard fns to one module used by the
  server only, and document the asymmetry in a WHY comment at
  `ScanConfig::validate()` pointing to the server-only gate.

If you cannot determine intent from the code/docs, DEFAULT TO OPTION A and
flag it prominently in the report — the asymmetry (Option B) is the kind of
implicit decision that caused this finding.

**Verify**: write the decision in the commit message body and the report.

### Step 2 (Option A): Move the guards into validate()

1. Move `banned_ip`/`banned` + `reject_non_routable` + 
   `reject_default_warp_ports` logic from `server/mod.rs` into
   `src/api/types.rs` as private helpers called from
   `ScanConfig::validate()` (iterate `custom_cidrs` and WARP endpoints —
   read what fields the guards currently check in the handler and check
   the same fields).
2. Delete the handler-side calls; keep the handler's error mapping (the
   400 with the same message text — validate() errors already map to 400
   via the existing path; verify the response CODE stays identical).
3. CLI: `run_scan`/wizard now surface the same rejection — check their
   error printing paths handle a validate() error gracefully (they
   already print validate errors; confirm no unwrap).

**Verify**: new tests in api/types.rs: a config with custom_cidr
`192.168.1.0/24` fails validate() with the same message the server used to
return; a WARP config with endpoint port 2408 (a default WARP port) with no
other ports fails; existing validate tests green. CLI test: follow
`tests/cli_scan_agent.rs` patterns — a scan invocation with a private CIDR
exits non-zero with the message on stderr (or stdout per its `--json-errors`
contract — read that test file for the assertion style).

### Step 3: Cooldown the xray download endpoint

Mirror the register gate exactly:

1. `src/server/state.rs`: add `last_xray_download: Option<Instant>` beside
   the register-gate fields (same type/lock pattern — read them).
2. In the download handler (~493-508): check-and-set with a 60 s window;
   on hit return the same `ApiError::too_many` shape the register path
   returns (code `rate_limited`) — reuse its constructor/helper.
3. Keep the single-flight mutex call to `ensure_binary` unchanged.

**Verify**: server tests: two rapid POSTs to `/api/xray/download` (with the
download seam the existing tests use — find how ensure_binary is faked or
ignored in tests; if the endpoint is untested because it touches the
network, test ONLY the gate: first request passes the gate, second within
60 s gets 429, using a state reset between subtests) — mirror the register
cooldown tests at `server/mod.rs:365-373` if they exist.

## Done criteria

- [ ] `rg -n "reject_non_routable|reject_default_warp_ports" src/server/mod.rs` → no handler-side calls (moved or deleted)
- [ ] `ScanConfig::validate()` enforces the guards (Option A) OR the extraction+doc exists (Option B) — per Step 1's recorded decision
- [ ] Download cooldown test passes; register cooldown tests still pass
- [ ] Full `cargo test` + clippy + fmt green
- [ ] The CLI policy decision is stated in the report

## STOP conditions

- Moving the guards into validate() breaks the version-parity or contract
  tests because validate() errors now include new message strings that some
  test pins — update the pins ONLY if the text change is the guard's own
  message moving; anything else, report.
- The CLI has a documented escape hatch for private CIDRs you cannot find
  in AGENTS.md but find elsewhere (README, intent doc) — STOP and report
  the contradiction instead of choosing.
- The register-gate pattern cannot be mirrored because state.rs fields are
  shaped differently than described — report the actual shape.

## Maintenance notes

- One admission point means ONE place to audit for target-safety — future
  clients (npm wrapper triggers, tray) inherit the guards for free.
- The cooldown constant should live beside the register cooldown's constant
  (same file) with a shared WHY comment.
- Reviewer scrutiny: Option A is a behavior change for CLI users — the PR
  description must call it out; the maintainer signs off on the decision.
