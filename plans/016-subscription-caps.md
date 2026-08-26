# Plan 016: Bound subscription ingestion — streaming size cap and spec-count ceiling

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/ranges.rs src/configs.rs src/engine/phase2.rs src/api/types.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (caps must be generous enough for legitimate subscriptions; fail loudly, never silently truncate)
- **Depends on**: none (after plan 010/014 avoids same-file churn, not required)
- **Category**: security
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Subscription URLs are user-supplied and fetched at scan start — the threat
model explicitly includes hostile URLs. Today the ingestion path buffers the
ENTIRE response before checking the 64 MiB cap (`ranges.rs:576-590` awaits
`response.bytes()` then compares), `parse_subscription` pushes every
parseable line with no count ceiling (`configs.rs:316-330`), and phase-2
extends the spec list unbounded across all allowed config entries
(`engine/phase2.rs:230-290`), multiplying verification work by candidates ×
specs × SNIs. A hostile or oversized subscription turns one scan start into
hundreds of MB of buffering and unbounded verification churn on the user's
machine.

## Current state

- `src/ranges.rs:540-592` — `fetch_tls`/`fetch_tls_inner`: the shared
  `HttpGet` path; ~576-590 does `response.bytes().await?` (full buffering)
  then `if body.len() > MAX_BODY_BYTES { bail }`. `MAX_BODY_BYTES = 64 MiB`
  (const near the top; read exact). Content-Length is not pre-checked; no
  incremental cap while streaming.
- `src/configs.rs:316-330` — `parse_subscription`: splits lines, parses each,
  pushes to `specs`, counts `ignored`; no maximum.
- `src/engine/phase2.rs:230-290` — `parse_phase2_configs`: loops the ≤8
  config entries (URI or subscription), `specs.extend(...)` per entry; no
  total ceiling. Verification multiplies candidates × specs × SNIs
  (~72-98).
- `src/api/types.rs:22-49` — the `MAX_*` caps family (the contract's
  validation constants). `MAX_ENDPOINTS = 2048` at :49.
- Repo rule (AGENTS.md): every network call sets its own timeout; the
  fetch client has NO global timeout BY DESIGN — keep per-call timeouts.
- Repo rule: fail loudly — `socks.rs:46-51`'s comment is the house style
  ("an explicit failure, not a silent truncation").

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Targeted | `cargo test ranges configs phase2` | all pass incl. new |

## Scope

**In scope**:
- `src/ranges.rs` (streaming/incremental cap in `fetch_tls_inner`)
- `src/configs.rs` (spec-count ceiling in `parse_subscription`)
- `src/engine/phase2.rs` (total spec ceiling across entries)
- `src/api/types.rs` ONLY to add a `pub const` if the new caps belong with
  the MAX_* family (adding a constant is NOT a contract change — no struct
  or field changes; if you find yourself touching structs, STOP)
- Test modules in those files

**Out of scope** (do NOT touch):
- The redirect guard / `validate_fetch_url` (plan 015 owns its V6 fix)
- Decompression (flate2 is not in the runtime path — no decompression bomb
  surface at runtime today; do not add decompression)
- The xray zip caps (`src/xray.rs` — already capped)
- Any UI code

## Git workflow

- Branch: `advisor/016-subscription-caps`
- Commits: `fix(ranges): cap response bodies incrementally instead of after buffering`, `fix(configs): ceiling on subscription-expanded specs`, `fix(phase2): total spec ceiling across config entries`

## Steps

### Step 1: Choose and document the caps

Add to the `MAX_*` family (in `ranges.rs` for the byte cap if it lives
there, and `api/types.rs` alongside MAX_ENDPOINTS for the spec counts —
mirror where each existing constant lives):

- `MAX_SUBSCRIPTION_SPECS = 2048` per subscription entry (mirrors
  MAX_ENDPOINTS' spirit; generous for real feeds).
- `MAX_PHASE2_TOTAL_SPECS = 4096` across all entries in one scan config.
- Keep `MAX_BODY_BYTES = 64 MiB` as the hard byte cap.

One WHY comment each: hostile-subscription bounding, generous for real
feeds, fail-loudly rule.

### Step 2: Incremental body cap in fetch_tls_inner

Replace the buffer-then-check with a bounded read. reqwest's
`response.chunk().await?` (bytes_stream without the `stream` feature:
`resp.chunk()` is available on Response by default) allows:

```rust
let mut body: Vec<u8> = Vec::new();
while let Some(chunk) = response.chunk().await? {
    if body.len() + chunk.len() > MAX_BODY_BYTES {
        bail!("response exceeds {MAX_BODY_BYTES} byte cap");
    }
    body.extend_from_slice(&chunk);
}
```

Keep the existing per-call `.timeout(...)` semantics EXACTLY (read the
current call site; the overall-call timeout must still bound the whole
read — if the current timeout wraps only `send()`, wrap the whole
read loop in the same `tokio::time::timeout`). Honor Content-Length when
present as an early bail (`if let Some(len) = response.content_length() &&
len as u64 > MAX → bail` before reading).

**Verify**: `cargo test ranges` green. New test: the existing fetch tests
use a local TLS server (rcgen is a dev-dep — find the test harness that
serves fake HTTPS, likely in ranges.rs tests); add a case serving
MAX+1 bytes slowly → error mentions the cap; a normal-size body still
succeeds.

### Step 3: Spec-count ceiling in parse_subscription

Add `max_specs: usize` (or use the new const directly) to
`parse_subscription`: when `specs.len()` would exceed
`MAX_SUBSCRIPTION_SPECS`, bail with a clear ConfigError-style message
("subscription expands to more than N configs" — match the existing error
wording style in configs.rs).

**Verify**: new test: a subscription body with 3000 valid vless URIs →
error naming the cap; 100 URIs → all parsed.

### Step 4: Total ceiling across phase-2 entries

In `parse_phase2_configs`, track a running total; before each
`specs.extend(...)`, bail (or skip-with-warning — read how partial config
failures are handled today and MATCH that policy; if a bad entry is a hard
error, make the ceiling a hard error too) when the total would exceed
`MAX_PHASE2_TOTAL_SPECS`.

**Verify**: new test: two subscription entries each expanding large →
error at the total cap; existing phase-2 parse tests green.

## Done criteria

- [ ] `rg -n "response.bytes\(\)" src/ranges.rs` → no hits in fetch_tls_inner (replaced by chunked read)
- [ ] Content-Length early-bail present; incremental cap test passes
- [ ] Both spec ceilings enforced with tests
- [ ] Full `cargo test` + clippy + fmt green; no out-of-scope files
- [ ] New constants live beside the existing MAX_* family with WHY comments

## STOP conditions

- The test harness has no local HTTPS server seam for ranges tests (rcgen
  exists but maybe unused for this path) — implement the byte-cap test with
  whatever seam EXISTS (even a unit test on a extracted `read_capped_body`
  helper fed by a fake stream); extract the helper if needed.
- `response.chunk()` is unavailable on the locked reqwest version without
  the `stream` feature — check `Cargo.toml` reqwest features; enabling a
  feature is an "ask first" dependency change per AGENTS.md → report
  instead of enabling.
- Existing phase-2 tests feed subscriptions larger than the new caps (real
  fixtures) — report the sizes; do not silently shrink fixtures.

## Maintenance notes

- The three caps (body bytes, per-entry specs, total specs) are the
  ingestion bound triangle — any new ingestion path (new config source)
  must respect all three.
- If real users hit `MAX_SUBSCRIPTION_SPECS` legitimately, raise it via the
  constant with a changelog note — never truncate silently.
- Reviewer scrutiny: the timeout must still bound the STREAMING read (a
  slow-drip server within the byte cap must still hit the call timeout).
