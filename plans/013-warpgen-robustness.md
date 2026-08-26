# Plan 013: Harden warpgen — bounded response reads, sane retry policy, safe rename

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/warpgen.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: S–M
- **Risk**: LOW–MED (retry policy is behavioral; existing timeout-mapping tests cover the seams)
- **Depends on**: none
- **Category**: bug / security
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The WARP registration client has three robustness holes, all verified in
code:

1. **The response body read is outside the timeout.** `warpgen.rs:134` wraps
   only `build(http).send()` in `tokio::time::timeout(self.timeout, ...)`;
   `resp.text()` at ~149-156 is awaited bare. A slow-drip peer holds the
   call open indefinitely — the documented "~45 s worst case"
   (`src/server/mod.rs:339`) is not actually bounded, and retries never
   trigger because no timeout fires.
2. **A non-idempotent `POST v0a884/reg` is retried on transport errors**
   (~126-146 retry loop, `MAX_ATTEMPTS`). A timeout AFTER the server
   processed attempt 1 re-registers on attempt 2 — orphaned Cloudflare WARP
   devices accumulate on flaky networks; 429s also retry on a fixed 300 ms
   instead of honoring `Retry-After` (~161-164).
3. **The Windows save path does a delete-then-rename fallback** (~385-393)
   based on a false premise (`std::fs::rename` DOES replace existing files
   on Windows). A crash between the delete and the rename destroys the
   registered identity (private key + token gone).

## Current state

- `src/warpgen.rs:126-146` — `attempt`/retry loop: transport errors and
  timeouts retry up to `MAX_ATTEMPTS` (read the exact loop and error
  classification).
- `src/warpgen.rs:130-133` — per-attempt `reqwest::Client` built with
  `use_rustls_tls().no_proxy()`, default redirect policy (follow up to 10),
  NO `.timeout()` on the builder.
- `src/warpgen.rs:134` — `tokio::time::timeout(self.timeout, build(http).send())`.
- `src/warpgen.rs:149-156` — `resp.text().await?` outside any timeout.
- `src/warpgen.rs:161-164` — 429 handling sleeps a fixed 300 ms (read exact).
- `src/warpgen.rs:220-232` — `register` issues `POST {DEFAULT_API_BASE}/reg`.
- `src/warpgen.rs:385-393` — Windows rename fallback:
  ```rust
  #[cfg(windows)]
  // fallback: Windows rename does not replace an existing file
  if fs::rename(&tmp, dest).is_err() {
      fs::remove_file(dest)?;
      fs::rename(&tmp, dest)?;
  }
  ```
  (read exact; the doc comment's premise is false — `std::fs::rename`
  replaces existing files on Windows via MoveFileEx REPLACE_EXISTING).
- `src/ranges.rs:26-34` + `614-639` — the repo's canonical guarded client
  pattern (`HTTP_CLIENT` with per-hop `validate_fetch_url` redirect policy).
  The invariant (AGENTS.md): "All direct HTTPS fetches ... go through
  ranges::HTTP_CLIENT". warpgen builds its OWN client because it needs
  `.no_proxy()` — keep that requirement, add the redirect policy.
- Existing tests: `warpgen.rs:801,834` persistence tests; timeout-mapping
  tests exist (find them — `map_register_error` tests in
  `src/server/mod.rs` cover 504/429/502 mapping).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| warpgen tests | `cargo test warpgen` | all pass incl. new |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/warpgen.rs` only

**Out of scope** (do NOT touch):
- `src/server/mod.rs` (`map_register_error` stays as-is; the error TYPES this
  plan produces already map correctly)
- Identity file PERMISSIONS (Windows DACL work is plan 019 — do not touch
  `lock_down_to_owner` here)
- `src/ranges.rs` (the guarded client stays where it is; we only copy its
  redirect-policy construction pattern)

## Git workflow

- Branch: `advisor/013-warpgen-robustness`
- Commits: `fix(warpgen): bound the response-body read with the request timeout`, `fix(warpgen): retry policy — no reg retries, honor retry-after`, `fix(warpgen): drop the windows delete-then-rename fallback`, `fix(warpgen): guard redirects on the registration client`

## Steps

### Step 1: Bound the whole request lifecycle

Prefer builder-level timeout so all four call sites are covered uniformly:
on the per-attempt client builder add `.timeout(self.timeout)` (reqwest's
RequestBuilder/ClientBuilder timeout covers through end-of-body). KEEP the
existing `tokio::time::timeout` around `send()` (harmless, and preserves
current timeout-mapping test behavior) or remove it if the tests read
better — choose one, run tests.

**Verify**: `cargo test warpgen` green. New test in Step 5.

### Step 2: Retry policy — never retry registration; honor Retry-After

1. In the retry loop, classify: retries apply to GET/PATCH (fetch/adopt
   flows) and to CONNECT-level failures of POST /reg ONLY when no response
   was possibly processed — which cannot be known, so: **do not retry POST
   /reg on transport errors or timeouts at all** (attempts = 1). Keep
   retries for the other endpoints.
2. On 429: read the `Retry-After` header (seconds form; if absent or
   unparsable, fall back to the existing fixed delay), and cap the wait at
   `self.timeout` so the overall bound holds.

**Verify**: `cargo test warpgen` green; existing server-side
`map_register_error` tests stay green (error types unchanged).

### Step 3: Delete the Windows rename fallback

Remove the `#[cfg(windows)]` delete-then-rename block (~385-393) and its
false-premise comment; keep the plain `fs::rename(&tmp, dest)?`. The
temp+rename sequence itself is sound — touch nothing else.

**Verify**: `cargo test warpgen` green (persistence tests at :801/:834
cover save/load). On a Windows host (this repo's dev platform) run the
persistence tests specifically.

### Step 4: Guard redirects on the registration client

Copy the redirect-policy construction from `src/ranges.rs` `HTTP_CLIENT`
(read lines ~23-34 for the exact `Policy::custom` that calls
`validate_fetch_url` per hop) and attach an equivalent policy to the
warpgen client builder. `validate_fetch_url` is `fn`-private to ranges.rs —
check its visibility; if private, either (a) make it `pub(crate)` (one-line
change in ranges.rs, allowed) and reuse it, or (b) replicate the check —
prefer (a). Keep `.no_proxy()`.

**Verify**: `cargo test` green; `rg -n "Policy::custom" src/warpgen.rs` shows
the policy; add one WHY comment tying it to the HTTP_CLIENT invariant.

### Step 5: Tests

1. `reg_is_never_retried` — with the client seam used by existing warpgen
   tests (read how the HTTP layer is faked at :801+ — if the retry loop is
   tested via a counting fake transport, reuse it): a transport error on
   POST /reg results in exactly ONE attempt and the typed error.
2. `retry_after_is_honored` — a 429 response carrying `Retry-After: 2`
   produces a ~2 s delay (assert via elapsed ≥ 2s on an injected clock OR
   factor the delay computation into a pure fn `retry_delay(retry_after,
   fallback) -> Duration` and unit-test THAT — prefer the pure fn).
3. `save_replaces_existing_identity` — call save twice; second save
   succeeds and content updates (runs on all platforms; this is the
   regression test for Step 3).

**Verify**: `cargo test warpgen` green.

## Done criteria

- [ ] `rg -n "remove_file" src/warpgen.rs` → no hits in the save path
- [ ] POST /reg attempts === 1 on transport failure (test)
- [ ] `Retry-After` respected with fallback (pure-fn test)
- [ ] Client builder has `.timeout(self.timeout)` and a redirect policy that validates per hop
- [ ] Full `cargo test` + clippy + fmt green

## STOP conditions

- The retry loop's structure doesn't distinguish endpoints (a single generic
  retry helper) — report the actual structure; implement per-endpoint attempt
  counts without redesigning the client.
- `validate_fetch_url` cannot be made `pub(crate)` cleanly (visibility web) —
  use option (b) and note the duplication for plan 024's ranges split.
- The persistence tests rely on the delete-then-rename branch (i.e. they fail
  on Windows after Step 3 for reasons OTHER than the removed fallback) —
  report the failure; do not re-add the fallback.

## Maintenance notes

- The registration client is now bounded end-to-end: per-attempt timeout +
  redirect guard + no-reg-retry. Any NEW warpgen endpoint must follow the
  same trio.
- The `retry_delay` pure fn is the place for future backoff policy (jit,
  caps).
- Reviewer scrutiny: confirm `map_register_error` in server/mod.rs still maps
  the typed errors to 504/429/502 (no error-variant renamed).
