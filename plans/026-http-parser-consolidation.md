# Plan 026: Consolidate the two hand-rolled HTTP/1.1 response parsers onto one generic reader

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/socks.rs src/inline_verify.rs`
> Assumes plan 014 landed (its truncation/query fixes touch both files) —
> re-locate by content if line numbers shifted.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: MED (inline_verify reads through a TLS-in-TLS `PrefixedReader`
  with subtly different semantics; needs a spike-first approach and the
  property suite as the net)
- **Depends on**: plans/014 (fixes land first), 021 (property tests exist
  as the safety net — if 021 hasn't landed, write the parser round-trip
  property test FIRST inside this plan)
- **Category**: tech-debt
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Two hand-rolled HTTP/1.1 response parsers do the same job class and WILL
drift: `src/socks.rs:31-90` `send_http` (status+headers+body, chunked
support, `MAX_BODY_BYTES` cap over any `AsyncRead`) and
`src/inline_verify.rs:503-630` (`read_http_response`/`read_http_body`/
`read_line` with its own `MAX_PROBE_BODY_BYTES` cap and
content-length/close-delimited handling, reusing only `socks::decode_chunked`).
Parser hardening (caps, CRLF edge cases, header folding) must currently be
fixed twice — the two probes would then classify the SAME server differently,
which for a verification tool means contradictory verdicts.

## Current state

- `src/socks.rs:31-90` — `send_http`: writes a request, reads status line +
  headers (CRLF-terminated lines via a `read_line`-style helper), then body
  by content-length / chunked / close-delimited, capped by `MAX_BODY_BYTES`.
  Also exports `decode_chunked` (used by inline_verify at ~577).
- `src/inline_verify.rs:503-630` — `read_http_response` + `read_http_body` +
  `read_line`: parallel implementation; `MAX_PROBE_BODY_BYTES` const (~561
  area); plan 014 made over-cap close-delimited bodies FAIL here.
- The stream types differ: socks reads a plain tunnel `AsyncRead`;
  inline_verify reads through its `PrefixedReader` (~449) wrapping
  TLS-in-TLS — the reader is GENERIC over `AsyncRead` in both cases; the
  difference is which stream is passed in, not the parsing logic.
- Tests: framing tests exist in both files' test modules; plan 021 added
  property coverage for URI rendering (NOT for these parsers — if 021's
  parser property tests don't exist, Step 1 adds them).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |
| Parser tests | `cargo test socks inline_verify` | all pass incl. new |

## Scope

**In scope**:
- `src/socks.rs` (gains the generic `http_wire::read_response`)
- `src/inline_verify.rs` (deletes its duplicates, calls the shared reader)
- Test modules in both files

**Out of scope** (do NOT touch):
- Request WRITING (both sides build requests differently by necessity —
  only RESPONSE reading consolidates)
- `decode_chunked` semantics (it moves or gets re-exported, body unchanged)
- TLS/verification logic, probe classification

## Git workflow

- Branch: `advisor/026-http-parser-consolidation`
- Commits: `test: property-test the http response readers against each other`, `refactor(socks): extract a generic read_response`, `refactor(inline): consume the shared reader, delete the duplicates`

## Steps

### Step 1: Differential property test FIRST (the net)

In the socks.rs test module (or tests/), add a proptest that feeds the SAME
synthetic byte streams (valid responses, chunked, content-length,
close-delimited, truncated, over-cap, CRLF variants, huge headers) to BOTH
current parsers and asserts they agree on: parsed-or-error, status, body
bytes (or error class). Generate streams from a strategy mixing the framing
modes. This test pins CURRENT behavior — including any disagreements, which
you must LIST in the report (they are pre-existing drift, not regressions).

**Verify**: `cargo test` green with the differential test (agreements
asserted; disagreements EXCLUDED explicitly with a comment listing them —
or assert equality if they already agree everywhere, which is unlikely).

### Step 2: Spike — extract the generic reader

In `socks.rs`, extract `pub(crate) async fn read_response<S: AsyncRead +
Unpin>(stream: &mut S, max_body: usize) -> Result<ParsedResponse, ...>`
from `send_http`'s read side (keep `send_http` calling it). `ParsedResponse`
= whatever struct both sites need (status + headers + body; read both
callers' consumption and design the minimal shape).

**Verify**: `cargo test socks` green (send_http behavior unchanged — the
differential test from Step 1 still passes with socks' results identical).

### Step 3: Switch inline_verify onto it

1. Replace `read_http_response`/`read_http_body`/`read_line` bodies with
   calls to `socks::read_response` (import path per visibility; if
   inline_verify needs different CAP semantics — it has its own const —
   that's what the `max_body` parameter is for).
2. Where the differential test documented disagreements, the SHARED parser
   now behaves ONE way for both callers: for each former disagreement,
   choose the behavior that matches each caller's contract comments
   (`socks.rs:46-51` and `inline_verify.rs:31-38` — both demand fail-closed
   on oversize; align to the STRICTER reading) and UPDATE the differential
   test to assert the now-unified behavior.
3. Delete the dead duplicates.

**Verify**: `cargo test inline_verify socks` green; full suite green; the
differential test now asserts full agreement (no exclusions left, or the
remaining ones are documented as intentional with WHY).

### Step 4: Cleanup

`decode_chunked` lives wherever it's used (socks.rs, re-exported or
`pub(crate)`); remove now-unused imports; run clippy.

**Verify**: `rg -n "fn read_http_response|fn read_http_body" src/` → no
hits; clippy `-D warnings` green.

## Done criteria

- [ ] ONE response-reading implementation (`socks::read_response`); inline_verify consumes it
- [ ] Differential/property test asserts agreement (documented exclusions ≤ the intentional set)
- [ ] Full `cargo test` + clippy + fmt green; test count ≥ pre-refactor
- [ ] Report lists the pre-existing drift disagreements found in Step 1 and their resolutions

## STOP conditions

- The `PrefixedReader` semantics make the shared reader misparse streams
  that inline_verify's own tests prove it handled (buffering boundaries,
  short reads) — report the failing case; the reader may need a
  `read_exact`-style loop hardening first (do it in this plan ONLY if
  small; otherwise report).
- The differential test shows >3 disagreement classes (the parsers are more
  divergent than "same job, two copies") — STOP and report the table; the
  consolidation may need its own design round.
- Request-writing consolidation tempts you — out of scope; don't.

## Maintenance notes

- `read_response` is now THE HTTP/1.1 response reader for probe paths — new
  probe clients must use it, not roll their own.
- The differential property test is the drift tripwire — keep it green.
- Reviewer scrutiny: verdict-relevant behavior changes (the unified
  disagreement resolutions) must each trace to a contract comment in one of
  the two files.
