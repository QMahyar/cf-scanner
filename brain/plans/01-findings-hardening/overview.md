# Plan 01 — Findings Hardening (adversarially-verified fix wave)

## Context

A multi-lens findings sweep (6 lenses: correctness/concurrency, security, invariants, dead-code, errors/IO, contract/tests) over the v0.14.0 tree produced 34 raw findings. After dedup and adversarial per-finding verification (5 verifier agents + inline grep verification), **19 findings are confirmed real**; 2 were refuted (phase-2 cancel-skip is already surfaced via `summary.cancelled`). Baseline on the clean tree: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` all GREEN (verified 2026-09-09).

Headline bugs:
1. **Speed test measures the wrong tunnel** — `Phase2Verdict.config_index` (raw entry idx) is used to index the *expanded* specs vec (subscription expansion + skipped entries corrupt the mapping).
2. **Bundle exports are silently empty** for subscription/file phase-2 configs (controller retains raw entries; `parse_uri` bails on `https://`).
3. **check-sub is vacuous** — `probe_urls: &[]` means xray-routed rows pass with zero probes and inline rows falsely fail.

## Scope

**Included:** the 19 confirmed findings, grouped into 11 implementation phases (see below), each with regression tests.
**Excluded:** any behavior change not traceable to a confirmed finding; no new features; no dependency changes; no version bump / release (USER-GATED, out of scope).

## Constraints

- Project invariants (AGENTS.md) are hard: per-worker bounded channels with backpressured `send().await`; `tokio::select!` + `ProbeContext::cancelled()` cancellation; BATCH_FLUSH store; broadcast cap 4096; per-controller SocketCache; `ranges::HTTP_CLIENT` + per-call `.timeout()`; `.dgst` grammar in `src/dgst.rs` only; `ensure_binary` caps; NDJSON stdout contract (results + one terminal Finished, stderr human-only).
- `src/api/` changes are an ask-first boundary. The user pre-authorized implementing these findings (this plan is the record). The single contract change is additive: `spec_index: Option<u32>` with `#[serde(default)]` (the documented pattern for new fields), plus the `speed_test_mbps` → `speed_test_mb_s` rename (pre-1.0 contract fix; the value is and stays MB/s).
- Every phase must end GREEN: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- `Result<T, anyhow::Error>` at boundaries, typed errors internally; no comments unless WHY; no secrets/configs in logs.

### Alternatives considered

- **F1 index fix:** (a) add `spec_index` alongside `config_index` (chosen — additive, serde-default, export keeps raw-entry semantics); (b) reindex expanded specs by entry idx in a HashMap (loses per-spec identity for multi-spec entries); (c) return pass→spec mapping from verify_phase (bigger refactor of the verify seam).
- **F10 unit fix:** (a) rename field to `speed_test_mb_s` (chosen — name now tells the truth, matches CLI help/wizard); (b) convert value to true Mbps keeping the name (silently changes semantics for existing threshold consumers); (c) do nothing (8× trap stays).

## Applicable skills

- `rust-engineering` — load before any Rust work (project rule).
- `code-review-and-quality` — used at the review stage.
- `ponytail` mindset for the cleanup phases (delete, don't refactor).

## Phases

Wave-ordered; phases in the same wave touch disjoint files and can run in parallel.

1. [[plans/01-findings-hardening/phase-01-contract-spec-index]] — `spec_index` field + speed-test resolution fix + `speed_test_mb_s` rename (F1, F10, F16a)
2. [[plans/01-findings-hardening/phase-02-export-bundles]] — retain parsed specs, render bundles from them, empty-bundle hard error, CSV header (F2, F16b)
3. [[plans/01-findings-hardening/phase-03-check-sub]] — real probe URLs, spec cap, config_index emission (F3, F5, F21)
4. [[plans/01-findings-hardening/phase-04-cancel-and-events]] — cancel latch, single Finished, Finished-before-Results ordering, retry-save warning (F4, F8, F9, F29)
5. [[plans/01-findings-hardening/phase-05-io-safety]] — capped phase-2 config read, trial-dir guard move (F11, F7)
6. [[plans/01-findings-hardening/phase-06-error-hygiene]] — central reqwest URL-strip in fetch errors (F12)
7. [[plans/01-findings-hardening/phase-07-export-hardening]] — exclusive random temp files, stdout write errors, format help note (F13, F14, F22)
8. [[plans/01-findings-hardening/phase-08-warp-skip-semantics]] — stop-boundary recording, (ip,port) skip set (F15, F27)
9. [[plans/01-findings-hardening/phase-09-cleanup-engine]] — gate test-only controller API, enforce/delete MAX_LICENSE_BYTES (F17, F20)
10. [[plans/01-findings-hardening/phase-10-cleanup-io]] — delete dead code, consolidate secret writes (F18, F23, F19)
11. [[plans/01-findings-hardening/phase-11-truth-pass]] — CLI defaults/help from constants, stale docs fixed (F24, F25, F26)

## Verification

Project-level gate after every phase and at the end:

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Runtime smoke (end of wave 2 and at the end): `cargo run -- scan --mode cdn --preset quick --json` streams NDJSON with exactly one terminal `finished` line as the last event type; `--export` bundle paths produce non-empty bodies for a direct-URI scan. Live network-dependent paths (check-sub against a real subscription, WARP probes) are covered by unit/integration fakes only — no live scanning in CI.
