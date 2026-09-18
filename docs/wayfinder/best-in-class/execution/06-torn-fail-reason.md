# 06: Torn-down signal as export-only fail_reason

**What to build:** endpoints that answer the handshake then die mid-stream become visible instead of silently vanishing: when the probe budget allows it, they are stored with a `torn_down` failure reason, show up in csv/json exports and the end-of-scan diagnostics, and never count as working (no stop-count, no live working result, no best/conf/bundle eligibility).

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-6. Inherits spec §6 execution rules.

- [x] Trailing-run + confirm-burst classification (min burst 5), active only when `--warp-probes >= 4`; default probes behavior byte-identical (dormant)
- [x] Torn rows carry null latency + measured loss; sort with failures; the latency-is-working invariant holds everywhere (store, counting, wizard, exports, NDJSON)
- [x] Phase-2 and wgconf verify errors share the `torn_down` wording (wording only, no structural change there); torn rows never enter the speed-test shortlist
- [x] Zero contract change (fields + columns exist); injected-transport tests for classify/store/count-skip/export-render
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

## Result

Implemented in `src/engine/warp.rs` (+ its tests) only. No other file touched.

What was built:
- `TORN_DOWN_REASON = "torn_down"` shared wording const; gates `TORN_MIN_PROBES = 4`,
  `TORN_TRAILING_UNANSWERED = 3`, `TORN_MIN_BURST = 5`.
- Per-endpoint trailing-failure counter in the WARP worker loop (behavior-neutral
  when dormant). When `probes_per_endpoint >= 4`, handshake-OK (`latency_ms.is_some()`)
  with a trailing run of >= 3 unanswered triggers a confirm burst topping the total
  up to 5 probes, under the same `tokio::select!` + `ProbeContext::cancelled()` race
  as the main probes (rust-async skill applied; rust-engineering absent per spec §6 note).
- A still-trailing endpoint after the burst is stored via `record_and_batch` with
  `latency_ms: None`, measured `loss_pct`, `fail_reason: "torn_down"`. Because the
  row has null latency it: sorts with failures; never increments found/satisfies stop
  (`driver.rs:60-77`, `mod.rs:228-234` untouched); never emits a live Result-as-working
  (flush-only via the end-of-scan store flush in `drive_run`); is ineligible for
  bundles (`rewrite_uris` needs a phase-2 pass) and the speed shortlist
  (`build_passing_index` needs a phase-2 pass, verified read-only). A confirm-burst
  recovery (tail answers) is dropped as plain lossy, never stored.
- Zero contract change: csv/json columns + `diagnostic_line` already render
  `fail_reason`/`latency_ms: None`; no export or API edits.

Tests (injected `FakeTransport` seq scripts, offline): torn stored export-only at
probes=4 (sent=5/received=1/loss=80); default-3 dormancy (same shape dropped, store
empty); confirm recovery dropped; torn skips found/stop + no live Result event
(rx drain shows only the working endpoint); csv/json/diagnostic render + bundle-empty
+ shortlist-empty for the stored torn row. `engine::warp`: 23/23 pass.

Gate evidence (2026-09-18, current tree):
- `cargo test --lib engine::warp`: 23 passed, 0 failed.
- Full `cargo test`: 687 passed, 1 failed — the failure is
  `engine::phase2::tests::phase2_colo_rejected_zero_pass_tier_skips_removed_candidates`
  (`src/engine/phase2.rs:1189`, P1-2 tier-ladder + colo logic, CDN path untouched by
  this ticket; file under active parallel edit — observed unparsable 10:14–10:18 UTC).
- `cargo clippy --all-targets`: 1 warning tree-wide, `too_many_arguments` on
  `probe_once` (`src/warp.rs:445`, P0-5's 8th `amnezia` param); zero warnings in
  `src/engine/warp.rs`. With `-D warnings` the gate fails solely on that
  out-of-scope lint.
- `cargo fmt --check`: tree diffs confined to `src/warp.rs` (P0-5 in-flight);
  `rustfmt --edition 2024 --check src/engine/warp.rs` clean.

Follow-up (left per ticket rule — structural/forbidden-file edits, not single-line):
phase-2 per-endpoint errors are dynamic sanitized probe strings (no static token site
in `src/engine/phase2.rs`), and wgconf mid-stream deaths are `ProbeError::Refused`
literals in `src/warp.rs::finish_full_session` (do-not-touch file). Sharing the
`torn_down` token into those sites needs their owners' structural call; the
`TORN_DOWN_REASON` const in `src/engine/warp.rs` is the wording anchor.
