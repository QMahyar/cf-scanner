---
name: Engine LOWs + run-wide cap semantics
labels: [wayfinder:task]
state: open
assignee:
branch: review/engine
blocked-by:
  - t1-engine-highs.md
---

## Question

Remaining `src/engine/` findings, sequenced after `t1-engine-highs.md` on the
same `review/engine` branch (claim only when T1 is closed).

1. **Overlapping user CIDRs double-count** — `engine/mod.rs:491-515` +
   `plan.rs:106-157`: dedup/merge overlapping CIDRs once in
   `effective_pool_from` so `(ip, port)` pairs are unique and `summary.found`
   counts unique endpoints. Test: overlapping custom CIDRs yield no duplicate
   verdicts.
2. **WARP cancel channel fresh-install trap** — `engine/warp.rs:73-74`: route
   `run_warp` through `self.cancel_signal()` like the CDN path so an in-flight
   cancel can never be silently dropped by a WARP start.
3. **Producer busy-spin** — `engine/warp.rs:112-114`: replace `yield_now()` in
   the Full arm with the CDN path's 5 ms sleep (`PRODUCER_POLL`, cdn.rs:31).
4. **Detached producer on worker panic** — `engine/cdn.rs:194-197`: abort the
   producer handle before the early error return.
5. **Run-wide cap + scanned semantics — APPROVED CONTRACT CHANGE** —
   `phase2.rs:93-94` + `cdn.rs:62-63`: share one cap counter across phases;
   count phase-2 verification attempts in `summary.scanned` (previously
   reported 0 under phase2_only). Update contract tests.
6. **Progress-tick races: document, don't fix (DECIDED)** — `cdn.rs:185-187`,
   `warp.rs:183-185`: add a WHY comment stating ticks are best-effort by design
   (skip/duplicate harmless), referencing the review.

Acceptance: verification trio green; contract tests assert new scanned/cap
semantics.
