# Phase 04 — Cancel latch + event ordering

Back to [[plans/01-findings-hardening/overview]]

## Goal
Cancellation must never be dropped, and the NDJSON stream must end the way the contract says: results, then one terminal `finished`.

## Findings addressed
- **F4 (medium)**: `cancel()` is a no-op before `cancel_signal()` lazily creates the watch channel (mod.rs:240-253); the channel's first call sites are late (cdn.rs:131, warp.rs:66 — after `reserve()`, pool file reads, validation). A Ctrl+C in that window is silently dropped; the one-shot main.rs handler then exits, so a second Ctrl+C hard-kills the process.
- **F8 (low)**: empty-plan CDN path emits `Finished` 2× normally, up to 7× with quality-gate rounds (cdn.rs:127-129 `self.finish(...)` + cdn.rs:92-94 unconditional emit).
- **F9 (medium)**: `drive_run` (mod.rs:327-335) forwards `Finished` then flushes unseen `Result`s after it — trailing `result` lines after `finished` in the NDJSON stream under broadcast lag.
- **F29 (low)**: failed last-scan save logged only at `debug` (main.rs:250-252) — `--retry-last` silently disabled.

## Changes
- `src/engine/mod.rs`: create the cancel watch channel eagerly in `reserve()` (keep `cancel_signal()`'s lazy-create as fallback for external reservers; `ResetGuard::drop` already resets per run). Loop the Ctrl+C handler in `main.rs` so repeated presses keep calling `cancel()`.
- `src/engine/cdn.rs`: empty-plan early return uses `finish_quiet` (run_cdn's unconditional emit stays the sole terminal Finished).
- `src/engine/mod.rs` `drive_run`: on `Finished`, buffer the event, flush unseen Results FIRST, then forward Finished.
- `src/main.rs`: escalate the retry-save failure log to `warn!`.

## Data structures
No contract changes. `ScanEvent::Finished` remains the sole terminal event.

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before, PASS after):
  1. `reserve()` → `cancel()` → `run_reserved_streaming`: summary.cancelled == true, ~0 scanned (cancel not dropped).
  2. Empty-plan run (excluded everything): broadcast stream contains exactly ONE `Finished`.
  3. Stream ordering: under forced lag, no `Result` line appears after `Finished` (drive_run-level test with a lagging broadcast consumer).
- Manual: Ctrl+C during a real quick scan → graceful summary, process exits 0; Ctrl+C again within the run → still graceful.
