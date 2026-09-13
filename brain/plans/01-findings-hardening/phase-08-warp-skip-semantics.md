# Phase 08 — WARP stop semantics + (ip,port) skip set

Back to [[plans/01-findings-hardening/overview]]

## Goal
Stop boundaries record completed work; top-up rounds don't shrink the multi-port search space.

## Findings addressed
- **F15 (low)**: WARP worker (warp.rs:144-160) conflates `ctx.should_stop()` (found/cap reached — NOT user cancel) with cancellation: mid-endpoint break skips the `scanned` increment and discards recorded probes; summary undercounts at the stop boundary. CDN workers drain instead.
- **F27 (low)**: quality-gate top-up skip set is ip-only (cdn.rs:106-110, consumed at cdn.rs:30-31) — an IP probed-and-failed on port 443 is skipped for ALL ports in later passes, silently shrinking `--ports 443,8443` recall.

## Changes
- `src/engine/mod.rs`: add `ProbeContext::is_cancelled()` (pure user-cancel read: `*self.cancel.borrow()`).
- `src/engine/warp.rs`: inner per-endpoint loop checks `is_cancelled()` (only genuine cancellation discards mid-endpoint); found/cap stop lets the current endpoint finish (counted + recorded) — matching CDN drain semantics. Keep `should_stop()` for the top-of-outer-loop break.
- `src/engine/cdn.rs`: `ProbedSet` becomes `HashSet<(IpAddr, u16)>` keyed (ip, port); `forward_to_worker` checks the pair. Add a WHY comment on endpoint identity.

## Data structures
`ProbedSet: Arc<HashSet<(IpAddr, u16)>>` (was ip-only).

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before, PASS after):
  1. WARP: found-stop tripping mid-endpoint → in-flight endpoint still lands in results + scanned count.
  2. CDN top-up: stored 443-failure verdict for an IP, round-2 samples (ip, 8443) → task IS probed.
- Manual: none beyond tests (stop-boundary paths).
