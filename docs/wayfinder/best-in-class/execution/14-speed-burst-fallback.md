# 14: Speed-test burst fallback

**What to build:** the opt-in speed test degrades gracefully instead of erroring on stalled downloads: when the full capped sample stalls or times out, parallel small burst fetches produce a lower-bound MB/s record under the same flag, caps, and concurrency bound.

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P1-5. Inherits spec §6 execution rules.

- [x] Fallback lives strictly behind `--speed-test`; 8 MiB/30 s defaults and `--min-speed` semantics unchanged; existing tester/opener seams reused (tests stay offline)
- [x] Stall/timeout converts to a lower-bound record; fast paths byte-identical; cancel-safe cleanup preserved
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

## Result

Implemented in `src/engine/speed.rs` + `src/socks.rs` only (verified via
`git diff --stat`; no other file touched). `measure_endpoint` keeps the
8 MiB/30 s full sample first and byte-identical: on success or any
non-stall error it returns/propagates exactly as before. Only errors
classified by the new `socks::is_stall_or_timeout` helper ("timed out" /
"timeout" / "deadline" / "stalled" — owns the substring contract for
`timed_download_via_socks`'s own "speed test timed out" /
"tunnel probe {what} stalled" messages) fall back to 8×16 KiB parallel
bursts (`SPEED_BURST_URL`, `SPEED_BURST_COUNT/BYTES/TIMEOUT = 8/16 KiB/10 s`)
in waves clamped to `SPEED_TEST_CONCURRENCY`, reusing the `SpeedTester` seam
and the already-open tunnel. The recorded value is a conservative lower
bound (successful bytes over summed burst times — the sequential-equivalent
rate, so parallel delivery can only have been faster); zero usable bursts
keeps the original stall error, so dead endpoints still error. Waves use
fixed-arity `tokio::join!` (no `spawn`), so the existing cancel-`select!`
inside `measure_through_tunnel` drops burst futures and still runs
`tunnel.cleanup()` exactly once. `apply_speed_result` untouched, so
`--min-speed` semantics apply equally to burst bounds. New tests (all mock
injected, no network): stall→lower-bound value + call shape (1 full + 8
bursts, burst URL/size), non-stall error spends no burst traffic, dead
bursts keep the original error, fast path is 1 call, peak in-flight == 4
(bound honored + actually parallel), cancel mid-burst → cleanup ×1,
phase-level record + `--min-speed` gating of the bound; plus a
`socks::is_stall_or_timeout` classifier unit test. `rust-engineering` skill
is absent in this environment; `rust-async` was loaded instead and spec §6
+ AGENTS.md invariants followed. Gates run in the shared tree (it compiled
throughout, so no worktree was needed): `cargo test` green (697 lib + 61 /
16 / 16 / 2 integration, 0 failed), `cargo clippy --all-targets --
-D warnings` green, `cargo fmt --check` green (my files formatted with
per-file `rustfmt` only; whole-tree `cargo fmt` never run).
