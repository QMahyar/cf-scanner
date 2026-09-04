## Question

How do we add per-step timeouts to the HTTP probe so a single stalled response
can't block a worker for the full scan timeout?

## Scope

**Finding** (`src/probe.rs:232`): the entire connect+TLS+write+read sequence
is wrapped in a single outer timeout. If TLS succeeds but the HTTP body stalls
(partial data), the worker blocks for the full timeout (1-3s). With low
concurrency (4-8 workers), one stall blocks 25-50% of throughput.

**Pattern to follow**: `src/socks.rs` uses per-operation `io_step` timeouts.

**Fix**: split the HTTP probe timeout budget:
- 30% for TCP connect
- 30% for TLS handshake
- 40% for HTTP write + read

Also fix the related export robustness issue: `write_export` in `main.rs:870`
uses non-atomic `fs::write` (crash mid-write = empty/partial file). Use the
atomic tmp+rename pattern from `warpgen.rs::write_private_replace`.

## Acceptance

- [ ] HTTP probe has per-step timeouts (connect / TLS / read)
- [ ] Total never exceeds the configured `--timeout`
- [ ] Existing HTTP probe tests pass (update timeouts if needed)
- [ ] New test: stalled-body server fails fast (not full timeout)
- [ ] Export writes are atomic (tmp + rename)
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Don't change default timeout values
- Don't touch TCP/TLS probe paths (only HTTP)
- Every network call site must keep its `.timeout(...)`
