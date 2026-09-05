# T-14 — refresh-spawn-blocking (F-14)

## Finding
`refresh_to_disk` / `refresh_v6_to_disk` (`src/ranges/official.rs:18-40`) are
async fns that synchronously call `write_pool_to` (`src/ranges/pool.rs:310-327`:
blocking `create_dir_all`/`write`/`rename`/`remove_file` under a
`std::sync::Mutex`) — blocks the runtime.

## Verify
Read both fns + `write_pool_to` + `data_write_guard`. Confirm no
`spawn_blocking` and the std-Mutex-across-async boundary.

## Fix
Wrap the `write_pool_to` call in `tokio::task::spawn_blocking` (move owned
data in; map `JoinError` to anyhow). Keep the `data_write_guard` OUTSIDE or
INSIDE consistently — simplest: acquire semantics preserved by keeping the
guard inside the blocking closure (it is a std mutex; holding it on a blocking
thread is correct).

## Test
Existing refresh tests (temp-dir) stay green. Add: concurrent `refresh_to_disk`
×2 against the same temp dir → no panic, one wins, file valid (DATA_DIR_LOCK
concurrency coverage — also closes TEST-29's race note).

## Files
`src/ranges/official.rs` (+ tests).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
