---
name: Server/API races + SSE shutdown hang
labels: [wayfinder:task]
state: closed
assignee: ox-alpha
branch: review/server
blocked-by: []
---

## Question

All `src/server.rs` / `src/main.rs` findings on a `review/server` branch.

1. **HIGH — graceful shutdown hangs with an SSE client attached** —
   `server.rs:601-615` + `main.rs:643`: the events stream only ends on
   `Lagged`; after `Finished` it pends forever, so hyper graceful shutdown
   never completes (Ctrl+C/tray Exit = zombie). APPROVED CONTRACT CHANGE: end
   the stream after the terminal event (`take_while` stops on terminal too —
   reconnect-replay already guarantees exactly-once terminal). Test: stream
   terminates after `Finished`/`Failed`.
2. **Missed-terminal race** — `server.rs:585-602`: subscribe BEFORE the
   `is_running()` check; decide replay-vs-live from `(epoch, terminal)` state so
   the broadcast tail always contains the terminal.
3. **start_scan spin-wait race** — `server.rs:470-498`: reserve synchronously
   (set running under the lock before spawning the run task) instead of
   `yield_now()` spinning; second POST gets a real conflict, no phantom
   `Failed` event.
4. **Overwrite-consent race** — `server.rs:707`: hold a registration mutex
   across the `has_identity()` check AND the registration.
5. **Unsanitized download error** — `server.rs:848`: route through
   `configs::sanitize_error_text` like every other error path.
6. **Host allowlist** — `server.rs:101-112`: case-insensitive compare; REMOVE
   `"::1"` from `ALLOWED_HOSTS` (DECIDED — server binds v4 loopback only);
   update the tests asserting `[::1]` (`server.rs:1810-1821`) to assert
   rejection instead.
7. **Length caps** — `RegisterRequest.license` and `ExportConfigRequest.config`
   get explicit byte caps symmetric with existing limits.

Acceptance: verification trio green; SSE-contract tests updated to assert
stream-end-on-terminal.

## Resolution

Fixed on eview/server (worktree cfs-wt-server), commit 4fb37f3. All seven
items: TerminalBounded SSE stream ends after Finished/Failed (graceful shutdown
completes); events subscribes before reading terminal state; start_scan
reserves via controller.reserve()/run_reserved_streaming before spawning;
register holds one critical section across overwrite consent + cooldown
(test concurrent_registers_serialize_overwrite_consent); download/export errors
sanitized; Host allowlist case-insensitive with ::1 removed; caps added
(MAX_EXPORT_CONFIG_BYTES 64 KiB, license 256 B) in api/types.rs. Verification
trio green, 0 failed.
