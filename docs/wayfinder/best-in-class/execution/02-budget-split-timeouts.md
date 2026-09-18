# 02: Budget-split timeouts for TCP/TLS probes

**What to build:** slow/black-holed endpoints fail fast instead of burning the whole probe budget: the TCP connect phase gets at most a quarter of the timeout and the TLS handshake at most half of the remainder, with the configured timeout still the hard ceiling and verdicts identical.

**Blocked by:** None (can start immediately).

**Status:** done

Spec: `../spec-best-in-class.md` §P0-2. Inherits spec §6 execution rules.

- [x] Per-step budgets on the TCP and TLS probe paths; outer timeout remains the ceiling; failure-reason strings unchanged
- [x] Always-on, no flag; outcomes identical except faster failures (pinned by unit tests with stalled vs healthy transports)
- [x] No contract change; cancellation still races in-flight probes
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

## Result

Shipped in `src/probe.rs` only (215+/10-, 4 hunks; no other file touched).
`rust-engineering`/`rust-async` skills are absent from this session's skill
list, so the work proceeded strictly per spec §6 + AGENTS.md v0.8.0
invariants (outer ceiling kept, `reason()` strings byte-identical, no
contract/config change, per-call `timeout(...)` so the engine-level
`select!`+cancel race is unaffected).

- New `tcp_connect_budget()` (`timeout_ms / 4`, min 1) and
  `tls_budgets()` (connect ≤¼, handshake ≤½ of remainder, min 1 each),
  mirroring the existing `step_budgets` pattern (HTTP path untouched).
- `TcpTransport::probe` wraps `TcpStream::connect` in the ¼ budget;
  `TlsTransport::probe` wraps connect in ¼ and the rustls handshake in ½
  of remainder. Budget expiry maps to `ProbeError::Timeout { timeout_ms }`
  with the *outer* value, so `reason()` stays `"timeout"`; inner connect /
  handshake errors keep the existing `Refused` / `Tls` mappings. The outer
  `timeout_ms` wrapper is unchanged, so it stays the hard ceiling.
  Always-on, no flag. Idle-hold behavior untouched.
- Tests (all in `src/probe.rs`, no network beyond loopback): budget-math
  pins (`tls_budgets(3000) == (750, 1125)`); injected ready futures pass
  through budgets with identical verdicts; injected 30 s stalls fail in
  budget time with `Timeout { timeout_ms }` + `reason() == "timeout"`;
  real `TcpTransport` vs loopback listener succeeds with identical verdict
  shape; real `TlsTransport` vs accept-and-hold listener fails as
  `Timeout { 3000 }` in ~1.1 s (< 2.5 s assert). One environment finding:
  a just-closed loopback port black-holes instead of refusing on this
  Windows host (budget correctly yields `Timeout`), so the Refused pin
  uses port 0, which the stack rejects synchronously with zero I/O.

Gate evidence (verified in an isolated `HEAD` worktree + only this file's
diff, because parallel tickets had the shared tree red mid-run — first a
`panic!("show output")` scratch test in `src/configs/mod.rs`, then compile
breaks in `src/configs/uri.rs`/`src/socks.rs`, all outside this scope):
`cargo test` ok — 653 lib + 57 + 16 + 16 + 2 integration, 0 failed;
`cargo clippy --all-targets -- -D warnings` exit 0;
`cargo fmt --check` exit 0 (main-tree file hash-identical to the
fmt-verified copy).
