# ADR-008: Dist-parity release profile and explicit tokio features

## Status
Accepted

## Date
2026-08-15

## Context
The product review (2026-08-13, Domain 6 rec 10) found that dev
`cargo build --release` produced binaries that were not representative of
shipped artifacts: only `[profile.dist]` (used by cargo-dist builds) had
`lto = "thin"`, so local performance measurements and release behavior could
diverge. The same review (Domain 4 rec 8) noted `tokio = { features = ["full"] }`
pulls in every tokio component (fs, io-std, rt, signal, sync, time, macros,
net, process, ...) even though the binary uses a known subset, inflating
compile time and binary size.

## Decision
- Add `[profile.release]` with `lto = "thin"` and `codegen-units = 1`,
  matching `[profile.dist]`, so any release-profile build behaves like the
  shipped artifact. `[profile.dist]` still exists for cargo-dist's explicit
  profile selection.
- Replace `features = ["full"]` on the tokio dependency with the explicit
  feature list the code actually uses: `rt-multi-thread`, `macros`, `time`,
  `net`, `io-util`, `sync`, `process`, `signal`. This keeps `signal`
  (Ctrl+C handling) and `process` (xray subprocess) while dropping the rest.

## Alternatives Considered

### Keep `full` and accept the cost
- Pros: zero maintenance when a new tokio feature is needed
- Cons: ~30% larger tokio compile surface and binary; the review flagged it;
  adding a feature later is a one-line diff
- Rejected

### Enable LTO in [profile.dist] only (status quo)
- Pros: shipped artifacts already get thin LTO
- Cons: local release measurements (latency tuning, RSS) misrepresent what
  ships; the review flagged exactly this mismatch
- Rejected

## Consequences
- `cargo build --release` now matches the shipped profile; any LTO/codegen
  tuning must be decided once for both profiles.
- Adding a new tokio feature later requires a deliberate Cargo.toml edit and
  a compile check — an acceptable one-line cost.
- CI `--locked` builds (checks.yml) keep the feature list honest: a code
  change that needs a new feature fails locally with a clear compile error.