# ADR-001: Xray as subprocess with release-archive bundling

## Status
Accepted

## Date
2026-08-13

## Context
Phase-2 verification needs a real Xray instance running user proxy configs
with DPI-bypass fragmentation. The crates.io `xray-core` crate (0.2.1) is only
a gRPC *client* for an already-running Xray — there is no official Rust API to
embed Xray in-process (only XTLS/libXray via C, which we do not want to link).
The app must stay a single, self-contained binary per the confirmed intent,
and users may be on networks where a runtime download from GitHub is blocked
or slow.

## Decision
Spawn the official `xray` binary as a subprocess (`xray run -c config.json`,
local socks/http inbound). Ship the binary inside every release archive:

- `build.rs` downloads `Xray-<os>-<arch>.zip` + its `.dgst` (pinned version in
  `data/xray-version.txt`) and verifies the `SHA2-256` line, but only when the
  cargo feature `dist-bundle-xray` is enabled (dist/release builds).
- The verified binary overwrites a committed 0-byte placeholder in
  `data/bundled/`, which `dist-workspace.toml` lists in `include` so every
  archive carries it.
- Dev builds never download anything; at runtime the engine first looks for the
  bundled binary next to the executable, then falls back to a cached download
  in the data dir (checksum-verified, refuses to overwrite an existing file).

## Alternatives Considered

### Embed xray via the `xray-core` crate or libXray C API
- Pros: no subprocess management
- Cons: crate is a gRPC client, not an embedder; C FFI adds unsafe/ABI risk
- Rejected: not supported by upstream for our use case

### Runtime download only (original intent recommendation)
- Pros: smaller archives, always-fresh binary
- Cons: blocked on exactly the restricted networks this tool exists for;
  version drift between app and xray
- Rejected: bundling removes the network dependency at install time

### dist ExtraArtifact for xray
- Pros: dist-native feature
- Cons: extra artifacts are global release assets, not inside archives, and
  the build command never receives the target triple in `CARGO_DIST_TARGET`
- Rejected: we need per-target binaries inside each archive

## Consequences
- Release archives grow by ~35 MB (windows/linux) or ~70 MB (macos).
- `dist-workspace.toml` must use the flat v0 schema keys (`include`,
  `features`); nested `[dist.artifacts.archives]`/`[dist.builds.cargo]`
  tables are silently ignored.
- The committed placeholders must stay in git or release builds fail with a
  hard error (missing include target).
- Runtime fallback download remains for dev builds and users who run a bare
  binary without an archive.
