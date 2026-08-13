# Development — local build and test flow

How to build, test, and verify CF-Scanner on a developer machine. The CI
pipelines (`.github/workflows/`) run the same gates; anything that works
locally here should be exercised before pushing.

## Prerequisites

- Rust stable, edition 2024 (`rustup default stable`).
- `curl` on PATH — build.rs uses it to fetch the GeoIP mmdb and (dist builds
  only) the pinned xray binary.
- Network access on the first build for the db-ip download. Tests themselves
  never touch the network (probe transports are injectable).
- cargo-dist 0.32 for release-artifact smoke tests: `cargo install cargo-dist`
  (binary `dist` / `cargo dist`). If your shell doesn't have
  `~/.cargo/bin` on PATH, call it by full path.

## Daily loop

```
cargo build --release        # build
cargo run -- serve           # dev: API + UI on 127.0.0.1:8765
cargo test                   # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check            # auto-fix with: cargo fmt
cargo audit                  # dependency vulnerability scan (cargo install cargo-audit)
```

Commit only when test + clippy + fmt pass (see `docs/release-process.md` for
what release commits require on top). `cargo build` alone is fine for a quick
iteration; `--release` is the profile dist ships.

## Local release-artifact smoke test

The fastest way to validate the packaging pipeline without waiting on CI:

```
dist build --artifacts=local --target=x86_64-pc-windows-msvc   # or your host target
```

This runs the same path CI uses: cargo build with the `dist-bundle-xray`
feature, build.rs downloads the pinned xray binary and verifies its `.dgst`
checksum, then archives + installers are assembled in `target/distrib/`.

**After the smoke test, restore the 0-byte placeholder:**

```
git restore data/bundled/xray data/bundled/xray.exe
```

The placeholders are git-tracked; the dist build overwrites one of them with
the real binary. Never commit the real binary (see ADR-001).

## Known local-only limitations

- **MSI build fails locally** (`candle` not found) unless WiX Toolset is
  installed. This is expected: GitHub's windows runners ship WiX, so CI
  produces the `.msi` even when your dev box can't. The zip archive is the
  artifact to inspect locally.
- **Sequential multi-target dist builds locally need placeholder restores.**
  Each dist build deletes the foreign platform's placeholder
  (`data/bundled/xray.exe` on linux builds and vice versa), so a second
  dist build for the other target fails with "placeholder missing" until you
  `git restore data/bundled/xray data/bundled/xray.exe` between runs. CI is
  unaffected (each job has its own checkout).
- **SmartScreen warning** on unsigned Windows binaries — accepted, documented.
- **Termux**: static musl build; xray linux-arm64 is glibc (needs the Termux
  glibc package). Document, don't fix.

## Cross-target builds

Only the host target is realistically testable locally. The other four
targets (aarch64/linux, aarch64/macos, x86_64/macos) are validated by the CI
release matrix; the asset-name mapping in `build.rs` (`xray_asset`) must stay
in sync with XTLS release naming (arm64 = `-v8a` suffix, macOS = `macos`).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `error: could not download .../Xray-*.zip` at build | Asset name mapping stale in `build.rs::xray_asset`; verify names via `gh api repos/XTLS/Xray-core/releases/tags/<v>/assets` |
| `error: ... placeholder missing; refusing to write xray` | Foreign-target placeholder deleted by a previous dist build; `git restore data/bundled/xray data/bundled/xray.exe` |
| `xray checksum mismatch` | Pinned tag in `data/xray-version.txt` re-released; re-verify `.dgst` and pin the new tag |
| `dist: command not found` | `~/.cargo/bin` not on PATH; call `dist.exe` by full path |
| MSI step error (`candle`) | Local-only; WiX missing — see limitations above |
