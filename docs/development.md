# Development: local build and test flow

How to build, test, and verify CF-Scanner on a developer machine. The CI
pipelines (`.github/workflows/`) run the same gates; anything that works
locally here should be exercised before pushing.

## Prerequisites

- Rust edition 2024. `rust-toolchain.toml` pins the toolchain to 1.88, the
  same version CI uses. Any rustup-installed toolchain resolves to it on
  first build. `Cargo.toml` keeps the MSRV floor at 1.85.
- Put `curl` on PATH. build.rs uses it to fetch the GeoIP mmdb, and in dist
  builds only, the pinned xray binary.
- The first build needs network access for the db-ip download. build.rs pins
  the mmdb by SHA-256, so a failed download or checksum mismatch fails the
  build; there is no empty-database fallback. The validated download is
  cached in `target/**/out`, so repeat builds work offline until `cargo
  clean`. For fully offline environments, set `CFSCANNER_OFFLINE_BUILD=1`
  to any non-empty value. build.rs then skips the download and checksum and
  embeds a placeholder database, so country lookups return `None`. Tests
  never touch the network because probe transports are injectable.
- cargo-dist 0.32 for release-artifact smoke tests: `cargo install cargo-dist`.
  The binaries are `dist` and `cargo dist`. If your shell doesn't have
  `~/.cargo/bin` on PATH, call it by full path.

## Daily loop

```
cargo build --release        # build
cargo run -- scan --mode cdn --preset quick   # dev: run a scan
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

This runs the same path CI uses: a cargo build with the `dist-bundle-xray`
feature. build.rs downloads the pinned xray binary and verifies its `.dgst`
checksum, then the archives and installers are assembled in `target/distrib/`.

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
- **Sequential multi-target dist builds self-heal.** Each dist build deletes
  the foreign platform's placeholder (`data/bundled/xray.exe` on linux
  builds and vice versa); the next build recreates it automatically
  (`build.rs::ensure_placeholder`), so no manual restore is needed between
  runs. `git restore` is still required before committing (placeholders are
  git-tracked; the real binary must never be committed).
- **SmartScreen warning** on unsigned Windows binaries. Accepted and documented.
- **Termux.** The build is static musl, but xray linux-arm64 is glibc, so it
  needs the Termux glibc package. Document this; don't fix it.

## Cross-target builds

Only the host target is realistically testable locally. CI validates the
other two targets (aarch64-unknown-linux-gnu and x86_64-pc-windows-msvc)
in its release matrix. The asset-name mapping in `build.rs` (`xray_asset`)
must stay in sync with XTLS release naming; arm64 uses the `-v8a` suffix.
ADR-009 dropped macOS from the matrix because there are no signing certs
and Gatekeeper blocks unsigned binaries. `build.rs` (`xray_asset`) and
`src/xray.rs` still map macOS assets. That mapping is dead code after
ADR-009; keep it in sync with XTLS naming anyway, but never promise macOS
binaries in the README or spec, and never re-add the targets without Apple
signing and notarization.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `error: could not download .../Xray-*.zip` at build | The asset-name mapping in `build.rs::xray_asset` is stale. Verify names with `gh api repos/XTLS/Xray-core/releases/tags/<v>/assets`. |
| `error: db-ip download failed` or `db-ip mmdb checksum mismatch` | No network, or the pin in `data/geoip-version.txt` is stale. Update the version and SHA-256 (`Get-FileHash` or `sha256sum` on the `.mmdb.gz`). |
| `xray checksum mismatch` | The pinned tag in `data/xray-version.txt` was re-released. Re-verify the `.dgst` and pin the new tag. |
| `dist: command not found` | `~/.cargo/bin` is not on PATH. Call `dist.exe` by full path. |
| MSI step error (`candle`) | Local only: WiX is missing. See Local-only limitations. |
