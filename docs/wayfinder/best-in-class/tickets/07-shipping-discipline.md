# 07: Shipping discipline (release shape, stdout contract, memory, self-update)

**Type:** research (AFK)

**Blocked by:** none

**Status:** resolved

## Question

What ships: keep dist + `.dgst` + pinned `data/xray-version.txt` +
version-parity CI, or borrow SenPai's composite-release + per-OS-native CI
split, warpscout's UPX-on-Linux/Docker/install.sh/AUR patterns, BPB's
`install.sh` self-update-by-VERSION-file — plus warpscout's memory notes
(`GOMEMLIMIT=32MiB`, `BatchSize()=1`, `SetGCPercent(20)`) and the
stdout/stderr guard (`rejectBestConfStdout` analogue)?

## Context

- Non-goals already fixed: no Docker, no GUI/mobile, no phone-home update
  banner, no committed binaries, no unpinned `latest` (see map Out of scope).
- Compare our `dist-workspace.toml` + `.github/workflows` + `npm/cf-scanner`
  against their `release.yml`/`build-*.yml`, `Dockerfile`, `install.sh`,
  `SHA256SUMS.txt` vs `.dgst` — keep/drop per item with rationale.
- Deliverable: keep/drop table + any `cf-scanner self-update` sketch input.
  Feeds 08.

## Answer

Evidence: ours — `dist-workspace.toml`, `.github/workflows/release.yml`,
`.github/workflows/checks.yml`, `npm/cf-scanner/install.js`,
`npm/cf-scanner/package.json`, `Cargo.toml`, `build.rs`, `src/dgst.rs`,
`data/xray-version.txt`, `docs/release-process.md`, `src/main.rs`,
`src/warpgen.rs`, `src/export.rs`. Theirs (fetched live 2026-09-18):
SenPai `MatinSenPai/SenPaiScanner` `release.yml` + `build-cli.yml` +
`build-gui.yml`; warpscout `vernette/warpscout` `release.yaml`,
`Dockerfile`, `docker-build.yaml`, `install.sh`, `main.go`, `tunnel.go`,
`bind_linux.go`, `version.go`, `wgconf.go`, `report.go`,
`docs/en/docker.md`; BPB `install.sh` + `VERSION`
(`bia-pain-bache/BPB-Warp-Scanner`).

Correction to the ticket premise: SenPai has no "composite-release"
action — `release.yml` is a reusable-workflow (`workflow_call`)
orchestrator over `build-cli`/`build-gui`/`build-android` plus a
`SHA256SUMS.txt` step. Also note: their `release.yml` is hardcoded to
`v1.0.0` (tag filter, version inputs, `RELEASE_NOTES.md`, release name),
so each release requires editing the workflow — strictly weaker than our
tag-derived dist flow.

| # | Item | Keep / Drop | Rationale |
|---|------|-------------|-----------|
| 1 | dist + pinned `data/xray-version.txt` + `.dgst` + version-parity CI | KEEP | `dist-workspace.toml` (3 targets, msi+powershell+shell installers, `allow-dirty` for hand edits) + `release.yml` gate/cross-check/attest/SBOM + `checks.yml` xray-parity + version-parity jobs is a stronger shape than anything observed. `.dgst` is not our checksum file — it is XTLS's upstream digest format for the *third-party xray zip*, parsed strictly by the single shared `src/dgst.rs` (used by both `build.rs` and runtime) and cross-checked against the npm `parseChecksum` twin. SenPai's `SHA256SUMS.txt` (`sha256sum *`) is the equivalent of dist's per-archive `.sha256` + aggregate, which we already publish — no gap. Their hardcoded-`v1.0.0` release file is an anti-pattern to avoid, not copy. |
| 2 | SenPai reusable-workflow split + per-OS-native CI | DROP the split | The split exists to serve Wails GUI (needs native GTK/WebKit on `ubuntu-24.04`, `macos-15`, `windows-latest` in `build-gui.yml`) + Android. Map Out of scope bans GUI/mobile; pure-CLI Rust cross-compiles from dist's matrix, and our `gate` job already runs test+clippy+fmt+audit before any artifact build — i.e. we already have their test-before-build ordering (`build-cli.yml` runs `go test`/`go vet` first). Nothing to borrow beyond what exists. |
| 3 | warpscout UPX-on-Linux (`upx --best --lzma` in `release.yaml` + `Dockerfile`) | DROP | UPX buys download bytes at the cost of slower startup, AV/heuristic false positives (we already carry an accepted SmartScreen warning — UPX would worsen it), and incompatibility with signed/attested artifacts. Our size story is `tar.xz`/zip archives + `[profile.release] lto="thin"` + `codegen-units = 1` (`Cargo.toml`). Revisit only with measured download-size pain, never by default. |
| 4 | warpscout Docker + `docker-build.yaml` | DROP | Map Out of scope (ADR-013 pure CLI). Their `docs/en/docker.md` also documents the costs we avoid: `--user` ownership footguns, `-it` needed for the dashboard, `--network host` for `-6`/`-I`, ping sysctls. No action. |
| 5 | warpscout `install.sh` | DROP as installer; borrow checklist noted | No checksum verification anywhere in the script (downloads `$ASSET` from `releases/download/v$VERSION` and untars blindly) — falls under the banned checksum-less curl\|bash pattern. It resolves `latest` via the GitHub API (rate-limit prone on restricted networks). Our `npm/cf-scanner/install.js` already does this job better: pinned `RELEASE_TAG`, mandatory `.sha256` fetch + `verifyChecksum`, musl/Alpine early note, classified errors. Borrowable micro-ideas already-covered-or-trivial: `--version` pin (ours: `RELEASE_TAG`), `--uninstall` (= `npm uninstall`), `-y` (ours is non-interactive), macOS quarantine hint (irrelevant — ADR-009 dropped macOS). No action. |
| 6 | AUR packaging | DROP | No `PKGBUILD` in warpscout's repo — AUR presence, if any, is community-maintained outside their tree. Taking on distro-packaging maintenance contradicts the single-pipeline release process (`docs/release-process.md`) and adds USER-GATED release surface for near-zero restricted-network user value (npm wrapper + GitHub Releases + dist shell installer cover our targets). |
| 7 | warpscout memory notes (`GOMEMLIMIT`, `BatchSize()=1`, `SetGCPercent(20)`) | DROP as literal items; keep the principle | All three are Go-GC-specific mitigations, verified in their tree: `tunnel.go` avoids `conn.NewDefaultBind()` because "its BatchSize is 128 on Linux … measured as 96% of the live heap", and `main.go` `measureSpeed` brackets the serial speedtest with `debug.SetGCPercent(speedGCPercent)`. Rust has no GC; our footprint is already structurally bounded (per-worker channels, `BATCH_FLUSH=256` plain-push store, 4096-event broadcast cap). Corresponding principle for ticket 08: keep per-tunnel/per-worker allocations bounded and the opt-in `--speed-test` shortlist small (already: 8 MiB capped sample, serial). Optional follow-up (not this ticket): measure peak RSS on a max-concurrency WARP scan to confirm no boringtun-side batch-buffer surprise. |
| 8 | warpscout stdout/stderr guard (`-conf -` / `--best` purity, TUI→stderr) | KEEP (already satisfied; hold the line) | Their shape, verified: `tea.NewProgram(m, tea.WithOutput(os.Stderr))`, `writeConf` writes pure config bytes to `os.Stdout` only for `-conf -` (file gets `0600` otherwise), separator blank line goes to stderr, and no default report file is created in best/conf-stdout mode. Ours matches point for point: `src/main.rs` NDJSON results on stdout via `write_stdout_line` (+ pipe-close cancels scan), progress ticker and summaries TTY-gated to stderr, `tracing_subscriber` writer is stderr, `--json-errors` contract, `src/export.rs` `-` = stdout with surfaced write errors, `src/warpgen.rs` wgconf to stdout while "printed above" notes go to stderr. Contract tests exist (`check_sub_rows_emit_config_index_for_ndjson`, `stdout_export_surfaces_write_errors_instead_of_panicking`). Rule for 08: any new machine-readable output defaults to stdout-pure + stderr-human, with a test. |
| 9 | BPB `install.sh` self-update-by-`VERSION`-file | DROP the mechanism | Verified live: fetches `VERSION` from `main`, compares with `--version`, downloads from `releases/latest/download` with **no checksum**. Triply banned here: unpinned `latest` (map Out of scope), checksum-less download, and per-run phone-home (ADR-006; same reason warpscout's `version.go` GitHub-API banner with 2s timeout + 6h tmp cache stays dropped). See sketch input below for the only acceptable shape. |
| 10 | `SHA256SUMS.txt` vs `.dgst` | KEEP both (not competing) | Different jobs: `SHA256SUMS.txt`/dist `.sha256` attests *our* artifacts; `.dgst` verifies the *upstream xray zip* at bundle/download time. No change. |

### `cf-scanner self-update` sketch input (for ticket 08, not a proposal)

Constraints first: ADR-006 bans background checks and banners, so there is
no version check on any existing path — `self-update` may exist only as an
explicit user-invoked subcommand, never automatic, never a banner. It must
not use `latest` (pin the target tag explicitly, default = the release tag
matching the binary's own `CARGO_PKG_VERSION`), must verify the downloaded
archive against its published `.sha256` with the same strictness as
`install.js verifyChecksum` / `src/dgst.rs`, must reuse the existing
`ranges::HTTP_CLIENT` redirect guard + a call-site timeout, and on Windows
must handle self-replacement of a running exe (rename-and-replace dance;
MSI installs are owned by the installer and should refuse or defer).
Suggested contract: `cf-scanner self-update [--tag vX.Y.Z] [--check]`
where `--check` prints "current vs target" and exits without touching
disk; human progress on stderr; failures are plain errors (no
`--json-errors` obligation beyond the existing global flag). Anything
beyond this sketch (platform matrix, npm-wrapper interplay) is ticket 08's
call. No version bumps/tags/publishing implied — USER-GATED per AGENTS.md.
