# Plan 005: CI + release hardening (review domain CI)

> **Executor instructions**: Follow this plan step by step. Do NOT run
> workflows or trigger CI from your branch — CI runs on `main` and on tags,
> so you verify statically (yaml parse + reasoning) and locally where
> possible. Report: branch, commit hash, what changed per item, and your
> static verification notes. Drift → stop and report.

## Status

- **Priority**: P2 — **Effort**: S/M — **Risk**: LOW-MEDIUM (CI only)
- **Depends on**: none
- **Category**: ci, release, security
- **Planned at**: commit `cd4e3a5`, 2026-08-16

## Why this matters

The CI review found: the release workflow lacks the `id-token: write` +
`attestations: write` permissions GitHub now requires for artifact
attestations (release builds will fail or lose attestations); the release
`gate` job is not wired as a hard dependency of the host job; the
`windows-latest` runner was dropped from `checks.yml` (Windows is a
first-class artifact — must be tested); bundled-xray parity between the
release artifact and the repo mapping isn't verified; the MSI has no
license sidecar; and the `gate` job's checks are weaker than the local
gates in `AGENTS.md`.

## Current state (at base commit `cd4e3a5`)

1. `.github/workflows/release.yml`:
   - `permissions:` block: read `checks.yml`'s top block (recent GitHub
     default is contents: read + packages: read; check what's written) —
     missing `id-token: write` and `attestations: write` required for the
     dist `attest` / `build` attestation steps.
   - The `gate` job (rust: 1.80+, runs cargo fmt/clippy/test) — check how
     the `host` job (the one that runs `dist build`) declares `needs:`;
     the review found the host job is NOT gated on `gate` succeeding.
   - The `gate` job should also run `cargo audit` and `cargo test --all`
     equivalent (match AGENTS.md local gates: test + clippy
     `--all-targets -- -D warnings` + fmt --check + audit).
   - `dist build --artifacts=all` output — verify the workflow uploads
     attestations (dist `attest` step) and has the permissions to do so.
2. `.github/workflows/checks.yml` — confirm whether `windows-latest` is in
   the matrix; the review says it was removed (check `git log -p` on the
   file if unsure). Windows must run: build + test + clippy + fmt (clippy
   on windows needs `--all-targets`; fmt is platform-independent — the
   matrix may exclude fmt for win to avoid false diffs; keep whatever
   pattern the other runners use).
3. `dist-workspace.toml` + release.yml — the release builds bundle xray
   via a `dist-bundle-xray` step (fetch xray for the target from the pinned
   GitHub release in `data/xray-version.txt`, verify `.dgst`). The review
   found: no CI check that the bundle contains the SAME xray version as the
   repo's `data/xray-version.txt` + no parity check between bundled binaries
   and the xray `XrayProcess` probe expectations. Add a job/step in
   `checks.yml` (or release gate): parse `data/xray-version.txt` and assert
   the pinned tag equals the one used at bundle time (a simple grep-assert
   is acceptable).
4. `wix/main.wxs` — add a `<File>` for a license sidecar
   (`README.md` is not a license; bundle the LICENSE — check what license
   files exist at repo root; if none, add the sidecar step that copies the
   SPDX license text from `Cargo.toml`'s `license = "..."` into the MSI
   payload as `LICENSE.txt`).
5. Caching: `checks.yml`/`release.yml` — the review noted rust-cache was
   removed; re-add `Swatinem/rust-cache@v2` with `cache-on-failure: true`
   to the build jobs (not the gate) to keep CI time sane.
6. `docs/release-process.md` claims the release pipeline's gates equal
   `checks.yml` — plan 003 fixes the doc; if you touch it, keep it minimal
   (only if the workflow change makes the current text wrong — leave the
   wording to plan 003 otherwise).

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| YAML sanity | `pwsh -c "Get-Content .github/workflows/release.yml -Raw | ConvertFrom-Yaml"` (if `ConvertFrom-Yaml` unavailable, use a python one-liner or `cargo`-free `ruby -e 'require \"yaml\"; YAML.load_file(...)'` — any YAML parser) | parses |
| Tests (unchanged code) | `cargo test` | all pass |
| Lint | `cargo clippy --all-targets -- -D warnings` | exit 0 |
| Format | `cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `.github/workflows/release.yml`
- `.github/workflows/checks.yml`
- `dist-workspace.toml` (only if a needed setting is missing — report if so)
- `wix/main.wxs`
- Nothing else.

**Out of scope**: `src/**`, `embed/`, docs (plan 003), plans/ dir,
Cargo.toml version bump, running/releasing anything.

## Git workflow

- Branch: `review/r7-ci` from `main` (`cd4e3a5`).
- Commit per item; message style `review: <what>`.
- Do NOT push or merge.

## Steps

1. **release.yml permissions**: add `id-token: write` and
   `attestations: write` to the top-level `permissions:` block (keep
   `contents: read` etc. as-is). Verify the `attest` step exists in the
   release workflow (dist generates one; if missing, add a step
   `attest-build-provenance`-equivalent — follow the dist docs pattern
   already in the file if present).
2. **Gate wiring**: make the `host` job `needs: gate`; make `gate`
   succeed only when all checks pass; if `gate` uses a conditional
   expression on matrix results, ensure a failed gate blocks host.
3. **Gate parity**: in the `gate` job, run the same command set as
   AGENTS.md: `cargo fmt --check`, `cargo clippy --all-targets -- -D
   warnings`, `cargo test --all`, `cargo audit` (audit with `--no-fail-on`?
   NO — keep it failing on any advisory, matching local practice; if the
   audit action needs `--deny warnings`, follow whatever the existing
   checks.yml does).
4. **Windows runner**: restore `windows-latest` to the `checks.yml`
   matrix (build + test + clippy). Keep fmt on the runners where it
   currently runs. If clippy on windows was dropped for a real reason
   (toolchain), note it and keep the previous exclusion — do not guess;
   report.
5. **Xray version parity**: add a small job or step in `checks.yml`
   (cheap, runs on all OSes): read `data/xray-version.txt`, assert it
   matches the pinned tag referenced by the release bundle step (grep the
   workflow + a shell assert). If the release workflow already asserts it,
   skip and report.
6. **MSI license**: in `wix/main.wxs`, add the license file to the
   payload (find the SPDX license text — if `LICENSE`/`LICENSE.txt` doesn't
   exist at repo root, create it from `Cargo.toml`'s `license` field with
   the canonical text) and reference it in the MSI dialog if the existing
   wxs has a license dialog element; else just ship the file.
7. **Caching**: re-add `Swatinem/rust-cache@v2` to the build jobs in both
   workflows with `cache-on-failure: true` (guard with the existing job
   patterns).

## Test plan

- YAML parses (parser command above) for both workflows.
- No workflow is triggered: verify with `git diff` that no secrets/tokens
  are introduced; verify workflow `on:` triggers unchanged.
- `cargo test`, clippy, fmt pass locally (code untouched — sanity).
- Report a per-item diff summary + any deviations.

## Done criteria

ALL must hold:
- [ ] `permissions` block in release.yml includes `id-token` + `attestations`
- [ ] `host` job `needs: gate`; gate runs fmt/clippy/test/audit
- [ ] windows-latest back in checks.yml matrix (or documented reason it's not)
- [ ] xray-version parity assert exists (or documented as already-present)
- [ ] MSI ships a license file
- [ ] rust-cache re-added (or documented reason)
- [ ] Both YAMLs parse; `cargo test` + clippy + fmt pass locally
- [ ] `git status` shows only in-scope files modified
- [ ] Commit on `review/r7-ci`; report hash + item list

## STOP conditions

- A cited location doesn't match (drift).
- You'd need to change `dist-workspace.toml` in a way that changes release
  artifacts (report the need; don't do it).
- You can't verify a claim statically (e.g. whether attestations are
  required) — report the uncertainty and pick the safe default
  (add permissions; permissions that are unused are harmless).

## Maintenance notes

- `id-token`/`attestations` are required by GitHub's current release
  attestation model; if the dist version used here predates attestation
  support, the permissions are still harmless and future-proof.
- Keep the release workflow's trigger conditions (`on: push: tags` etc.)
  exactly as they are — changing triggers is out of scope.