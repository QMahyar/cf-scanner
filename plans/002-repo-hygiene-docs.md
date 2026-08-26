# Plan 002: Clean repo hygiene and fix the docs that are actively wrong

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- CHANGELOG.md docs README.md Cargo.toml .gitignore build.rs`
> On any mismatch with the "Current state" excerpts below, treat as a STOP
> condition.

## Status

- **Priority**: P1
- **Effort**: S–M
- **Risk**: LOW (one MED-risk step, isolated in Step 5 with its own commit)
- **Depends on**: none
- **Category**: tech-debt / docs
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The repo root carries ~1.5 MB of orphaned QA screenshots (tracked in git,
referenced nowhere), untracked one-off scripts that mutate `ProPanel.svelte`
by hardcoded line offsets (landmines if re-run), and a dead `flate2`
dependency compiled into every build. Meanwhile several docs are actively
wrong rather than merely missing: the changelog claims post-tag UI work as
shipped in v0.10.0, the spec's CLI list is missing a subcommand that shipped
in v0.5.0, the docs index describes a retired ledger, and the development
docs never mention the frontend toolchain. Wrong docs on a repo that treats
`docs/spec.md` as the approved source of truth are worse than missing docs.

## Current state

Verified facts at commit `51c4711`:

- Tracked orphan PNGs at repo root (confirmed via `git ls-files`):
  `qa-two-cards-1440.png`, `step1-hero-1280.png`, `step2-progress.png`,
  `step2-progress-anim.png`, `step2-progress-live.png`, `step2-results.png`,
  `step3-pro-bottom.png`, `step3-pro-top.png`, `step3-validation.png`,
  `step4-warp.png`, `step4-warp-register.png`. Repo-wide grep for these
  filenames across `docs/`, `README.md`, `CHANGELOG.md`, `ui/` returns zero
  references.
- Untracked `scripts/` dir: `scripts/_fix_warp_details.py` (mutates
  `ui/src/lib/components/ProPanel.svelte` via hardcoded line-offset heuristics)
  and `scripts/_tree.py` (debug tag-depth printer pinned to line 1181 of the
  same file). Both are one-off session leftovers, already applied/obsolete.
- `vite-dev.log` at repo root — untracked, gitignored via `.gitignore:15`,
  still on disk.
- `.gitignore` has NO entry for `.ruff_cache/` (the dir exists at root; it is
  currently untracked only because ruff ships an internal `.gitignore`).
- `Cargo.toml:28` declares `flate2 = "1"` under `[dependencies]`. `grep -r flate2 src/ tests/`
  returns nothing — the only consumer is `build.rs:18`, which is covered by
  the identical entry under `[build-dependencies]` (`Cargo.toml:67`).
- `CHANGELOG.md:8` — `## [0.10.0] - 2026-08-25`. Its Added bullet (lines
  23–26) claims the "Custom reveals a single inline field … on **both
  surfaces**" behavior, but the Pro half landed in commit `a59d739`
  (2026-08-26, AFTER the `v0.10.0` tag which points at `1b6cf20`). Verify:
  `git merge-base --is-ancestor a59d739 v0.10.0; echo $LASTEXITCODE` → non-zero.
  `CHANGELOG.md:6` `[Unreleased]` is empty. `CHANGELOG.md:599-602` — the link
  definition block defines only `[0.4.0]`…`[0.1.0]`; headings `[0.5.0]`
  through `[0.10.0]` have no definitions (broken reference links on GitHub).
- `docs/spec.md:72-73` — "main.rs CLI entry (clap): serve | scan | ranges |
  wizard | warp-config". The actual clap enum at `src/main.rs:47-98` also has
  `ExportConfig`. `README.md:88` — the `ranges refresh` row omits the real
  `--ipv6` flag (`src/main.rs:104-107`).
- `docs/README.md:42-45` — lists `tasks/wayfinder-map.md` twice; the first
  description ("v0.8.0 ten-agent review remediation ledger … scores …
  deliberately not done") describes content retired in commit `33e85aa`; the
  file is now the phase-separation ledger.
- `docs/development.md` (99 lines) — no mention of Node/npm/Vite/svelte-check;
  prerequisites (lines 7–24) cover Rust/curl/cargo-dist only. `AGENTS.md:166-169`
  is the only place the UI flow (`npm ci`, `npm run check && npm run build`,
  commit dist with src) is written down, and it is agent-facing.
- `release.yml:284-305` — SBOM step is `continue-on-error: true` (GLIBC
  mismatch on 22.04 runners), but `CHANGELOG.md:40-43` says release builds
  "now emit" the SBOM and ADR-012 presents it as a release property.
- No `.gitattributes`, no `.editorconfig` at repo root. `checks.yml:36-39`
  skips `cargo fmt --check` on the Windows leg with a comment blaming CRLF
  (no `.gitattributes`).

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Verify PNG references | `Get-ChildItem -Recurse -Include *.md -Path docs,ui\src | Select-String "step1-hero|step2-progress|step3-pro|step4-warp|qa-two-cards"` | no output |
| Verify flate2 unused in src | `rg flate2 src tests` | no matches |
| Build after dep removal | `cargo build && cargo test` | exit 0 |
| Check tag ancestry | `git merge-base --is-ancestor a59d739 v0.10.0; echo $LASTEXITCODE` | non-zero |
| Full gates | `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` | all exit 0 |

## Scope

**In scope**:
- `git rm` of the 11 PNGs listed above
- Deletion of `scripts/_fix_warp_details.py`, `scripts/_tree.py`, `vite-dev.log`
- `.gitignore` (append `.ruff_cache/`)
- `Cargo.toml` (remove the `[dependencies]` flate2 line only) + `Cargo.lock` (regenerated)
- `CHANGELOG.md`, `docs/spec.md`, `README.md`, `docs/README.md`, `docs/development.md`
- `.gitattributes`, `.editorconfig` (create)
- `.github/workflows/checks.yml` (only the Windows fmt-skip comment/step, in Step 5)

**Out of scope** (do NOT touch):
- `docs/decisions/**` ADR content (ADR-012 SBOM wording is amended in CHANGELOG
  only; editing ADRs is a maintainer decision — flag it in the report instead)
- Any file under `src/` or `ui/src/`
- `npm/cf-scanner/**`
- Version numbers anywhere (releases are USER-GATED; see `AGENTS.md`)

## Git workflow

- Branch: `advisor/002-hygiene-docs`
- Separate commits per step: `chore: drop orphaned qa screenshots and scratch scripts`, `build: drop unused flate2 runtime dep`, `docs: ...` per doc fix, `chore: add gitattributes and editorconfig` LAST.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Remove orphaned artifacts

```
git rm qa-two-cards-1440.png step1-hero-1280.png step2-progress.png step2-progress-anim.png step2-progress-live.png step2-results.png step3-pro-bottom.png step3-pro-top.png step3-validation.png step4-warp.png step4-warp-register.png
Remove-Item scripts/_fix_warp_details.py, scripts/_tree.py, vite-dev.log
```

Then append one line to `.gitignore`: `.ruff_cache/`.

**Verify**: `git status` → deletions staged, `.gitignore` modified, `scripts/` gone. The reference-check command in the table above returns nothing (run it BEFORE the git rm; if it DOES return a reference, STOP per conditions).

### Step 2: Remove the dead flate2 runtime dependency

In `Cargo.toml`, delete line 28 (`flate2 = "1"`) from `[dependencies]`.
Leave `[build-dependencies]` (line 67) untouched. Then run `cargo build` to
refresh `Cargo.lock`.

**Verify**: `rg flate2 src tests` → no matches; `cargo test` → exit 0;
`git diff Cargo.toml` shows exactly one removed line.

### Step 3: Fix the changelog

1. Move the "both surfaces" Custom-field bullet (and any other bullet that
   describes only post-tag commit `a59d739` behavior) from `## [0.10.0]` into
   `## [Unreleased]`. Keep bullets that ARE in the tag (check with
   `git log v0.10.0 --oneline` / `git show <sha>` when unsure).
2. Add the missing link definitions at the bottom of `CHANGELOG.md` (match the
   existing format at lines 599–602):
   `[0.5.0]: https://github.com/qmahyar/cf-scanner/releases/tag/v0.5.0` through
   `[0.10.0]: https://github.com/qmahyar/cf-scanner/releases/tag/v0.10.0`.
3. In the SBOM bullet (lines 40–43), reword "now emit" to "emit on a
   best-effort basis (skipped if the SBOM tooling cannot run on the release
   runner)" so the changelog matches `release.yml:284-305`.

**Verify**: `git diff CHANGELOG.md` shows only those three changes; every
`[x.y.z]` heading has a matching link definition (count them).

### Step 4: Fix the wrong docs

1. `docs/spec.md:72-73`: add `export-config` to the subcommand list →
   `serve | scan | ranges | wizard | warp-config | export-config`.
2. `README.md` commands table, `ranges refresh` row: append `--ipv6` mention,
   matching `src/main.rs:104-107` (read the clap definition and mirror its
   help text).
3. `docs/README.md:42-45`: collapse the duplicated `tasks/wayfinder-map.md`
   entries into ONE entry describing the current file (phase-separation
   decision ledger).
4. `docs/development.md`: add a "Frontend" section after the prerequisites:
   Node ≥ 20 (LTS), `cd ui && npm ci`, dev loop (`npm run dev` with the Rust
   server on 8765, or rebuild dist and restart), and the commit rule
   (`npm run check && npm run build`, commit `ui/src` + `ui/dist` together).
   Mirror the wording already in `AGENTS.md:166-169` so the two docs agree.

**Verify**: `cf-scanner --help` (or `cargo run -- --help`) lists exactly the
subcommands the spec now names; docs diff reviewed line by line.

### Step 5: Add .gitattributes and .editorconfig (isolated commit)

1. Create `.gitattributes`:
   ```
   * text=auto eol=lf
   *.png binary
   *.woff binary
   *.woff2 binary
   *.mmdb binary
   ```
2. Create `.editorconfig`:
   ```
   root = true
   [*]
   charset = utf-8
   end_of_line = lf
   insert_final_newline = true
   [*.{rs,ts,svelte,js,json,toml,yml,yaml,md}]
   indent_style = space
   indent_size = 4
   [*.svelte]
   indent_size = 2
   [*.{yml,yaml,json}]
   indent_size = 2
   ```
   (Check actual indentation in a few `ui/src` files first; adjust to reality,
   don't impose a new style.)
3. In a SEPARATE commit run `git add --renormalize .` and commit ONLY the
   line-ending normalization (message: `style: normalize line endings via gitattributes`).
4. Then, in `.github/workflows/checks.yml:36-39`, re-enable `cargo fmt --check`
   on the Windows leg and delete/replace the CRLF-skip comment.

**Verify**: `cargo fmt --check` exits 0 on BOTH the assumption of LF files —
run it after renormalization. `git status` clean. If `cargo fmt --check`
fails after renormalization, run `cargo fmt`, and include any reformatting in
the same normalization commit.

## Test plan

No new tests (docs/hygiene plan). Verification is the command table plus
`cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`
all exit 0 at the end.

## Done criteria

- [ ] The 11 PNGs, both scratch scripts, and `vite-dev.log` are gone; `.gitignore` covers `.ruff_cache/`
- [ ] `Cargo.toml` `[dependencies]` has no flate2; `cargo test` green
- [ ] CHANGELOG: post-tag claims moved to `[Unreleased]`; link defs complete; SBOM wording honest
- [ ] spec §4 lists `export-config`; README shows `--ipv6`; docs/README has one wayfinder entry; development.md has a Frontend section
- [ ] `.gitattributes` + `.editorconfig` exist; `cargo fmt --check` green including Windows CI step re-enabled
- [ ] No files outside scope modified

## STOP conditions

- Any doc/markdown file DOES reference one of the PNGs (then they are not
  orphaned — report which reference you found).
- `git merge-base --is-ancestor a59d739 v0.10.0` returns 0 (the premise about
  post-tag work is wrong — report, don't rewrite history claims).
- Renormalization produces diffs in files beyond line endings (e.g. a tool
  rewrote content) — report.
- Any ADR edit seems needed to keep docs consistent — report instead of
  editing ADRs.

## Maintenance notes

- After this lands, `cargo fmt --check` runs on Windows CI too — keep CRLF out
  by relying on `.gitattributes`, not by re-adding skips.
- The changelog discipline introduced in Step 3.1 (feature work after a tag
  goes under `[Unreleased]`) should become the norm; consider adding it to
  `docs/release-process.md` in a future docs pass (deferred here).
- Reviewer scrutiny: confirm the renormalize commit contains ONLY whitespace
  (`git diff --stat` then `git diff -w` should be empty for that commit).
