---
label: wayfinder:map
name: Ship the 2026-08-21 review findings (v0.5.1)
state: open
---

# Map — Ship the 2026-08-21 review findings (v0.5.1)

## Destination

Every confirmed finding from the 2026-08-21 full-codebase review (3 HIGH, 8 MEDIUM,
~15 LOW) is fixed on `main` across four domain branches with tests green, then
released as **v0.5.1** through the documented tag → CI → GitHub Release → npm flow.

## Notes

- **Plan-don't-do is overridden**: the human mandated execution ("implement all
  these using subagents and branches and tests"). Tickets here carry code, tests,
  and merges — not just decisions. All decisions were settled in grilling rounds
  1–2 before charting; nothing left to decide, only work to do.
- **Skills**: load `rust-engineering` before any Rust edit (AGENTS.md rule);
  `test-driven-development` for behavior changes; `git-workflow-and-versioning`
  for branch/commit hygiene.
- **Settled decisions** (do not re-open):
  1. Scope = ALL findings including LOWs.
  2. Ship = merge to main + tag `v0.5.1` (patch) via `docs/release-process.md`.
  3. Contract changes APPROVED: SSE `/api/events` stream ends after the terminal
     event; `--cap` becomes run-wide; `phase2_only` counts verification attempts
     in `summary.scanned`; `loss_pct` field REMOVED from WARP verdicts.
  4. Micro-decisions: `::1` dropped from Host allowlist; `send_http` body-cap
     overflow returns an explicit error (no silent truncation); progress-tick
     races stay best-effort with a WHY comment.
  5. A new Windows dependency (windows-rs) is APPROVED for ACL hardening.
  6. Execution = four domain branches off latest `main`, merged sequentially:
     `review/engine` → `review/server` → `review/probe` → `review/platform`.
     One branch may hold several sequential tickets; never two writers on one
     branch concurrently.
- **Boundaries that still bind**: never log/transmit configs or keys; validate
  all user input; `cargo fmt --check && cargo clippy --all-targets -- -D warnings
  && cargo test` before every commit; never delete tests to go green; scan
  targets unchanged.
- **Tracker mechanics (local markdown)**: claim = set `assignee:` in the ticket's
  frontmatter BEFORE working; close = `state: closed` + append a `## Resolution`
  section; blocking = `blocked-by:` listing ticket filenames. Refer to tickets by
  name in narration, never bare filename.

## Decisions so far

- [Grilling round 1–2 scope and ship bar](https://github.com/qmahyar/cf-scanner/compare/v0.5.0...main) — all findings in scope; ship = v0.5.1; contract edits and windows-rs crate pre-approved (decisions recorded here and in ticket bodies; no separate ticket needed).
- [Engine HIGHs — exclude-CIDR silent drop + controller brick](t1-engine-highs.md) — WARP exclusions fail loudly naming the bad CIDR; ResetGuard binds before the run await so a panic cannot brick the controller. `review/engine` e98614f+c840440.
- [Server/API races + SSE shutdown hang](t3-server-api-races.md) — SSE ends after the terminal event; subscribe-before-state-check; synchronous slot reservation; overwrite critical section; sanitized download errors; case-insensitive Host without ::1; byte caps on license/export config. `review/server` 4fb37f3.
- [Build cache integrity + autostart off-switch + typed interrupt](t5-build-platform-cli.md) — geoip cache verify-before-use via sidecar (tamper-tested live), shared src/dgst.rs grammar, `--autostart enable|remove` with post-bind registration, typed WizardInterrupted. `review/platform` 819970b.
- [Windows ACL lockdown for secret files](t6-windows-acl-lockdown.md) — paths::lock_down_to_owner sets a protected owner-only DACL (windows crate, 4 features); wired into identity.json, profiles.json (TODO removed), trial configs; icacls-proven live (5 inherited ACEs → single owner grant). `review/platform` dc5570c.
- [Probe/WARP panic path + verify-layer hardening](t4-probe-verify-hardening.md) — persisted WARP key validated with silent fallback (panic path closed); loss_pct field removed end-to-end (type/engine/UI/CSV); 1 MiB probe body cap replaces 64 MiB preallocs; send_http overflow fails explicitly; tls_connector built once; bracketed IPv6 literals parsed. `review/probe` b0b92b7.
- [Release v0.5.1](t7-release-v0.5.1.md) — all branches merged (one engine/mod.rs conflict combined reserve + panic-safe guard), full gate + audit + dist plan green, release commit 03b7dc1, tag pushed, Release workflow fully green. GitHub Release https://github.com/QMahyar/cf-scanner/releases/tag/v0.5.1 · npm latest 0.5.1.

**Map complete** — destination reached: every review finding fixed, tested, merged, released as v0.5.1.

## Not yet specified

Nothing — every finding was located to `file:line` with a fix direction during
the review itself, so no fog remains. If a ticket's resolution surfaces a new
question, graduate it here then into a fresh ticket.

## Out of scope

Nothing ruled out yet. Deliberate-design quirks documented in the review
(`plan_hosts_iter` reseeding, `swap_remove` sampling, phase-2 indexing bounds)
are NOT findings and are not tickets.
