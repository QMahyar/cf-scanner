---
name: Release v0.5.1
labels: [wayfinder:task]
state: closed
assignee: ox-alpha
branch: main
blocked-by:
  - t1-engine-highs.md
  - t2-engine-lows-and-cap.md
  - t3-server-api-races.md
  - t4-probe-verify-hardening.md
  - t5-build-platform-cli.md
  - t6-windows-acl-lockdown.md
---

## Question

Ship the patch release once every fix ticket above is closed and merged to
`main`. Follow `docs/release-process.md` EXACTLY — never publish artifacts or
npm manually:

1. All four domain branches merged sequentially into `main`; verification trio
   green on main; `dist plan --artifacts=all --tag=v0.5.1` dry-run clean.
2. Bump version to 0.5.1 (Cargo.toml + wherever release-process.md says).
3. Tag `v0.5.1` and push → CI builds, creates the GitHub Release, publishes
   npm (`@qmahyar/cf-scanner`). Watch the `npm-publish` job; if it dies with
   ENEEDAUTH/E401, stop and ask the human for a fresh NPM_TOKEN
   (`gh secret set NPM_TOKEN`) then re-run — never publish around it.
4. Confirm `RELEASE_TAG` in `npm/cf-scanner/install.js` equals `v0.5.1`
   (the workflow greps it).

Resolution records: tag URL, release URL, npm version published.

## Resolution

Shipped 2026-08-21. All four domain branches merged to main (engine ff, server
with one engine/mod.rs conflict resolved by taking the reserve+panic-safe
guard combination, probe and platform clean); merged tree green: fmt/clippy
-D warnings/340 lib + 35 bin + 12 property + 3 doctests; cargo audit exit 0;
dist plan dry-run clean for all targets. Release commit 03b7dc1 (version
bumps Cargo.toml/npm package.json/RELEASE_TAG + changelog cut [0.5.1] -
2026-08-21), tag v0.5.1 pushed; Release workflow all jobs green incl.
npm-publish. GitHub Release: https://github.com/QMahyar/cf-scanner/releases/tag/v0.5.1
(14 assets). npm @qmahyar/cf-scanner latest = 0.5.1.
