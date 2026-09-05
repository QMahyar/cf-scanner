# T-25 — npm-hardening (F-25)

## Gaps (`npm/cf-scanner/`)
1. `bin/cf-scanner.js` has no missing-binary guard → silent failure.
2. Error messages lack categorization (platform vs network vs checksum).
3. No download progress indicator.
4. README documents no minimum Node version.
5. musl/Alpine (Docker/CI): glibc binary fails — APPROVED as proposal ticket
   only (doc-only, no matrix change): document the glibc requirement + write
   the musl-support proposal (dist target + CI + wrapper detection).

## Fix
(1)-(3) in `install.js`/`bin/cf-scanner.js`; (4) README one-liner;
(5) `docs/wayfinder/mother-session/tickets/T-35-musl-proposal.md` (new file,
this ticket writes it) + README glibc note.
NOT DOING: macOS targets (ADR-009, deliberate).

## Test
Node-level: assert guard message + error categories (run install.js helpers
with stubbed platform/fetch where feasible; at minimum a `node --check` +
manual matrix in the commit message). No new npm deps.

## Files
`npm/cf-scanner/install.js`, `npm/cf-scanner/bin/cf-scanner.js`, `README.md`,
new proposal ticket file.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`
+ `node --check` on edited JS.
