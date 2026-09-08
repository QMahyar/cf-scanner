# T-21 — changelog-hygiene (F-21)

## Gaps
`CHANGELOG.md`: no `[Unreleased]` section; 0.12.x/0.11.x ordering broken;
non-standard subsections. (Accuracy/links verified good — keep.)

## Fix
1. Restore `## [Unreleased]` at top; add entries for every mother-session
   ticket as they land (update this ticket's commit at the END of the program
   with the final list, or append per-ticket — prefer: per-ticket appends by
   each implementer, T-21 does structure + first entries).
2. Fix version ordering; normalize subsection names to Keep-a-Changelog
   (Added/Changed/Deprecated/Removed/Fixed/Security).

## Files
`CHANGELOG.md`.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`
(docs-only; tests prove nothing broke).
