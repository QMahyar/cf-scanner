# 15: Crash-safe live export + show-link

**What to build:** long scans stop being all-or-nothing artifacts: an opt-in live export appends each result as it arrives (so an interrupted scan stays parseable) while the default export keeps its atomic all-or-nothing semantics, and `warp-config` can additionally print a copy-pasteable link to stderr without disturbing the piped config body on stdout.

**Blocked by:** 09 (the link renderer covers the Reserved field from ticket 09).

**Status:** done

## Result (driver-implemented 2026-09-18; subagents unavailable — invalid API key)

- [x] `--export-live FILE` (append + flush per result, fsync on finish; rows match the NDJSON shape); conflicts with `--export`; no partial-file behavior change for `--export`
- [x] Opt-in `--show-link` on warp-config generate/export renders the URI (inverse of the URI parser, Reserved included) to stderr; stdout keeps exactly one artifact; contract test pins the stdout/stderr split
- [x] `--export -` bundle rule implemented + documented as decided
- [x] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green

Notes: live file opens truncated (never mixes runs) with owner-only perms on Unix; `-` rejected as redundant (NDJSON already streams); live write failure cancels the scan and fails the command after the summary; `warpgen` API untouched (main re-parses its returned text); link carries URI-supported fields only (DNS/AllowedIPs stay in the conf body); bundle-after-summary already held structurally (export runs after the stream ends) and is now pinned in help + README. Full suite: 745 lib + 91 bin, 0 failed; clippy clean; fmt clean.
