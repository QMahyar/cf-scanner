# Phase 11 — Truth pass: defaults, help, docs

Back to [[plans/01-findings-hardening/overview]]

## Goal
Everything a user reads matches what the code does.

## Findings addressed
- **F24 (medium)**: `--concurrency` help says "default 256, max 1000" but `DEFAULT_CONCURRENCY = 64`; `--phase2-concurrency` help says "default 4, max 8" but the default is 3 (`DEFAULT_PHASE2_CONCURRENCY`).
- **F25 (low)**: `driver.rs` module doc claims CDN producer uses non-blocking `try_send` — actual dispatch is backpressured `send().await` (the AGENTS.md invariant).
- **F26 (low)**: AGENTS.md claims `ScanConfig` has `deny_unknown_fields`; types.rs:198-204 documents it is INTENTIONALLY absent (retry-last forward compatibility). Docs must match intent.

## Changes
- `src/cli.rs`: derive help strings from the constants (`format!` in a `const`-friendly way or clap `long_help` with the real values); fix "default 4, max 8" → real default 3 / real max.
- `src/engine/driver.rs`: fix the module doc to describe backpressured `send().await`.
- `AGENTS.md`: correct the serde invariant line to match types.rs's documented intent (ScanConfig without deny_unknown_fields by design; nested types strict). This is a docs-file edit, not a code-behavior change.

## Data structures
None.

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- `cargo run -- scan --help` shows defaults that match `api/limits.rs` constants exactly (eyeball + grep the rendered help in a test if clap makes it accessible).
- `grep deny_unknown_fields AGENTS.md` reads consistently with types.rs's NOTE comment.
