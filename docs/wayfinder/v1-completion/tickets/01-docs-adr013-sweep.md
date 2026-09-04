## Question

How do we purge all stale ADR-013 references (removed HTTP server, browser UI,
tray) from the documentation so every doc accurately reflects the pure-CLI
product?

## Scope

15+ stale references identified in the 2026-09-06 deep review:

| File | Line(s) | Issue |
|---|---|---|
| `docs/spec.md` | 4 | Says "ADR-012" — should be "ADR-013" |
| `docs/spec.md` | 40, 68, 71-75, 90, 102, 118, 238, 251, 262, 284 | Server/tray/UI references — all dead |
| `docs/intent/cf-scanner.md` | 24-25, 27-29, 40-41, 175 | "embedded frontend", 5-target matrix, axum runtime, dist v0.31 |
| `docs/decisions/ADR-005` | 1 | Title says "embedded UI" — superseded |
| `CONTEXT.md` | 28 | Module map lists deleted server/ and ui/ |
| `docs/README.md` | 43 | Dead link to `tasks/wayfinder-map.md` |
| `CHANGELOG.md` | 755+ | Missing link refs for v0.5.1, v0.12.0, v0.12.1, v0.12.2 |

## Acceptance

- [ ] No references to `serve`, `src/server/`, `ui/`, `tray.rs`, `--tray`,
      `--autostart` remain outside historical documents (CHANGELOG entries,
      review reports, ADRs are historical — leave those alone)
- [ ] `docs/spec.md` project structure matches current `src/` tree
- [ ] CHANGELOG has link refs for all released versions
- [ ] `CONTEXT.md` module map matches current modules (add `export.rs`, `util.rs`)
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Historical documents (CHANGELOG entries, review reports, superseded spec
  sections) are not rewritten — only current-state docs are fixed
- No version bumps in this ticket
