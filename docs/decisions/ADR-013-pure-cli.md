# ADR-013: Pure CLI — remove the HTTP server, browser UI, and tray

Date: 2026-09-02
Status: Accepted

## Context

CF-Scanner shipped with three clients over one engine: the CLI, an axum
localhost HTTP API with an embedded Svelte 5 SPA (`ui/`), and a Windows
system tray. The Svelte frontend accumulated its own toolchain (Node 22,
Vite, Tailwind 4, vitest, Playwright a11y gates), a committed `ui/dist`
with build-determinism problems across Node versions, and CI jobs to keep
it honest. The user decided the product is a pure CLI tool and asked for
the server, UI, and tray to be removed entirely.

## Decision

- Delete `src/server/` (axum routes, SSE, guards, state, server tests),
  `src/tray.rs`, and `ui/` wholesale.
- Remove the `serve` command, `--tray`, `--autostart`, and the autostart
  registry helpers. `wix/` stays: the MSI packages the CLI binary into an
  installer, which is packaging, not UI.
- Preserve export functionality by moving it out of the deleted server
  into `src/export.rs`; add `scan --export FILE --export-format
  csv|json|base64|raw|singbox|clash` (`-` = stdout) so users get the same
  bundle/result formats on disk or a pipe instead of over HTTP.
- Dependency changes: drop `axum`, `rust-embed`, `tokio-stream`,
  `tray-icon`, `winreg`, and the tray-only Windows reqwest `blocking`
  feature. Keep `axum` as a dev-dependency only (warpgen's mock
  registration server). Keep the `windows` crate (paths.rs file lockdown).
- Keep `src/api/types.rs` as the single contract: the engine consumes it
  directly (ADR-011 unchanged); the CLI serializes its events on stdout.
- CI drops the `ui` and `ui-a11y` jobs; all other gates unchanged.

## Consequences

- One toolchain (cargo), one build command, no committed build artifacts.
- The SSE/broadcast event path remains inside the engine (the CLI streams
  from the same channel); only the HTTP layer is gone.
- Docs (`README`, `AGENTS.md`, `CONTEXT.md`, `docs/development.md`) are
  rewritten to the CLI reality; the historical spec (`docs/spec.md`)
  carries a superseded banner instead of being rewritten.
- The `test-helpers` feature and integration tests keep working unchanged;
  server-only tests died with the server module.

## Supersedes

The server/UI/tray portions of `docs/spec.md` and ADR-010's HTTP-surface
guidance. ADR-005's "one binary, one contract" principle is unchanged;
it now describes CLI + wizard clients only.
