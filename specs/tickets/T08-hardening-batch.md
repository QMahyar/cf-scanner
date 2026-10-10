# T08 — Xray, ports, sanitizer, wizard, build, secrets

Spec stories 19-20, 22-26.

## Goal
Batch of small hardening items, one ticket to avoid churn.

## Scope
- `src/xray.rs:443-469,531-553`: re-check dgst on memo hit when mtime/size changed; checksum-then-replace instead of refuse-overwrite.
- `src/verify.rs:442-480`: remove pick-then-drop port race (handover or port-0 read-back).
- `src/api/types.rs:437-470`: exhaustiveness test for sanitizer (`other => other` trap).
- `src/cli_wizard.rs` + `src/cli/scan_args.rs:386-408`: share wgconf reader helper (64 KiB cap `src/api/limits.rs:44`); recap shows SNI rotation + export paths; warp prompts cover junk/port-gate/adaptive.
- `build.rs:26-30,74-83`: explicit truthy parse for `CFSCANNER_OFFLINE_BUILD`; curl error hints escape hatch. Document macOS gap (`dist-workspace.toml:9` vs `src/xray.rs:384-393`).
- `src/warpgen.rs:511-520` vs `:326-332`: atomic wgconf export. `src/paths.rs:355-369` tmp collision retry like export `:801-829`.

## Acceptance
- New tests: sanitizer exhaustiveness, wgconf atomic, tmp retry, offline flag `"0"`/`"false"` does NOT take offline path.
- `cargo test --locked`, clippy `-D warnings`, `cargo fmt --check` green.

## Commands
`cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check`
