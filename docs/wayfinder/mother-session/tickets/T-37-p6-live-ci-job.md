# T-37 — P6 C-5: live-evidence CI job (opt-in, secrets-gated)

## Proposal (approved pull)
Phase-2/xray/WARP/registration proof lives only in manual notes (open since
the 2026 review). Add an opt-in CI job that runs the `#[ignore]` live suite
against a secrets-provided subscription URL.

## Work
1. New workflow (or job in checks.yml): `live-evidence.yml`, `workflow_dispatch`
   only (+ optional schedule), `if: secrets.CFSCANNER_SUB_URL != ''`, runs the
   ignored live tests with `CFSCANNER_SUB_URL` from secrets, uploads NDJSON
   evidence as an artifact. Never runs on PRs/forks without the secret.
2. Document in `docs/development.md` (live QA runbook section): how to run
   locally, what evidence to attach to a release PR.
3. No prod code change. Secrets docs must warn: subscription URL is a
   credential — repo secret, never logged (mask in workflow).

## Files
`.github/workflows/live-evidence.yml`, `docs/development.md`.

## Gates
YAML validity review (can't run secrets-gated job locally); `cargo test` +
`cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green.
