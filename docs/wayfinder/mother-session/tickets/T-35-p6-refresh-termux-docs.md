# T-35 — P6 C-2 + C-6: refresh docs + Termux docs (docs-only)

## Work (no code)
1. C-2: `ranges refresh` automation guidance — cron (Linux), Task Scheduler
   (Windows), systemd timer example + `termux-job-scheduler` note. New
   `docs/refresh-automation.md` (or README section if short) + link from
   `docs/development.md`.
2. C-6: Termux/musl install docs — expand the existing Termux caveat into a
   step-by-step (static musl binary, glibc xray requirement, storage perms),
   Docker glibc note (musl images need glibc compat or the gnu build).
3. Link both from README troubleshooting (T-20 lands first; rebase on it).

## Files
Docs only.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`
(docs-only; proves nothing broke).
