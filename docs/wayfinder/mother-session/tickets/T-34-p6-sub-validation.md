# T-34 — P6 C-1: subscription validation command

## Proposal (approved pull)
A `validate-sub` (name TBD — `scan` already covers; candidate: `check-sub
URL`) command that fetches a subscription URL and validates every config
end-to-end (parse → phase-2 verify against a probe target), reporting
per-config pass/fail as NDJSON. Offline-testable with `FakeSub` + loopback.

## Verify/design
Check `src/main.rs` command dispatch + `src/configs.rs` fetch + phase-2
plumbing for the cheapest composition (reuse `scan --phase2-configs <url>`
internals; the new command is a thin reporting wrapper, not a second engine).

## Rules
No new deps. Caps enforced (reuse limits). Keys never logged.

## Files
`src/main.rs`, `src/cli.rs`, `src/configs.rs` (as needed), tests, README row.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
