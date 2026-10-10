# T05 — probe path: loss, idle-hold, shutdown, header reads

Spec stories 9, 13-14.

## Goal
- Real transports always `sent=1, received=1` (`src/probe.rs:54-63`), filter at `src/engine/cdn.rs:333-341` dead.
- Idle-hold tripled (`src/probe.rs:218-230,263-275,415-427`), fresh full timeout after hold (up to 60s `src/api/limits.rs:47`).
- `tls.shutdown().await` unbounded (`src/probe.rs:212`).
- Header reads 1 byte/syscall (`src/socks.rs:34-73,170-184,359-409`).

## Scope
- `src/probe.rs`, `src/socks.rs`, `src/engine/cdn.rs`, `src/cli_wizard.rs:557-562` prompt.
- Decision: implement real multi-shot loss OR remove/deprecate flag (prefer removal if multi-shot too invasive — document choice in code comment).
- Extract single idle-hold helper budgeting remaining time.
- Wrap shutdown in step timeout; BufReader/chunk reads for headers.

## Acceptance
- Test pins real transports emit loss 0 OR flag removed with help/wizard updated.
- Unit tests for idle budget (worst case <= timeout+hold, not timeout+hold+timeout).
- `cargo test --locked -- probe socks cdn`, clippy, fmt green.

## Commands
`cargo test --locked probe`, `cargo test --locked socks`, `cargo clippy --all-targets --locked -- -D warnings`
