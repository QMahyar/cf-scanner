---
name: Engine HIGHs — exclude-CIDR silent drop + controller brick
labels: [wayfinder:task]
state: closed
assignee: ox-alpha
branch: review/engine
blocked-by: []
---

## Question

Two HIGH findings in `src/engine/`. Fix both with tests; this ticket opens the
`review/engine` branch off latest `main`.

1. **WARP mode silently probes excluded CIDRs** — `src/engine/warp.rs:220-224`
   uses `.filter_map(|c| ranges::parse_cidr(c).ok())`, dropping unparsable
   `--exclude` entries. CDN mode fails loudly (`ranges.rs:327-330`). A typo'd
   exclusion is scanned anyway — violates the "scan only explicit user input"
   boundary. Fix: propagate the parse error (collect-and-bail like the CDN/custom
   path). Test: a WARP config with a bad exclusion must error, not scan.
2. **ResetGuard built too late bricks the controller** — `src/engine/mod.rs:303`
   sets `running=true`; line 305 awaits `run_seeded_unguarded`; the RAII guard is
   only constructed at line 328. A panic unwinding through that await leaves
   `running=true` forever ("a scan is already running" for process lifetime).
   Fix: construct `ResetGuard` immediately after setting `running=true`, before
   the first fallible call. Test: inject a panicking transport/fetch and assert a
   subsequent run starts cleanly.

Acceptance: `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
cargo test` green; commit per repo conventions (reference "review H2/H3").

## Resolution

Fixed on eview/engine (worktree cfs-wt-engine), commits 98614f + c840440.
H2: ngine/warp.rs:220-227 now collect-and-bails with context naming the bad
CIDR; tests warp_rejects_unparsable_exclusion_cidrs +
warp_exclusion_removes_space_from_the_bundled_pool. H3: ResetGuard binds
immediately after unning=true; test
panic_during_a_run_leaves_the_controller_usable proves recovery. Verification
trio green (329 lib + 34 bin + 12 property + 3 doctests, 0 failed). Deviations:
test drives warp_groups directly (validate() already rejects bad CIDRs earlier
in production paths); panic seam is a panicking SubFetch (transport panics are
JoinSet-caught and never reach the guard).
