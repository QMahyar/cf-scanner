# T-36 — P6 C-4: IPv6 end-to-end pass

## Proposal (approved pull)
IPv6 is opt-in (`--ipv6`) but the path scan→verify→export has gaps (audit:
bundles silently drop IPv6, wgconf/zone-ID edges untested, large-prefix
exclusion untested).

## Work
1. Fix IPv6 handling gaps found by testing (bundles: emit or loud-drop per
   T-24's decision — T-36 implements the v6 half: zone IDs, bracketing in
   every format, sing-box/clash address fields).
2. Cover: v6 scan → phase-2 verify → all export formats (loopback/fake-based
   tests; no network).
3. Close TEST edges: large-prefix v6 exclusion, `Geo::country` v6, wg://
   IPv6 zone/long-host (may already be covered by T-18 — dedupe at
   implementation time, don't double-test).

## Rules
No behavior change for IPv4. No new deps.

## Files
`src/export.rs`, `src/configs.rs`, `src/ranges/pool.rs`, tests (as needed).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
