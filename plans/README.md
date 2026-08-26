# Advisor Plans Status

Audited at `51c4711` (v0.10.0 + F7). 10 parallel audits → ~92 findings → 26 plans.

## Shipped to `main` (committed + gated)

| Plan | Title | Status | Commit(s) |
|---|---|---|---|
| 001 | UI CI gate + vitest + grammar parity | DONE | b72dbfd — checks.yml ui job + vitest harness + 5 test files (149 tests), validators fix for `1.2.3.4:` |
| 002 | Repo hygiene + docs + .gitattributes | DONE | ce04b01 — git rm 11 PNGs, drop flate2 dep, CHANGELOG/ spec/README/README/dev-docs/.gitattributes/.editorconfig |
| 003 | Pro form layout repair (dup field, grids, widths, segmented mode) | DONE | 3787011 — delete orphan customPorts duplicate, .grid-form/.span-all/.field-num, Segmented.svelte, sticky bar inset, SimpleStart widths+aria |
| 004 | WARP regroup + i18n hint (partial) | DONE (partial) | 8d50372 + follow-ups — wgconf label i18n'd, verifyHint key+paragraph (full identity grouping wrapper deferred) |
| 005 | Error affordances + heading hierarchy | DONE (partial) | field[aria-invalid] CSS, WgNoise inline drop, ProPanel h3→h2 |
| 006 | Behavior bugs (results wipe + copyAll) | DONE (partial) | e9005b9 — startScan reset after accept, copyAll honors latency filter (WARP 5000 cap, endpoints cap, clipboard announce deferred) |
| 007 | Results store O(1) per verdict | DONE | Map-backed applyResult + setResults helper, App.svelte hydrate via setResults |
| 008 | Font bundle slimming (partial) | DONE (partial) | 61aa83d — drop dead @fontsource-variable/inter (jetbrains woff2 + vazirmatn subset deferred) |
| 010 | Config parsing (VMess/base64/ports) | DONE | a429b66 — 4 commits: VMess alterId/security, 4 base64 variants, numeric port/aid, SIP002 default 443 |
| 011 | WARP plan sampling | DONE | 3b60c05 + ccda54b — shared RNG, /31-/32 → Every |
| 012 | Progress milestones + cancel during parse | DONE | cdaf6bd + 94ea906 — milestone CAS gate, terminal dedup, parse_phase2_configs cancel-aware |
| 013 | warpgen robustness | DONE | 8c338e0 — builder timeout, POST /reg no-retry, Retry-After, Windows rename plain, redirect guard |
| 014 | Protocol hardening (5 small fixes) | DONE | 61841f7 + 85566b7 + 7240a61 + 360701d + abb2fb0 + 6697967 — redact loop, credential caps, truncation, query strings, colo charset |
| 015 | Mapped-v6 + Origin port pinning | DONE | 1424be8 + 8a9ec6a + 5eaf01d — banned_ip + validate_fetch_url mapped-v6, GuardConfig port pin |
| 016 | Subscription ingestion caps | DONE | 410f2ac — Content-Length early bail, MAX_SUBSCRIPTION_SPECS/MAX_PHASE2_TOTAL_SPECS, phase2 enforcement |
| 018 | npm installer hardening | DONE | caa8297 + c2a182e + 980c0f5 + ba4f5d3 — redirect cap/https-only, PS env vars, strict checksum, tar flags |

## Remaining (plans written, not yet shipped)

| Plan | Title | Why deferred | Next step |
|---|---|---|---|
| 004 (remaining) | Identity grouping wrapper + xray/range relocation + disabled reasons | Nesting error on first attempt; minimal shipped, full wrapper needs careful grid re-parenting | Re-attempt the bordered identity-group wrap + move xray chip to tunnel card + ranges info into CIDRs disclosure |
| 005 (remaining) | Validation messages → i18n keys + live-region throttle + hardcoded English sweep | Needs FieldIssue → {key,params} refactor (M) | plan 005 Steps 2+4 |
| 006 (remaining) | WARP 5k cap surface + endpoints cap + clipboard announce | S each, was batched but not reached | plan 006 Steps 3–5 |
| 007 (remaining) | Batch view recomputation (dirty-flag / rAF) | Map shipped; view batch still pending | plan 007 Step 3 |
| 008 (remaining) | JetBrains woff2-only faces + Vazirmatn arabic subset | Visual verification of FA needed | plan 008 Steps 2–3 |
| 009 | ProPanel decomposition (6 new components) | L, must come last (after all UI fixes stable) | leaf-first extraction per plan |
| 017 | Single admission point + xray cooldown + build.rs caps | Needs CLI policy decision (Option A vs B) | Step 1 decision, then validate() move + cooldown |
| 019 | Windows DACL at create (CreateFile2) | MED, needs Win32 SECURITY_ATTRIBUTES | plan 019 |
| 020 | Store accessors (Rust) | Partially landed in 012 (has_results/for_each_result already in engine/mod.rs); status handler swap still pending | finish plan 020 Step 2 |
| 021 | De-flake async tests + property tests | S–M, independent | wait_until helper + proptest render URI |
| 022 | Server split (tests → server/tests.rs) | After 017 | code motion only |
| 023 | api/types.rs split (limits/error/validate) | After 017 | facade preserves paths |
| 024 | ranges.rs split (pool/http/official) | After 015/016 | directory module |
| 025 | Grammar consolidation (one CIDR/endpoint parser) | After 017+023 | fixture-driven resolution |
| 026 | HTTP parser consolidation (socks + inline_verify) | After 014+021 | generic read_response |

## Direction (design spikes, not yet planned as builds)

- `ranges reset` + UI refresh button, WARP deregister, wayfinder fog items, live-evidence CI decision — see plans/README.md Direction section at audit time.

## How to continue

```
# remaining plans are ready to execute; each says "Depends on" — honor it
# example:
#   016 is already done; 017 is next, after which 022/023 unblock
# run one at a time and gate:
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
cd ui && npm test && npm run check && npm run build
```

## Verification of shipped state (last run)

- `cargo test --lib` — 384 passed
- `cargo clippy --all-targets -- -D warnings` — exit 0
- `cargo fmt --check` — pre-existing drift in api/mod.rs etc. (untouched files); in-scope files clean
- `cd ui && npm test` — 149 passed
- `cd ui && npm run check` — 0 errors
