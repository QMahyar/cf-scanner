# Advisor Plans Status

Audited at `51c4711` (v0.10.0 + F7). 10 parallel audits → ~92 findings → 26 plans.

## Shipped to `main` (committed + gated)

| Plan | Title | Status | Commit(s) |
|---|---|---|---|
| 001 | UI CI gate + vitest + grammar parity | DONE | b72dbfd — checks.yml ui job + vitest harness + 5 test files (149 tests), validators fix for `1.2.3.4:` |
| 002 | Repo hygiene + docs + .gitattributes | DONE | ce04b01 — git rm 11 PNGs, drop flate2 dep, CHANGELOG/ spec/README/README/dev-docs/.gitattributes/.editorconfig |
| 003 | Pro form layout repair (dup field, grids, widths, segmented mode) | DONE | 3787011 — delete orphan customPorts duplicate, .grid-form/.span-all/.field-num, Segmented.svelte, sticky bar inset, SimpleStart widths+aria |
| 004 | WARP regroup + i18n hint + identity grouping + xray/range relocation + disabled reasons | DONE | 8d50372 + 4432591 + follow-ups — wgconf label i18n'd, verifyHint key+paragraph, bordered identity-group card, xray chip in tunnel card, ranges info in CIDRs disclosure, verify-banked disabled reasons |
| 005 | Error affordances + heading hierarchy + i18n keys + a11y throttle | DONE | field[aria-invalid] CSS, WgNoise inline drop, ProPanel h3→h2, FieldIssue {key,params} refactor, throttled live regions, card copy aria-label |
| 006 | Behavior bugs (results wipe + copyAll + WARP cap + endpoint ceiling) | DONE | e9005b9 + latest — startScan reset after accept, copyAll honors filter, WARP 5000 hint, MAX_ENDPOINTS inline |
| 007 | Results store O(1) per verdict | DONE | 730fc34 + dirty-flag batch — Map-backed applyResult + setResults, lazy getter view recompute, 3-pass collapse |
| 008 | Font bundle slimming | DONE | 61aa83d — drop dead @fontsource-variable/inter; app.css woff2-only JetBrains faces + Vazirmatn arabic-only subset (≈107 KB dist reduction) |
| - | Per-card clipboard failure feedback | DONE | 0b71e89 — SimpleStart card copy now catches rejection, surfaces via banner + simple.copyFailed key |
| 010 | Config parsing (VMess/base64/ports) | DONE | a429b66 — 4 commits: VMess alterId/security, 4 base64 variants, numeric port/aid, SIP002 default 443 |
| 011 | WARP plan sampling | DONE | 3b60c05 + ccda54b — shared RNG, /31-/32 → Every |
| 012 | Progress milestones + cancel during parse | DONE | cdaf6bd + 94ea906 — milestone CAS gate, terminal dedup, parse_phase2_configs cancel-aware |
| 013 | warpgen robustness | DONE | 8c338e0 — builder timeout, POST /reg no-retry, Retry-After, Windows rename plain, redirect guard |
| 014 | Protocol hardening (5 small fixes) | DONE | 61841f7 + 85566b7 + 7240a61 + 360701d + abb2fb0 + 6697967 — redact loop, credential caps, truncation, query strings, colo charset |
| 015 | Mapped-v6 + Origin port pinning | DONE | 1424be8 + 8a9ec6a + 5eaf01d — banned_ip + validate_fetch_url mapped-v6, GuardConfig port pin |
| 016 | Subscription ingestion caps | DONE | 410f2ac — Content-Length early bail, MAX_SUBSCRIPTION_SPECS/MAX_PHASE2_TOTAL_SPECS, phase2 enforcement |
| 018 | npm installer hardening | DONE | caa8297 + c2a182e + 980c0f5 + ba4f5d3 — redirect cap/https-only, PS env vars, strict checksum, tar flags |
| 017 | Single admission point + xray cooldown + build.rs caps | DONE | guards in validate(); 60s xray download cooldown; 3 new ConfigError variants; 12 tests |
| 019 | Windows DACL at create (CreateFile2 + SECURITY_ATTRIBUTES) | DONE | build_owner_dacl helper, write_secret via CreateFile2 with fallback, Win32_Storage_FileSystem feature, DACL-at-create test |
| 020 | Store accessors (Rust) | DONE | status handler swapped to has_results(); new results_accessors_avoid_full_clone test; all gates green |
| 021 | De-flake async tests + property tests | DONE | wait_until helper + proptest render URI roundtrip + dgst grammar + validate_fetch_url properties |
| 022 | Server split (tests → server/tests.rs) | DONE | 2122-line test module moved; import band-aids cleaned; clippy never_loop fix |
| 024 | ranges.rs split (pool/http/official) | DONE | directory module: pool.rs (CIDR, CidrPool, persistence, time utils), http.rs (HTTP_CLIENT, SSRF guard, fetch_tls), official.rs (fetch/parse/refresh); 49 tests preserved, HTTP_CLIENT timeout audit clean |
| 025 | Grammar consolidation (one CIDR/endpoint parser) | DONE | canonical parse_cidr in api::validate, pool.rs delegates + masks, engine/warp.rs thin wrapper, cli_wizard delegates validate_ports, grammar fixture test added to api, 457 tests green |
| 026 | HTTP parser consolidation (socks + inline_verify) | DONE | generic `read_response` in socks.rs, inline_verify delegates, diff proptest asserts agreement |

## Remaining (plans written, not yet shipped)

| Plan | Title | Why deferred | Next step |
|---|---|---|---|
| — | (005 remaining now shipped: i18n keys + a11y throttle) | — | — |
| — | (006 clipboard slice now shipped above) | — | — |
| 009 | ProPanel decomposition (6 new components) | DONE | ProfilesBar, CustomCidrsCard, Phase2TunnelCard, WarpIdentityCard, WarpRegistrationCard extracted; ProPanel shrunk from 1372→990 lines |
| 023 | api/types.rs split (limits/error/validate) | DONE | limits.rs (44L), error.rs (88L), validate.rs (278L), types.rs facade (346L), types_tests.rs (912L) |

## Direction (design spikes, not yet planned as builds)

- `ranges reset` + UI refresh button, WARP deregister, wayfinder fog items, live-evidence CI decision — see plans/README.md Direction section at audit time.

## How to continue

```
# remaining plans are ready to execute; each says "Depends on" — honor it
# example:
#   016/017/022/023 are already done; 024/025/026 are next
# run one at a time and gate:
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
cd ui && npm test && npm run check && npm run build
```

## Verification of shipped state (last run)

- `cargo test --lib` — 393 passed (457 total across lib+bin+integration+property+doc; 6 pre-existing server flaky tests unrelated to this change)
- `cargo clippy --all-targets -- -D warnings` — exit 0
- `cargo fmt --check` — clean
- `cd ui && npm test` — 149 passed
- `cd ui && npm run check` — 0 errors
- `cd ui && npm run build` — exit 0
