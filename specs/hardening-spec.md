## Spec: cf-scanner correctness, performance, and contract hardening

### Problem Statement

As a cf-scanner user, scans are slower than they need to be, some flags silently do nothing, and automation around the output is fragile:

- Validating a subscription takes hours because configs are checked one at a time.
- Exporting to stdout mixes a result blob into the NDJSON event stream, breaking parsers.
- Re-running the last scan silently ignores most scan flags.
- Loss, bundle, and error-envelope behaviors do not mean what the flags and docs imply, so tuning is guesswork.

### Solution

Harden the CLI-first contract and remove the main performance bottlenecks, with no change to the intended UX:

- Concurrent `check-sub` with ordered rows and a parser-safe aggregate row.
- Stdout stays pure NDJSON; exports fail fast on bad configuration instead of after a full scan.
- Flag handling is explicit: retry conflicts warn, dead filters are fixed or removed.
- Hot paths (WARP pre-flight, phase-2 accounting, header reads, store access) stop wasting time and syscalls.

### User Stories

1. As an automation user, I want `check-sub` to check configs concurrently, so that a 2000-entry subscription finishes in minutes not hours.
2. As a script author, I want `check-sub` rows in input order, so that `config_index` joins back to my subscription lines.
3. As a script author, I want aggregate/unparseable rows to use a JSON-safe sentinel, so that JavaScript parsers do not lose precision.
4. As a script author, I want `check-sub` rows to carry a `type` envelope like scans, so that one NDJSON parser handles both streams.
5. As an automation user, I want stdout to remain pure NDJSON during `scan`, so that piping to `jq` never breaks.
6. As a CLI user, I want `--export -` rejected for `scan` (or clearly separated), so that I do not corrupt my own pipeline.
7. As a CLI user, I want bundle/sharelink formats validated before scanning, so that I do not wait minutes only to learn phase-2 was missing.
8. As a CLI user, I want `--retry-last` to warn when other scan flags are ignored, so that I do not think I changed the target when I did not.
9. As a CDN user, I want `--loss-threshold` to either measure real loss or be removed, so that tuning is not placebo.
10. As a WARP user, I want adaptive pre-flight to run in parallel, so that startup does not cost 100 serial timeouts.
11. As a WARP user, I want port-gating bounded and socket eviction non-random, so that large sweeps do not OOM or thrash.
12. As a power user, I want phase-2 stop accounting without per-combo locking, so that high-concurrency scans scale.
13. As a user on a slow link, I want probe header reads buffered, so that each probe does not pay thousands of syscalls.
14. As a user, I want idle-hold timeout accounting to be honest, so that one stalled endpoint cannot hold a worker for `timeout + hold + timeout`.
15. As an automation user, I want dropped NDJSON rows counted and surfaced on stderr, so that `summary.found` reconciles with emitted rows.
16. As an automation user, I want exactly one failure envelope per failed run, so that I do not need to dedupe two error shapes.
17. As a format contributor, I want the export registry to be exhaustive, so that adding a format without a renderer fails loudly instead of shipping base64.
18. As a privacy-conscious user, I want export temp files owner-only from creation with batched writes, so that credentials never sit world-readable and large exports stay fast.
19. As a WARP user, I want the cached Xray binary revalidated on change with checksum-then-replace, so that a corrupt binary self-heals.
20. As a phase-2 user, I want ephemeral-port handover without pick-then-drop races, so that xray spawn retries stop flaking.
21. As an ASN user, I want enrichment to skip failed endpoints and cache lookups, so that scans do not pay redundant network calls.
22. As a security reviewer, I want error sanitizers to be exhaustiveness-tested, so that a new error variant cannot leak a URL or token.
23. As a wizard user, I want the recap to show SNI rotation and export paths and warp prompts to cover junk/port-gate/adaptive, so that what I confirm is what runs.
24. As a builder, I want the offline-build flag to parse truthy explicitly and curl failures to hint the offline escape hatch, so that builds fail with guidance.
25. As a release user, I want macOS support stated or shipped, so that the Xray asset matrix matches the released targets.
26. As a maintainer, I want atomic wgconf exports and collision-retried secret writes covered by tests, so that credential files follow one safe pattern.

### Implementation Decisions

Seams (highest available, preferred):

- Scan admission: single validation gate for all scan config; fail-fast decisions go here.
- Probe transports: trait-injectable probe interface; concurrency and timeout-budget changes stay behind it.
- Scan controller + verdict store: single place for result merge, dedup, and sorted views.
- Export registry: single table mapping format name to renderer; help text derives from it.
- Tunnel probe trait: single seam for subscription checking and phase-2 verification.

Decisions:

- `check-sub`: introduce bounded concurrency behind the existing tunnel-probe seam, keep input order, keep per-config timeout semantics.
- NDJSON contract: stdout remains event stream only; export-to-stdout for scan is rejected; aggregate rows use a JSON-safe sentinel and typed envelope.
- Retry: retry-load path warns on any non-default scan flag outside the documented override subset; persisted secrets stay excluded and load stays strict.
- Loss: either implement real multi-shot loss accounting for CDN probes or remove/deprecate the flag and its wizard prompt; no silent no-op.
- WARP: parallelize pre-flight with small cap honoring cancel; bound port-gate fan-out by scan concurrency; replace random socket eviction with LRU/clock.
- Phase-2/store: replace per-iteration mutex size checks with atomic counters, keep set only for dedup; keep position index across removals or move to keyed map with lazy sorted view.
- I/O: buffer header reads; buffer live-export writes with flush per batch; create secret/export temp files owner-only at creation.
- Timeouts: single idle-hold helper that budgets from remaining time; bound TLS shutdown within step timeout; move WARP jitter to scheduler.
- Errors: single failure envelope shape; count and report serialization drops; make format match exhaustive.
- Xray/ports: revalidate memoized binary on mtime/size change, checksum-then-replace; remove pick-then-drop port race via handover or port-0 read-back.
- Enrichment: filter to working endpoints, add in-memory IP-to-ASN cache, skip already-annotated rows.
- Build/dist: explicit truthy parsing for offline flag, actionable curl error, resolve macOS target gap.

### Testing Decisions

What makes a good test: external behavior only (CLI exit codes, NDJSON shape, file permissions, timing bounds), offline and deterministic, no live network or real credentials.

Modules to test:

- Subscription checking: concurrency preserves order, cap enforced before any probe, every parsed config probed with a real URL.
- Export: stdout-purity, atomic no-tmp-leftover, bundle-without-phase2 fails before scanning, unknown format rejected.
- Retry: conflicting flags warn, secrets never persisted, corrupt saved config errors clearly.
- Loss: pin whether real transports can emit non-zero loss; scripted-loss path stays.
- WARP: pre-flight parallelism honors cancel, gate bounded, eviction deterministic under churn.
- Store/phase-2: no verdict deletion races, removal atomic with keep-check, sorted-view stable.
- Secrets: owner-only creation on both platforms, tmp-name collision retry.

Prior art to follow:

- Offline end-to-end CLI tests using documentation test-net ranges with fixed seed and NDJSON schema assertions.
- Fake/scripted transport and tunnel-probe doubles for loss, colo races, and verification paths.
- Golden tests for export formats; permission tests for secret files.

### Out of Scope

- New UI, server, tray, or background daemon.
- Multi-CDN expansion, exit-geo lookup, per-client preset packs, or DNS-upload workflows (see notes).
- macOS release pipeline work beyond documenting the gap.
- Live-network evidence runs requiring credentials.
- Publishing this spec to an issue tracker; triage labeling deferred per user request.

### Further Notes

Rival scan (separate research, not committed work): the dominant incumbent is a Go speed-test tool (~28k stars) with colo filtering and router builds; closest WARP specialists cover noise/fragment presets and wg/awg/masque with exit-geo visibility; closest Rust peer is a small CFST port. Borrow candidates if ever prioritized: colo filter, honest multi-stage validation, per-client WARP presets, curated-list bootstrap as optional seed. cf-scanner's durable edge to preserve: single static binary, NDJSON automation contract, unified CDN+WARP engine, trait-injectable offline tests, atomic/crash-safe exports.
