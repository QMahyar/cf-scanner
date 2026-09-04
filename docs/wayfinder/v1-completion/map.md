# wayfinder:map — CF-Scanner v1.0 Completion

## Destination

Ship CF-Scanner as a complete, production-quality v1.0: documentation accurate
to the shipped CLI, architecture free of god modules, security hardened against
all identified vectors, feature-complete against competitors, test coverage
above 80%, and a clean release. The loop is: plan → branch → implement →
verify → merge → next ticket, until every open ticket is closed and the
release is tagged.

## Notes

- Effort mode: **AFK execution**. Each ticket is implemented on its own branch
  and merged back. Tickets are resolved by subagents, verified by the driver.
- **No worktrees.** Plain branches only, one checked out at a time.
- Rust work: consult the `rust-engineering` skill. Contract changes touch
  `src/api/types.rs` — keep `deny_unknown_fields` semantics.
- Boundaries: `cargo test` + `cargo clippy --all-targets -- -D warnings` +
  `cargo fmt --check` before every merge. Never log/transmit configs or keys.
- Branch naming: `ticket/<short-name>` (e.g. `ticket/docs-adr013-sweep`).
- Version is USER-GATED. Never bump version strings without explicit approval.
- This map covers all gaps found in the 2026-09-06 deep review (80+ findings
  across 6 dimensions). Not all findings warrant a ticket — trivial nits are
  batched into larger tickets.

## Decisions so far

<!-- one line per closed ticket, links to ticket bodies -->

- [01: Docs ADR-013 sweep](tickets/01-docs-adr013-sweep.md): purged 15+ stale server/UI/tray refs from spec/intent/CONTEXT; fixed ADR number; added missing CHANGELOG links. Merged as `fb7c8b0`.
- [02: Security quick wins](tickets/02-security-quick-wins.md): probe URLs now gated by `validate_fetch_url` (loopback/link-local rejected, error is payload-free); trial dirs 0o700 on Unix. Landed src-only as `0bf5aeb` (branch had stale docs, excluded).
- [03: Split main.rs](tickets/03-main-split.md): `src/cli.rs` + `src/cli/scan_args.rs` (+ tests) + export helpers → `src/export.rs`; `main.rs` 1866→341 lines; `scan --help` byte-identical; 49 binary CLI tests green. Landed as `03b2e57`.
- [05: HTTP timeouts + atomic export](tickets/05-http-timeouts-atomic-export.md): `step_budgets` splits the HTTP probe timeout 30/30/40 across connect/TLS/read (stalls fail fast, same `Timeout` error); export files use tmp+rename atomic writes. 3 new tests. Landed as `a066c1b`.
- [04: Engine extract](tickets/04-engine-extract.md): new `store.rs` (Store/lock/merge_sorted/PosIndex/update/remove), `neighbor.rs` (ProbeTask/Hub/candidates+test), `test_helpers.rs` (shared FakeSub); `plan_hosts_iter`/`plan_probe_count` → `plan.rs`; 43 lock sites use `lock()`. Net -279 lines. Landed as `e863280`.
- [06: Verbose debug mode](tickets/06-verbose-debug-mode.md): shared `export::diagnostic_line` (human reasons, loss, country/colo, tunnel detail, IPv6 bracketing); CLI `run_scan` threads global `--verbose` to per-Result stderr lines; wizard prompts verbose + uses it; README documents with examples. 2 format tests. Landed as `d355bd1`.
- [07: ASN enrichment](tickets/07-asn-enrichment.md): chose keyless ipwho.is (no new deps, public HTTPS, per-hop SSRF-guarded client); `--enrich-asn` opt-in post-scan pass (8 concurrent, 8s timeout, best-effort); Verdict+CSV gain asn/isp; parse/truncate/set_asn unit tests. Landed as `af52a35`.
- [08: Quality stop + retry-last](tickets/08-quality-stop-retry-last.md): loss/min-latency ALREADY gated found (pre-count filter); added top-up loop — `--speed-test --min-speed` now keeps scanning (max 5 rounds, skip-set, cap budget) until N fast endpoints; `scan --retry-last` + wizard repeat prompt with phase2 redaction; TunnelOpener trait makes speed tests xray-free in tests (fixes flake). Landed as `1017b86`.

## Not yet specified

- **Feature: HTTPUpgrade transport verify + export** — parse-only exists today;
  full verify through xray and export to singbox/clash needed. Blocked on
  architecture split (need clean phase2 module first).
- **Feature: Upload speed measurement** — SenPaiScanner and Morteza both have
  it. Medium effort, medium impact. Blocked on speed module clarity.
- **Feature: Scan history / dated result files** — ADR-006 rejected history;
  would need decision reversal. Not ticketable until that decision is revisited.
- **Feature: Docker image** — contradicts "pure CLI" decision. Packaging only.
  Not ticketable without a packaging decision.
- **Architecture: ScanConfig builder pattern** — 20+ fields, no builder, tests
  duplicate ok_cfg() everywhere. Nice-to-have for test readability. Blocked on
  understanding how many construction sites exist after main.rs split.
- **CI: Raise coverage gate from 70% to 80%+** — blocked on test gaps being
  filled first.

## Out of scope

- **Reverting ADR-013 (restoring the HTTP server / browser UI)** — the user
  chose pure CLI; a future UI may return but is a separate effort.
- **macOS release targets** — ADR-009 dropped them; would need Apple signing
  certs. Out of scope for v1.0.
- **Default speed tests** — intent doc bans them; `--speed-test` opt-in ships.
- **IPv6 curated working-range file** — low demand, opt-in already works.
- **Wizard --seed option** — exists on CLI, wizard omission is minor.
- **XLSX export** — CSV opens in Excel with encoding issues, but XLSX is a
  niche need. Deferred to post-1.0.
