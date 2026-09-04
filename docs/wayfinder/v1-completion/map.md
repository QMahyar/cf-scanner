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

_(no tickets resolved yet)_

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
