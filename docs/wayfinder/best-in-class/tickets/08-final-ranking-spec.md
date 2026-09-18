# 08: Final ranking + spec-best-in-class.md synthesis

**Type:** grilling (HITL — locks the destination)

**Blocked by:** 01, 02, 03, 04, 05, 06, 07

**Status:** resolved

## Sign-off (2026-09-18, human)

- P0-1…P0-8 accepted as the first execution slice; SNI rotation stays P1.
- SNI rotation policy: worker-index deterministic.
- `--export -` bundles: bundle-after-summary, documented non-NDJSON.
- self-update: keep explicit-only P1 sketch.

## Answer (2026-09-18)

Destination written to `docs/wayfinder/best-in-class/spec-best-in-class.md`
(synthesis of the seven ## Answer + ## Resolution sections — decided content
was transcribed, not re-litigated; all insertion-point file:line cites were
re-verified by direct reads in the synthesis session).

**P0 — first execution slice (ordered, each S, independently shippable):**
P0-1 WARP pool 8→15 append (data-only); P0-2 budget-split TCP/TLS always-on
(no flag, outcomes-identical — the one sanctioned always-on change); P0-3
SOCKS `ServerName` repair; P0-4 share-URL missing-`?` recovery +
truncated-JWT shape check; P0-5 junk-send discovery + H/S/I1 honor in verify
(no new crate); P0-6 torn `fail_reason="torn_down"` export-only opt-in
(`--warp-probes >= 4`, WARP-only, shared wording); P0-7 `--adaptive-retries`
+ `--network-profile` + blocked-vs-slow wizard + four §06 wizard strings;
P0-8 `warp-config export --bind-best` + `Reserved` passthrough.

**P1 — second slice:** P1-1 `tune` subcommand (fragment/junk/sni, needs P0-5
knobs); P1-2 phase-2 tier ladder `[user URLs] → [public trace + data-path]`;
P1-3 opt-in SNI rotation (policy decided: per-probe worker-index rotation);
P1-4 opt-in `--warp-port-gate` (name decided; 12-addr × 4-port, 50-port
escalation); P1-5 speed-test burst fallback (behind `--speed-test` only);
P1-6 `--export-live` (conflicts with `--export`) + `--show-link` to stderr +
bundle-after-summary rule; P1-7 explicit-only `self-update` sketch
(design-gated follow-up).

**Rejected (15 items, R1–R15 in the spec):** disguised-I1 discovery; MASQUE/H2
(crate choice CLOSED: no quinn/h3); WARP-in-WARP nesting; ternary torn /
default-on torn / raised default probes; default-on pre-flight + `--tune-*`
scan flags; phase-1 WS gate; phase-2 idle-hold extension; retry-all-5-SNI /
in-probe ladder / 128 KiB verify gate; `&` auto-join / typo auto-correct /
strict JWT; SenPai ASN extras + MASQUE pools; default-on port-gate; stdout
dual-print / stdout bind / live-replaces-atomic; UPX/Docker/checksum-less
install.sh/AUR/Go-GC knobs/VERSION self-update/banner/workflow-split (dist +
pinned xray-version + `.dgst` + parity stand).

**Fog graduated:** IPv6 parity (new WARP paths IPv4-pool-only, no new v6
scope); speedtest policy (no change; torn rows never shortlisted); MASQUE
crate CLOSED; wizard strings locked (P0-7c); `tune fragment --config <uri>
[--need 3]` shape locked (P1-1). **Open follow-ups (§5):** self-update
matrix/npm interplay; peak-RSS measurement; `worers.dev` warn-only candidate;
`tune` threshold defaults vs live data.

**QUESTIONS FOR USER (sign-off gates before execution):**
1. P0 scope: is P0-1–P0-8 the right first slice, or should anything move
   (e.g. `--bind-best` P0-8 up, SNI rotation P1-3 into P0)?
2. Rotation policy: per-probe worker-index rotation (deterministic,
   test-friendly) — accept, or prefer random/shuffled rotation?
3. `--export -` bundle rule: bundle-after-final-summary (documented
   not-NDJSON-parseable) — accept, or prefer hard-rejecting `--export -`
   for bundle formats with a `--json-errors`-shaped stdout error?
4. `self-update`: keep P1-7 as a design-gated sketch, or drop it from the
   destination entirely (no update story beyond npm/dist)?

## Question

Given tickets 01–07, what is the ranked, buildable spec — P0 steals vs P1
vs explicitly rejected, with effort sizes (S/M, ≤5 files) and the first
execution slice — written to `docs/wayfinder/best-in-class/spec-best-in-class.md`?

## Context

- Input: the seven resolution comments + this map's fog patches (IPv6
  parity, speedtest policy, MASQUE crate, wizard text, `find-fragment`
  shape graduate here if specifiable).
- Must respect: binary-`Working` unless 02 changed it, opt-in-only defaults,
  contract-first + `deny_unknown_fields`/`#[serde(default)]` rules, bounded
  workers + cancel races + lazy sort, `.dgst`/caps, pure CLI, no
  history/telemetry.
- Resolve with human review of the ranked list; closing this ticket closes
  the map.
