# 06: Export + config-bind UX (dual print, bind-best, share hardening, streaming)

**Type:** grilling (HITL — user-facing output)

**Blocked by:** none

**Status:** resolved

## Resolution (2026-09-18, human)

- Q1: add `warp-config export --bind-best [--out FILE]` (fallback `--endpoint`, error when empty).
- Q2: opt-in `--show-link` renders `wireguard://` URI to stderr; stdout keeps single conf body. Plus additive `Reserved` parse/render passthrough for V2rayNG parity.
- Q3: add opt-in `--export-live FILE` (per-result append+flush, conflicts with `--export`).
- Q4: adopt the four wizard strings (bracketed-IPv6 hint, client labels, blocked-vs-slow stop framing).

## Question

Which UX do we adopt: Ptech's dual-format print (raw conf +
`wireguard://` link) + auto-inject best endpoint into the generated profile
(`install.sh:193-248`, `sed Endpoint=`), SenPai's crash-safe JSONL live
writer (`output.go:36-42`) + share-URL hardening, warpscout's
stdout=machine / stderr=human contract + `-best`/`-conf -` mutual exclusion
(`flags.go:555-560`), and wizard text (bracketed-IPv6, Nekobox/V2rayNG
labels, blocked-vs-slow framing)?

## Context

- Our surface: NDJSON stdout + TTY-gated stderr ticker, `--json-errors`,
  `--export csv|json|base64|raw|singbox|clash|sharelinks`, `warp-config`,
  `export-config`, `Reserved` in `wgconf.rs` (verify parity with Ptech
  Reserved-for-V2rayNG note).
- Constraints: stdout stays machine-parseable; secrets never in logs;
  additive export evolution only.
- Resolve with human over concrete flag/output sketches. Feeds 08.

## Answer

Evidence (current surface, verified in tree):

- `scan` streams NDJSON verdicts on stdout + TTY-gated stderr ticker
  (`src/main.rs:198-231`); `--json-errors` prints `{"error":…}` on stdout
  (`src/main.rs:40-50`, `src/cli.rs:545-550`).
- `--export FILE --export-format …` (`src/cli.rs:457-472`): `-` = stdout via
  `emit_stdout`, else atomic file write (0600 exclusive tmp + rename) + human
  note on stderr (`src/export.rs:745-778`).
- `export-config` prints the rendered URI with `println!` = machine stdout
  (`src/main.rs:101-105`); `warp-config generate/export` prints wgconf to
  stdout (`src/warpgen.rs:478-483`) + human note on stderr
  (`src/main.rs:116-128`); `--endpoint` override already exists
  (`src/cli.rs:147-169`).
- Wizard already auto-injects best endpoint into registration
  (`src/cli_wizard.rs:330-360`) and the recap hides secrets/payloads
  (counts only, `src/cli_wizard.rs:1254-1330` test pins this).
- `src/wgconf.rs` parses wgconf + `wg://`/`wireguard://` URIs (bracketed IPv6
  endpoints, userinfo rejected) but never *renders* a URI, and `WgConfig` has
  **no `Reserved` field** — the Ptech "Reserved-for-V2rayNG" parity item is a
  real gap (AmneziaWG `Reserved` bytes some clients expect on import).
- Bundle exports are IPv4-only: v6 skipped with stderr warning, hard error
  when only-v6 remains (`src/export.rs:283-312`); CSV has formula-guard;
  JSON strips `config_index`/`spec_index`.

Sketches (all additive; stdout stays machine-parseable, secrets stay on the
secret path — file/stdout body only, never stderr/logs):

A. `--bind-best` (Ptech `sed Endpoint=` auto-inject, CLI form). Wizard already
does this interactively; the gap is non-interactive:
`cf-scanner warp-config export --bind-best [--out FILE]` stamps
`Endpoint = <lowest-latency working result>` from the in-memory last scan
(falls back to `--endpoint` when given; errors when no results). No new
stdout shape: file/`-` body unchanged, human note on stderr.
B. Dual print (Ptech raw conf + `wireguard://` link). New pure renderer
`render_awg_uri(&WgConfig) -> String` (inverse of `parse_awg_uri`); opt-in
`--show-link` on `warp-config generate|export`. Link goes to **stderr**
(human, QR/copy-paste), never stdout — stdout keeps exactly one artifact
(the conf body) so `> out.conf` keeps working. Default stays single-artifact.
C. Streaming export (SenPai `output.go:36-42` crash-safe JSONL). Status quo =
atomic end-of-scan write (all-or-nothing, no partial files). Proposal =
opt-in `--export-live FILE` (append + flush per `ScanEvent::Result`, fsync
on finish; rows identical to NDJSON stdout shape minus nothing). `--export`
keeps atomic semantics; the two flags conflict. Share-URL hardening is
mostly already in place (`MAX_EXPORT_CONFIG_BYTES`, hostile-remark encoding,
`sanitize_error_text`, per-hop `validate_fetch_url`); no new allowlist
proposed beyond confirming current caps suffice.
D. warpscout contract + mutual exclusion. We already honor
stdout=machine/stderr=human; the hole is `--export -` during `scan`, which
would interleave the bundle body with the NDJSON result stream on one fd.
Proposal: clap-level `conflicts_with` is wrong (both are legitimate alone),
so instead: `--export -` with bundle formats prints the bundle **after**
the final summary line on stdout, documented as "not NDJSON-parseable when
mixed; prefer a file"; OR reject `--export -` for bundle formats with a
`--json-errors`-shaped stdout error. Wizard text additions (exact strings):
endpoint prompt gains "(IPv6 as [addr]:port)"; export/client labels become
"v2ray format (v2rayN / v2rayNG / NekoBox clipboard JSON)" and
"sing-box / clash / Shadowrocket / Quantumult"; blocked-vs-slow framing
added to the stop prompt: "Stop after N working endpoints (unreachable =
excluded, slow = kept — slowness is filtered by --min-speed, not here)".

Recommendation: A as `--bind-best` (small, matches wizard behavior);
B opt-in `--show-link` to stderr (no stdout breakage); C opt-in
`--export-live` conflicting with `--export`; D document-and-order
(bundle-after-summary) + the four wizard strings above; add additive
`Reserved` parse/render passthrough to `WgConfig` (default-off, round-trips)
for V2rayNG parity.

QUESTIONS FOR USER:
1. (RECOMMENDED) `--bind-best`: add `warp-config export --bind-best [--out FILE]` stamping best last-scan endpoint (fallback `--endpoint`, error when empty)? (alt: keep `--endpoint`-only, no bind flag)
2. (RECOMMENDED) Dual print: opt-in `--show-link` rendering `wireguard://` URI to stderr, stdout keeps single conf body? (alt: no link output at all)
3. Streaming export: add opt-in `--export-live FILE` (per-result append+flush, conflicts with `--export`) vs keep atomic end-of-scan `--export` only?
4. Wizard text: adopt the four strings in (D) — bracketed-IPv6 hint, "v2rayN / v2rayNG / NekoBox" labels, blocked-vs-slow stop framing? (alt: specify edits)
