# Phase 02 — Export bundles from parsed specs

Back to [[plans/01-findings-hardening/overview]]

## Goal
Bundle exports must contain the configs that actually passed, including those from subscriptions and file entries — never silently empty.

## Findings addressed
- **F2 (high)**: controller retains RAW `--phase2-configs` entries (`engine/mod.rs:415-422`); `rewrite_uris` runs `parse_uri` on them, which bails on `https://` (subscription) and schemeless file paths → every bundle format (raw/sharelinks/base64/singbox/clash/v2ray/shadowrocket/quantumult) writes an EMPTY body with exit 0 for subscription-based scans.
- **F16b**: regression test for the retained-entry rendering.

## Changes
- `src/engine/mod.rs`: retain the parsed expanded `Vec<(OutboundSpec, u32 raw_entry_idx)>` on the controller (e.g. `last_phase2_specs` alongside `last_phase2_configs`), cleared the same way.
- `src/engine/phase2.rs`: populate the retained specs after `parse_phase2_configs`.
- `src/export.rs`: `rewrite_uris` resolves a verdict's config via the retained specs (by raw entry index / `spec_index` when present); render with `configs::render_uri(&spec, ip, port, ...)` (uri.rs:145). Keep `export_config_uri(raw, ...)` passthrough when the raw entry parses (preserves SIP002 extras). Escalate to a hard error when ALL passing endpoints resolve to unparseable retained entries (instead of writing an empty bundle + stderr warning).

## Data structures
Controller progress gains `last_phase2_specs: Vec<(OutboundSpec, u32)>` mirroring the existing `last_phase2_configs` lifecycle.

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New tests (must FAIL before, PASS after):
  1. `export.rs`: retained raw entry `https://sub.example.com/x` + passing verdict (resolved via expanded specs) → non-empty bundle body for each format kind.
  2. `export.rs`: file-path retained entry behaves the same.
  3. All-unparseable case → hard error, not empty output.
- Manual: direct-URI scan `--export results.txt --export-format clash` still byte-identical to pre-change output (no regression for the working path).
