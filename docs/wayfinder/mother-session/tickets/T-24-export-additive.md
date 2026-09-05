# T-24 — export-additive (F-24) — approved: ADDITIVE ONLY

## Refine decision (approved)
Existing `singbox`/`clash`/other outputs stay byte-identical. New formats =
new `--export-format` values. Strip internal `config_index` from JSON export.
IPv6 in bundles = loud-drop (count + stderr warning) for now.

## Work
1. ADD `v2ray` (JSON) export — reuse URI parsers; template + tests.
2. ADD `shadowrocket` export — template + tests.
3. ADD `quantumult` (QX) export — template + tests.
4. FIX: sing-box/clash include grpc `mode` field.
5. FIX: bundles loud-drop IPv6 (count + one stderr warning, not silent).
6. FIX: bundles count + stderr-warn on skipped malformed URIs (not silent).
7. FIX: strip `config_index` from JSON export (internal field).
8. ADD: Clash `udp: true` on proxies; WS `packet_encoding` where one line.
9. Each new value: `ExportFormatArg` + dispatch + README row + help text.

## Test
Golden-file tests per new format (vless + vmess + ss + trojan inputs);
regression tests for (4)-(8); existing export goldens byte-identical.

## Files
`src/export.rs`, `src/cli.rs` (help), `README.md`, tests.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
