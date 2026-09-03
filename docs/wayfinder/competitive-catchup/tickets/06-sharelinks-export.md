# 06: Share-link rewriting export

**What to build:** `--export-format sharelinks` renders one rewritten config
URI per passing endpoint (original config re-hosted onto the winning ip:port,
with verified SNI + remark) — the batch form of the existing
`export-config` subcommand. Works off phase-2 configs like the other bundle
formats; IPv6 passing endpoints skipped with a warning (bundle formats are
IPv4-only today).

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `sharelinks` added to `BUNDLE_FORMATS` and clap enum
- [ ] Output = one rewritten `vless://|vmess://|trojan://|ss://` per line
- [ ] Reuses `configs::export_config_uri`; no new config parsing logic
- [ ] Empty-passing-list behaves like raw (empty output, no error)
