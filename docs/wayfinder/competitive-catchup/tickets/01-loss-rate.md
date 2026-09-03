# 01: Packet-loss rate

**What to build:** The phase-1 probe records sent/received probe counts and a
loss rate per endpoint, surfaced in `Verdict` and CSV/JSON export. A new
`--loss-threshold` flag (percent) drops results above the threshold. Default
behavior unchanged (single probe = loss 0 or 100).

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `Verdict` carries loss fields (sent, received, loss_pct) with `#[serde(default)]`
- [ ] `--loss-threshold <pct>` CLI flag; results above it are excluded from store
- [ ] CSV adds `sent,received,loss_pct` columns; JSON export includes them
- [ ] Default scan (no flag) behavior unchanged; tests pass, clippy clean
