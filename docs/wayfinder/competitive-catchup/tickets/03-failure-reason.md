# 03: Per-IP phase-1 failure reason

**What to build:** `Verdict` gains an optional `fail_reason` string. The CDN
phase-1 probe records why an endpoint failed (reset/refused, timeout, TLS
handshake) instead of only dropping it. Exported in CSV/JSON. Needed before
`--verbose`-style debugging and richer CSV (04).

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `Verdict.fail_reason: Option<String>` with `#[serde(default)]`
- [ ] `ProbeError` variants mapped to stable reason strings
- [ ] Failed verdicts retained in results with reason (still not counted in `found`)
- [ ] CSV/JSON export include `fail_reason`
