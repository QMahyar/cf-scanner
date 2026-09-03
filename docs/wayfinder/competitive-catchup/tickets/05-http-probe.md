# 05: HTTPing probe mode

**What to build:** `--probe tcp|tls|http` selector (default tls). HTTP mode
GETs `/cdn-cgi/trace` and classifies success by status code (accept
200/301/302 default, `--http-status-code` override), captures colo from the
trace body during phase 1 (feeds 02), and measures latency. New
`HttpTransport` in `src/probe.rs` sharing the injectable `Transport` trait.

**Blocked by:** 02 (colo filter consumes phase-1 colo)

**Status:** ready-for-agent

- [ ] `--probe` flag; `http` mode probes `/cdn-cgi/trace` over TLS
- [ ] Status-code acceptance configurable; default 200/301/302
- [ ] Phase-1 verdicts carry colo when trace body parses
- [ ] Tests use injected transport; no real network in tests
