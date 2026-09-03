# 08: Idle-hold stability probe

**What to build:** After a successful TLS handshake, hold the connection
idle for ~500ms and verify it isn't RST'd (DPI "allow handshake, kill the
idle stream" behavior, SenPaiScanner). Implemented as an opt-in mode in the
TLS transport (`--idle-hold-ms`, default 0 = off), so default latency numbers
are unchanged. Failed idle-hold → endpoint not found.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `--idle-hold-ms` flag, default 0 (off)
- [ ] TLS transport waits idle, treats disconnect/RST as probe failure
- [ ] Latency measured at handshake, not including idle wait
- [ ] Tests: injected transport simulates RST-after-idle
