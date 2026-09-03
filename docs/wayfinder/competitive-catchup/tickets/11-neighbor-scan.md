# 11: Neighbor scanning

**What to build:** `--neighbor-scan <N>` (opt-in, default 0 = off). After a
phase-1 hit, probe up to N neighboring IPs in the same /24 (radius around
the hit). Cap total neighbor probes with the existing `--cap` and a per-IP
neighbor budget; neighbors that hit are stored like normal results. CDN mode
only.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `--neighbor-scan <N>` flag, N in 1..=64, CDN-only
- [ ] Neighbor probes flow through the same worker channels / stop checks
- [ ] Result count obeys `--target` (neighbors count toward found)
- [ ] Cancellation races neighbor probes too; tests with injected transport
