# 07: Latency lower bound

**What to build:** `--min-latency <ms>` flag. Results with phase-1 latency
below the bound are dropped (low-latency-but-throttled routes, cfst `-tll`
use case). Independent of `--max-latency` (not currently exposed; cap stays
as-is unless this ticket exposes it too).

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `--min-latency` flag, validated (>= 0, integer)
- [ ] Filter applied at store level; no default change
- [ ] Tests cover boundary (== bound passes), below-bound drop
