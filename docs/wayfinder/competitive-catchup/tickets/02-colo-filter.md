# 02: Colo filter at scan time

**What to build:** `--colo HKG,NRT,...` flag. Results whose colo code is
known and not in the list are dropped at the store level. Colo is learned in
phase 2 (trace) and, when the http probe mode (05) lands, phase 1. In CDN
TCP/TLS-only scans without colo info, the filter passes everything (can't
filter what we don't know) but warns.

**Blocked by:** None (can start immediately); 01 optional for storage plumbing

**Status:** ready-for-agent

- [ ] `--colo` flag parsed, validated (3-letter IATA codes, comma list)
- [ ] Filter applies in phase 2 where colo known; unknown-colo verdicts pass + warn once
- [ ] WARP mode rejects `--colo`
- [ ] Tests cover include/exclude/unknown cases
