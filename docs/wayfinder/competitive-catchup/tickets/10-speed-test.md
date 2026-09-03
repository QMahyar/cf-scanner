# 10: Post-stop shortlist speed test

**What to build:** `--speed-test` (opt-in, default off). After the scan
reaches its stop condition, run a capped download sample (e.g. 8 MiB from a
CF speed endpoint) through each phase-2-passing endpoint, record throughput
MB/s in `Phase2Verdict`, and keep a `--min-speed <MB/s>` gate that drops
slower endpoints before export. Conflicts with intent doc's blanket "no
speed tests" — resolved by making it strictly opt-in with a capped sample.
`--speed-test` requires `--phase2-configs`.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `--speed-test` + `--min-speed <MB/s>` flags, requires phase-2 configs
- [ ] Capped download sample, per-endpoint timeout, throughput recorded
- [ ] Below-min-speed endpoints excluded from results when gate given
- [ ] Default scan behavior untouched (both flags off)
