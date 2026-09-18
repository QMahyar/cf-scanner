# 12: Opt-in SNI rotation for phase-1

**What to build:** phase-1 probes on DPI-shaped networks stop betting everything on one SNI: an opt-in SNI list rotates deterministically per probe (one dial per candidate — never multiple dials per IP), defaulting to today's single SNI so default scans are byte-identical.

**Blocked by:** None (can start immediately).

**Status:** done

## Result (driver-implemented 2026-09-18; subagents unavailable — invalid API key)

Opt-in `--probe-snis HOST,...` (Tuning heading, comma-delimited): TLS/HTTP
probes rotate the list per probe call; default = today's single
`cloudflare.com`; max 8; DNS-only (IP literals rejected); customized list
under `--probe tcp` or WARP mode rejected with flag-named errors (mirrors
`--http-status-code` gates); CLI normalizes trim+lowercase; config default
fills when flag absent; retry-last files without the field load the default;
Host header tracks the rotated SNI.

- [x] SNI list on both TLS/HTTP transports via `transport_for`; rotation by
      shared atomic counter (strict round-robin sequential, spread under
      concurrency, no RNG, no extra dials); empty/non-DNS falls back to default
- [x] Additive root `probe_snis` with serde default (forward-compat kept);
      `TooManyProbeSnis`/`ProbeSnisNeedTlsHttp` under existing conventions
- [x] 11 new tests (rotation order, fallback, Host tracking, parse, validate
      incl. cap/IP/tcp-gate/retry-last, CLI mapping+parse); none deleted
- [x] `cargo test` (725 lib + all targets, 0 failed) + `cargo clippy
      --all-targets -- -D warnings` + `cargo fmt --check` green; README row added

Design note (deviation, justified): rotation is counter-based, not literal
per-worker transport pinning. True worker-index pinning would break the
injectable-transport seam (`ScanController::new(Arc<dyn Transport>)`, dozens
of test call sites) and still be unobservable end-to-end (task→worker
assignment races). The approved properties — deterministic, no RNG,
test-friendly, no extra dials — all hold.

Spec: `../spec-best-in-class.md` §P1-3 (policy decided: worker-index rotation). Inherits spec §6 execution rules.

- [ ] SNI list plumbed to the TLS/HTTP probe transports; rotation by worker index (deterministic, test-friendly, no extra RNG)
- [ ] Additive root config field with default; single-SNI default path unchanged
- [ ] Unit tests pin rotation order and default-path equivalence
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green
