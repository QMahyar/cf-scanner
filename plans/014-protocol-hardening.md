# Plan 014: Protocol hardening sweep — redaction, caps, truncation, query strings, colo charset

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/configs.rs src/inline_verify.rs src/socks.rs src/geo.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: M (five small fixes, one plan)
- **Risk**: LOW (each fix is local and test-pinnable)
- **Depends on**: none (independent of plan 010, same files — sequence after it to avoid merge churn)
- **Category**: security / bug
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Five small, verified defects in the probe/config layer, each with a concrete
failure mode:

1. **Secret redaction masks only the FIRST URL on a line**
   (`src/configs.rs:101-120`): a diagnostic line mentioning two URLs keeps
   the second URL's userinfo and query intact — credentials can leak into
   error envelopes/logs despite the sanitizer existing.
2. **Decoded-credential size cap is bypassed** by the VMess and SS parsers:
   `MAX_USER_ID_BYTES` (1024) is enforced only in `parse_sip002`
   (~361-363); `parse_vmess` (~421-423) and `parse_ss` (~477-479) impose no
   decoded-length limit, so a megabyte-scale payload lands verbatim in every
   trial config written per attempt.
3. **Close-delimited inline responses are silently truncated at the 1 MiB
   cap** (`src/inline_verify.rs:596-605`): `stream.take(MAX).read_to_end`
   crops instead of failing — both files' own contracts (`socks.rs:46-51`,
   `inline_verify.rs:31-38`) demand an explicit failure.
4. **Probe URLs' query strings are dropped** by both tunnel clients
   (`inline_verify.rs:232-236`, `socks.rs:153-157` build the path from
   `parsed.path()` only) — verification exercises a different resource than
   requested.
5. **`parse_colo` accepts arbitrary junk** (`src/geo.rs:45-53`): any
   non-empty value after `colo=` flows into results/UI.

## Current state

- `src/configs.rs:101-120` — `redact_line`: finds first `"://"`, cuts at
  first `?`/`#`, masks userinfo to first `@`, copies the remainder verbatim.
- `src/configs.rs:361-363` — the `MAX_USER_ID_BYTES` check with the WHY
  comment ("the id lands verbatim in generated xray configs").
- `src/inline_verify.rs:596-605` — the `take(MAX_PROBE_BODY_BYTES).read_to_end`
  branch; `MAX_PROBE_BODY_BYTES` const at ~561 area; contract comments at
  `:31-38`. `src/socks.rs:46-51` — the contract comment ("explicit failure,
  not a silent truncation"). The zip extractor's over-cap pattern to mirror:
  `src/xray.rs:632-636` (read cap+1, fail when exceeded).
- `src/inline_verify.rs:232-236` — `Target.path = parsed.path().to_string()`;
  `src/socks.rs:153-157` — same in `get_via_socks_inner`.
- `src/geo.rs:45-53` — `parse_colo` returns any non-empty value.
- Existing test style: `configs.rs` tests are table-driven; `geo.rs` has a
  small test module; `inline_verify.rs`/`socks.rs` tests exist for framing
  (find `read_http_response` tests).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/configs.rs` (redact_line; credential cap hoist)
- `src/inline_verify.rs` (truncation failure; query-string path)
- `src/socks.rs` (query-string path; possibly host the shared helper)
- `src/geo.rs` (colo charset)
- Test modules in those files

**Out of scope** (do NOT touch):
- HTTP parser CONSOLIDATION between the two clients (separate plan 026 —
  here you fix each site in place; do not unify them)
- `src/xray.rs`, `src/api/**`, subscription fetch caps (plan 016)

## Git workflow

- Branch: `advisor/014-protocol-hardening`
- One commit per fix: `fix(configs): redact every url on a line`, `fix(configs): cap decoded credentials in all parsers`, `fix(inline): fail closed-delimited bodies over the cap`, `fix(probe): keep query strings in target paths`, `fix(geo): constrain colo to iata-style codes`

## Steps

### Step 1: Redact every URL on a line

Rewrite `redact_line` to iterate `match_indices("://")` and apply the
existing single-URL masking logic per scheme-bearing segment (or run the
single-URL redactor to fixpoint). Preserve current behavior for single-URL
lines (existing tests must pass unchanged).

**Verify**: `cargo test configs` green; new test: a line containing two
`vless://user:pass@host` occurrences redacts BOTH (assert no `user:pass`
remains anywhere).

### Step 2: Cap decoded credentials everywhere

Hoist the `MAX_USER_ID_BYTES` check into one shared spot applied by ALL
spec constructors — e.g. a `finish_spec(spec) -> Result<OutboundSpec>` (or
a constructor fn) called at the end of `parse_sip002`, `parse_vmess`,
`parse_ss`, and `parse_xray_json`. Remove the now-redundant inline check in
`parse_sip002` (or leave it and make the shared check the only one — pick
one place, not two).

**Verify**: new test: a vmess JSON whose decoded `id` is > 1024 bytes is
rejected with the SAME error wording as the SIP002 path; same for an SS
payload. Existing cap test (SIP002) still passes.

### Step 3: Fail over-cap close-delimited bodies

In `inline_verify.rs:596-605`, replace
`stream.take(MAX_PROBE_BODY_BYTES).read_to_end(&mut buf)` with the
cap+1 pattern from `xray.rs:632-636`: take `MAX + 1`, read to end, if
`buf.len() > MAX` return an explicit error (word it like the existing
over-cap error in socks.rs if one exists — read `socks.rs:46-90`).

**Verify**: new test in inline_verify's test module: a close-delimited
response of MAX+1 bytes fails the probe; MAX bytes parses. (Mirror how
existing framing tests build fake streams.)

### Step 4: Keep query strings in target paths

At both sites build the path as:
```rust
let mut path = parsed.path().to_string();
if let Some(q) = parsed.query() {
    path.push('?');
    path.push_str(q);
}
```
(inline is fine; identical at both sites — do NOT extract a shared helper
in this plan; that's plan 026's consolidation.)

**Verify**: new round-trip test per client: target URL
`http://host/cdn-cgi/trace?flag=1` produces a request line containing
`/cdn-cgi/trace?flag=1` (assert on the built `Target.path` / request bytes
however existing tests inspect them).

### Step 5: Constrain colo

In `geo.rs:45-53`: after trimming, accept only `value.len() <= 4` and all
ASCII alphanumeric; return `None` otherwise.

**Verify**: new tests: `"SJO"` → Some; `"sjoo!"` → None; 100-char junk →
None; existing colo tests updated if they used junk fixtures.

## Done criteria

- [ ] `rg -n "fn redact_line" -A 5 src/configs.rs` shows a loop/fixpoint, and the two-URL test passes
- [ ] One shared credential-cap enforcement point; vmess/ss/xray-json all covered (tests)
- [ ] Over-cap close-delimited body fails (test)
- [ ] Query strings preserved at both tunnel clients (tests)
- [ ] colo charset test green; full `cargo test` + clippy + fmt green
- [ ] No files outside scope modified

## STOP conditions

- `redact_line`'s remainder-copy semantics are load-bearing somewhere
  (existing test pins that text AFTER the first URL is preserved verbatim)
  and the multi-URL loop cannot preserve it — preserve per-segment instead
  and note the behavior choice in the report.
- The shared `finish_spec` constructor fights `OutboundSpec`'s visibility or
  construction sites outside configs.rs — report the constructor web.
- Query-string preservation changes an existing test's expected request
  bytes (some test pinned the dropped-query behavior) — update the test and
  flag it in the report (the pin was wrong).

## Maintenance notes

- `finish_spec` (Step 2) becomes the single place any NEW parser must pass
  through — future format support gets the cap for free.
- Plan 026 (HTTP parser consolidation) builds on Step 3/4's sites — leave
  them structurally separate until then.
- Reviewer scrutiny: redaction is a security control — review the two-URL
  test with extra care, including `?`/`#` interaction per segment.
