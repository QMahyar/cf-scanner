# Plan 019: Create Windows secret files with owner-only DACLs from the start

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/warpgen.rs src/xray.rs src/paths.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (Win32 SECURITY_ATTRIBUTES work is easy to get subtly wrong; the existing `lock_down_to_owner` test is the baseline)
- **Depends on**: plans/013 (warpgen rename cleanup lands first, same file)
- **Category**: security
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

On Windows, plaintext secrets — the WARP private key + registration token
(`src/warpgen.rs:358-362` and the identity temp file ~384), exported configs
(~546-550), and xray trial configs carrying ids/passwords
(`src/xray.rs:288-292`) — are created with INHERITED DACLs via
`fs::write` and only locked down to owner-only AFTER the write. Between
creation and `SetNamedSecurityInfoW`, the secrets exist under whatever ACEs
the data dir contributes (typically owner + Administrators + SYSTEM) —
wider than the documented "owner-only suffices" goal (`src/paths.rs:60-65`
documents the post-hoc approach). The Unix branch already achieves
mode-at-open (`warpgen.rs:349-356`). Windows is the platform where most
users run.

## Current state

- `src/warpgen.rs:349-362` — the Unix/Windows split of `write_private`
  (read the function): Unix uses `OpenOptionsExt::mode(0o600)` at open;
  Windows does `fs::write` then `lock_down_to_owner(path)`.
- `lock_down_to_owner` — the existing Windows helper (find it in
  warpgen.rs; it builds/sets the owner-only DACL via the `windows` crate:
  `Win32_Security_Authorization` features are already enabled in
  `Cargo.toml:54`). Read it fully — its DACL-building code is the piece to
  reuse.
- `src/warpgen.rs:384` — identity temp file write (same write-then-lock
  pattern); `:546-550` — exported config writes.
- `src/xray.rs:288-292` — `write_trial_config` (or equivalent) writing
  configs with ids/passwords to the trial dir, then locking down.
- `src/paths.rs:60-65` — doc comment describing the post-hoc approach.
- Existing test: a `lock_down_to_owner` test exists (find it — likely
  `#[cfg(windows)]` in warpgen tests) asserting the resulting DACL. That is
  the verification baseline.
- The `windows` crate features available: `Win32_Foundation`,
  `Win32_Security`, `Win32_Security_Authorization`, `Win32_System_Threading`
  (`Cargo.toml:54`). `CreateFile2` lives in `Win32_Storage::FileSystem` —
  NOT currently enabled. Adding a feature is an "ask first" dependency
  change per AGENTS.md — Step 1 handles this.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Windows tests | `cargo test --lib warpgen` (on Windows) | all pass incl. DACL tests |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/warpgen.rs` (write paths + new helper)
- `src/xray.rs` (trial-config write path)
- `src/paths.rs` (doc comment update)
- `Cargo.toml` (ONE windows-crate feature addition, per Step 1's gate)

**Out of scope** (do NOT touch):
- Unix paths (already correct)
- The DACL CONTENT (owner-only definition stays identical to
  `lock_down_to_owner`'s)
- Non-Windows behavior of any function

## Git workflow

- Branch: `advisor/019-dacl-at-create`
- Commits: `fix(secrets): create windows secret files with owner-only dacl at open`

## Steps

### Step 1: Feature gate (ask-first gate)

`CreateFile2` requires the `Win32_Storage_FileSystem` feature on the
`windows` crate. Check whether the existing `lock_down_to_owner` uses
`SetNamedSecurityInfoW` (Authorization feature, already present) and whether
`OpenOptions`-level custom security attributes are reachable WITHOUT new
features — std's `OpenOptionsExt` on Windows exposes `security_qos_flags`
and `security_attributes`?? NO — std does not expose SECURITY_ATTRIBUTES at
open. So the feature IS needed.

Per AGENTS.md ("Ask first: adding dependencies" — a feature flag on an
existing dependency is borderline; the plan treats it as required): add
`"Win32_Storage_FileSystem"` to the windows crate features in
`Cargo.toml:54` and FLAG this change prominently in the report for
maintainer review.

**Verify**: `cargo check` exit 0 with the new feature.

### Step 2: Build the SECURITY_ATTRIBUTES once, reuse

In warpgen.rs, refactor `lock_down_to_owner`'s DACL-building logic into a
helper that returns the prepared `SECURITY_ATTRIBUTES` (owner-only DACL)
— read the existing DACL construction and reuse it verbatim (same SIDs/
ACEs). Keep `lock_down_to_owner` as a thin wrapper that APPLIES the DACL to
an existing handle/path (it remains the fallback).

### Step 3: Open-with-DACL write helper

Add a `write_private_windows(path, bytes) -> io::Result<()>`:
`CreateFile2(path, GENERIC_WRITE, FILE_SHARE_READ (or none — match
lock_down's sharing), CREATE_ALWAYS, &security_attributes)` then write +
close. On ANY error creating with the DACL, fall back to the CURRENT
sequence (`fs::write` + `lock_down_to_owner`) so a Win32 misuse degrades to
today's behavior, never to a failure to save. One WHY comment at the
fallback.

Apply it to: `write_private`'s Windows branch, the identity temp file, and
the exported-config writes in warpgen.rs; and to xray.rs's trial-config
write (import the helper from warpgen or move it to a small shared module —
prefer moving to `src/paths.rs` if that keeps layering clean; read
paths.rs's role first).

**Verify**: `cargo test --lib warpgen` on Windows: existing
`lock_down_to_owner` test still passes; new test (Step 4).

### Step 4: Test — DACL present at first read

Extend the Windows DACL test: write a file via the new helper, then
IMMEDIATELY query the DACL (the existing test's query mechanism) and assert
owner-only — this proves the DACL was set at CREATE time, not after. (It
cannot prove the absence of the inherited-DACL window directly; the code
review of the CreateFile2 call is that proof — note it in the report.)

**Verify**: test passes; run it twice (CREATE_ALWAYS over an existing file
must also carry the DACL).

## Done criteria

- [ ] `rg -n "fs::write" src/warpgen.rs src/xray.rs` shows NO secret-bearing write on the Windows path outside the fallback
- [ ] New DACL-at-create test passes on Windows; existing lock_down test passes
- [ ] Unix behavior untouched (`git diff` shows cfg(windows)-gated changes only, plus the shared helper's neutral placement)
- [ ] Full gates green; the Cargo.toml feature addition is flagged in the report

## STOP conditions

- The DACL construction in `lock_down_to_owner` cannot be separated from
  its "apply to existing file" step without a rewrite — report its actual
  structure; implement the minimal version (build attributes inline in the
  helper) rather than refactoring the existing fn.
- `CreateFile2`'s return/HANDLE semantics require features beyond
  `Win32_Storage_FileSystem` (e.g. handle wrapping) that balloon the change
  — report; the fallback-only approach (keep fs::write, but shrink the
  window by locking down BEFORE the write via a pre-created empty file) is
  an acceptable degraded outcome if the maintainer prefers.
- Any existing persistence test fails on Windows after the change — report
  the failure; do not weaken the DACL to make tests pass.

## Maintenance notes

- `write_private_windows` (or its final name) is THE way to write secrets on
  Windows — future secret-bearing writes must use it.
- paths.rs's doc comment (60-65) must be updated to describe create-time
  DACLs with the fallback noted.
- Reviewer scrutiny: the fallback must never swallow a DACL error silently —
  it degrades to today's behavior (write + lock down), which is acceptable,
  but a comment and the report must say so.
