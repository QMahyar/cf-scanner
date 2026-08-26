# Plan 018: Harden the npm installer — redirect cap, https-only, no shell interpolation, strict checksum

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- npm/cf-scanner/install.js npm/cf-scanner/package.json`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: S–M
- **Risk**: LOW (behavior identical for the happy path: GitHub release → one redirect → CDN)
- **Depends on**: none
- **Category**: security (supply chain)
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

`npm/cf-scanner/install.js` runs at postinstall on user machines and is the
supply-chain boundary for the binary the sha256 check is supposed to
protect. Four verified defects:

1. **Unbounded redirect recursion that may downgrade to http**
   (`install.js:87-91`): `downloadOnce` picks `http` vs `https` from the
   current URL and recurses on any 3xx `Location` with no hop counter — a
   hijacked/looping redirect hangs every `npm i -g` or walks the download
   onto plain http, defeating TLS exactly where the checksum should protect
   integrity. The Rust-side fetcher enforces both properties
   (`src/ranges.rs:26-34, 614-639`); the wrapper must match.
2. **Install paths interpolated into a PowerShell `-Command` string**
   (`install.js:153-157`): `Expand-Archive -Path '${tmpFile}' ...`
   breaks (or is altered) by any path containing `'` — e.g. a project
   directory with an apostrophe.
3. **Loose checksum extraction** (`install.js:122-128`):
   `/[0-9a-fA-F]{64}/` accepts the first 64-hex substring anywhere in the
   checksum body; the Rust side deliberately rejects loose scans
   (`src/dgst.rs:5-17`, strict grammar `SHA2-256= <64 hex>[ <filename>]`).
4. **Unqualified tar invocation** (`install.js:136-145`): whatever `tar` is
   first on PATH, default flags — no `--no-same-owner`, no post-relocation
   regular-file assertion before `chmodSync` follows entries (~170-181,
   ~235).

## Current state

Read `npm/cf-scanner/install.js` in full (~250 lines) first. Key sites:

- `:87-91` — `downloadOnce(url, ...)` recursion on 3xx; scheme picked per call.
- `:110-119` — retry wrapper around the same recursion.
- `:122-128` — checksum regex extraction.
- `:136-145` — tar extraction (posix path).
- `:153-157` — PowerShell Expand-Archive with interpolated paths (Windows path).
- `:170-181` — relocation of `cf-scanner-{target}` contents out of the
  scratch dir.
- `:205-209` — sha256 verify + fail-closed messaging; `:209` fetches the
  checksum over the same channel.
- `:235` — `chmodSync` on the relocated binary.

The wrapper has NO test runner (plain node script; `npm/cf-scanner/package.json`
scripts are minimal — read it). CI does not exercise the installer.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Syntax check | `node --check npm/cf-scanner/install.js` | exit 0 |
| Smoke install (local) | `node npm/cf-scanner/install.js` with env pointing at a real release tag — ONLY if the operator approves network use; otherwise verify by code review + `node --check` | per script output |
| Wrapper gates | `cd npm/cf-scanner && npm pack --dry-run` | exit 0, file list sane |

## Scope

**In scope**:
- `npm/cf-scanner/install.js` only

**Out of scope** (do NOT touch):
- `npm/cf-scanner/package.json` version (release-parity job tracks it)
- The Rust-side fetcher (already correct — it is the reference)
- Release workflow files

## Git workflow

- Branch: `advisor/018-npm-installer`
- Commits: `fix(npm): cap redirects and require https per hop`, `fix(npm): stop interpolating paths into powershell`, `fix(npm): strict line-anchored checksum parsing`, `fix(npm): harden tar flags and assert regular files before chmod`

## Steps

### Step 1: Redirect cap + https-only

Thread a `hops` parameter through `downloadOnce` (default 0): on 3xx,
increment; `if (hops > 5) throw new Error("too many redirects")`; and before
EVERY request (initial + each hop):
`if (!url.startsWith("https:")) throw new Error("insecure download url: " + scheme)`.
Update the retry wrapper to preserve/reset hops correctly (retries of the
SAME url keep the same hop count — read the wrapper and keep semantics).

**Verify**: `node --check` exit 0. Code-trace: a 6-hop chain throws; an
`http://` hop throws. If a local test is feasible without network (extract
`downloadOnce` to accept an injectable fetch — only if trivial), add it;
otherwise the trace + review is the gate.

### Step 2: PowerShell without interpolation

Pass the two paths via environment variables read inside the PS snippet:

```js
const ps = [
  "$e = $env:CFSCANNER_TMP; $d = $env:CFSCANNER_DEST;",
  "Expand-Archive -Path $e -DestinationPath $d -Force;",
].join(" ");
execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", ps], {
  env: { ...process.env, CFSCANNER_TMP: tmpFile, CFSCANNER_DEST: destDir },
});
```

(Match the script's existing exec helper — read how it shells out today and
use the same mechanism with env vars; keep `-NoProfile -NonInteractive`.)

**Verify**: `node --check` exit 0. On this Windows dev machine, run the
extraction step against a fixture zip in a temp dir under a path WITH an
apostrophe (create `%TEMP%\cf-scanner'test\`) — extraction succeeds. Clean
up the temp dir.

### Step 3: Strict checksum parsing

Replace the loose regex with a line-anchored parse mirroring
`src/dgst.rs`'s grammar: for each line, accept either
`^SHA2-256= ([0-9a-f]{64})(?: (.+))?$` or `^([0-9a-f]{64})(?:  (.+))?$`
(dist-style `hex  filename` uses TWO spaces — read `src/dgst.rs:5-17` and
mirror ITS exact accepted grammar); first match wins; reject the file if a
line has trailing junk after an otherwise-matching hex run. Compare
case-insensitively as today (read current compare).

**Verify**: `node --check` exit 0; add a small pure function
`parseChecksum(text)` and, if the script structure allows a `node -e`
harness, exercise it with: valid dist format, `SHA2-256= <hex> name`,
hex-plus-junk (rejected), short hex (rejected). Otherwise assert by review
and note it.

### Step 4: Tar hardening + regular-file assertion

1. Add flags to the tar invocation: `--no-same-owner --no-same-permissions`
   (GNU/bsdtar both accept; if the script branches per-platform, add to the
   posix branch).
2. After relocation (~170-181) and BEFORE `chmodSync` (~235):
   `const st = fs.lstatSync(p); if (!st.isFile()) throw new Error(...)`
   for the binary and each relocated entry (read what gets relocated;
   assert each).

**Verify**: `node --check` exit 0; code-trace the symlink case: a symlinked
entry now fails the install loudly instead of being chmod'ed through.

## Done criteria

- [ ] `rg -n "hops" npm/cf-scanner/install.js` shows the cap; `rg -n "startsWith\(\"https:" npm/cf-scanner/install.js` present
- [ ] `rg -n "\\\$\{tmpFile\}|\\\$\{destDir\}" npm/cf-scanner/install.js` → no PowerShell interpolation remains
- [ ] Checksum parse is line-anchored (pure function, reviewed against src/dgst.rs grammar)
- [ ] tar flags + lstat assertions present
- [ ] `node --check` exit 0; `npm pack --dry-run` in npm/cf-scanner exit 0
- [ ] No other files modified

## STOP conditions

- The script's exec helper cannot pass env vars (uses `exec` with a shell
  string everywhere) — convert ONLY the PowerShell call site to
  `execFileSync` with env; if the helper is load-bearing for output parsing,
  report.
- The checksum file's real dist format doesn't match either accepted grammar
  (fetch a real `.sha256` from the latest release ONLY with operator
  approval) — report the actual format; align the parser to REALITY and note
  the divergence from src/dgst.rs.
- The apostrophe-path test fails for reasons unrelated to interpolation —
  report; do not ship Step 2 unverified.

## Maintenance notes

- The installer now mirrors the Rust fetcher's guarantees (https-only, hop
  cap, strict checksum) — keep the three in sync mentally; a comment at each
  site should name `src/ranges.rs`/`src/dgst.rs` as the reference.
- If the wrapper ever gains a test runner, Steps 1–3's pure functions are
  the first tests to move there.
- Reviewer scrutiny: this is supply-chain surface — every hunk must trace to
  a step above; no "improvements" beyond scope.
