# 16: Explicit-only self-update (design first)

**What to build (design, not code):** a decision record for a future explicit-only `self-update` command that can never phone home: invocation shape, tag-pinning (no `latest`), checksum verification strictness, HTTP-client reuse, Windows self-replacement and MSI interplay, and npm-wrapper interplay — with open questions resolved before any implementation ticket is cut.

**Blocked by:** None (can start immediately; implementation is gated on this design, not vice versa).

**Status:** done

Spec: `../spec-best-in-class.md` §P1-7 (sketch input; ADR-006 and USER-GATED releases are hard constraints). Inherits spec §6 execution rules.

- [x] Design covers: explicit-invocation-only shape (`--tag`/`--check`), pinned-target default, `.sha256`-strictness parity, redirect-guard + timeout reuse, Windows rename-and-replace + MSI refuse/defer, platform matrix, npm interplay
- [x] Records what was deliberately left out (automatic checks, banners, `latest`, VERSION polling) and why
- [x] Ends with either implementation tickets or a drop decision; no code lands here

## Result

Decision record for a future explicit-only `self-update` command. No code,
no version bumps, no workflow edits land here. All file/line citations were
verified by direct reads on 2026-09-18 (binary v0.14.0:
`Cargo.toml:3`, `npm/cf-scanner/install.js:13`, `RELEASE_TAG = "v0.14.0"`).

### 1. Core finding: this is a pinned (re)installer, not an updater

Because `latest` resolution is banned (ADR-006, map Out of scope, §07 row 9),
the command **cannot discover newer releases**. Its semantics are therefore:

- `cf-scanner self-update` (no flags) → reinstall the release matching the
  running binary's own `CARGO_PKG_VERSION` (repair path; checksum-verified).
- `cf-scanner self-update --tag vX.Y.Z` → move to exactly that tag
  (upgrade or downgrade — explicit invocation is consent; no prompt).
- `cf-scanner self-update --tag vX.Y.Z --check` → print current-vs-target
  and exit without touching disk or network (pure string compare).
- `cf-scanner self-update --check` (no `--tag`) → trivially "up to date"
  (target defaults to own version). Offline-safe by construction.

Version discovery stays out-of-band (release notes, `npm view
@qmahyar/cf-scanner version`, `gh release list`). This bound is the honest
basis for the implement/drop verdict in §9: the command serves the
repair + explicit-jump segments only.

### 2. Exact invocation shape (clap conventions per `src/cli.rs`)

New variant on the existing `Command` enum (`src/cli.rs:67-126`), following
the file's established patterns (`#[command(about = ...)]` on variants,
`#[arg(long, help = ...)]` on flags, `value_name` for valued flags):

- Subcommand: `self-update`, about: `"Reinstall this binary from its pinned
  GitHub Release (explicit only; never automatic)"`.
- `--tag <TAG>`: `value_name = "TAG"`, help states the pinning rule, the
  `vX.Y.Z` shape, and that `latest` is rejected. Optional; default =
  `"v" + env!("CARGO_PKG_VERSION")` of the running binary (tag is source of
  truth per `docs/release-process.md`; `version` parity job pins
  `Cargo.toml == package.json == RELEASE_TAG`, so own-version-derived tags
  always name a real release for released binaries).
- `--check`: boolean, help: `"Print current vs target and exit without
  downloading or touching disk"`.
- Globals inherit automatically: `--verbose` (human progress on stderr),
  `--json-errors` (existing `{"error": ...}`-on-stdout contract,
  `src/cli.rs:545-550` — no new obligation beyond it).

Tag validation (manual, after parse — mirrors `run_export_config`'s
validate-in-handler style in `src/main.rs:290-306` rather than a
value_parser, so errors stay plain `anyhow` with the sanitized-URL
treatment where applicable):

- Accept `^v\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$` (leading `v` mandatory;
  optional prerelease/build suffix allowed because `release.yml:12` tag
  filters accept suffixes). Reject anything else with a named reason.
- Explicit rejections: `latest`, `main`, bare `1.2.3` (no `v`), URLs /
  any string containing `://`, whitespace, or empty. Rationale: every one
  of these is either the banned unpinned mechanism (§07 row 9) or an SSRF /
  path-confusion shape that must never reach URL construction.
- Dev builds (unreleased `CARGO_PKG_VERSION`, dirty tree): not special-cased.
  Default-target `--check` still prints trivially current; an actual download
  404s on the missing tag and surfaces the classified "unknown tag" error
  (§5). No fallback, no guessing.

Dispatch: one new arm in `run()` (`src/main.rs:70-133`), next to the
`ranges`/`warp-config` arms. No `src/api/types.rs` change (Contract: none —
no scan-config surface, per P1-7 sketch). The update module must not be
imported by engine/wizard/scan paths: grep-guard at review time
(`self_update` referenced from `main.rs` dispatch only).

stdout/stderr contract (holds ticket 07 row 8 / spec §6 line):

- Human progress (download MB, verify, replace steps): stderr, TTY-gated
  ticker style like `run_scan` (`src/main.rs:218-230`).
- `--check` result: **stdout, one stable line** for scripts:
  `cf-scanner <current> -> <tag>: up to date` or `...: update available`.
  (Update-available here only ever arises with an explicit `--tag` that
  differs — see §1.)
- Success note (`replaced <path> (<old> -> <new>)`): stderr, mirroring the
  `ranges refresh` / `warp-config` arms (`src/main.rs:88-94,114-128`).
- Failures: stderr `error: ...` + global `--json-errors` stdout line. No new
  machine-readable output, but add one contract test for the `--check` line
  (spec §6 requires a test per new output).

README: the existing `every_long_scan_flag_is_documented_in_help_and_readme`
test (`src/cli.rs:619-666`) scans long flags — new flags must gain help text
**and** README Commands entries or that test fails. Count this as a
checklist item, not a discovery.

### 3. Tag-pinning logic

```
target_tag = --tag (validated) else "v" + env!("CARGO_PKG_VERSION")
```

- No `latest`, no `VERSION` file, no GitHub API version query, no redirect
  to `/releases/latest` (all triply banned: unpinned + checksum-less +
  phone-home, §07 rows 5/9). The only network hosts ever contacted are
  `github.com` release-download URLs derived from `target_tag` (§4).
- Downgrade (`target < current`): permitted with explicit `--tag`; stderr
  notes the direction (`downgrading 0.14.0 -> v0.13.0`). No interactive
  confirmation — pure CLI must stay scriptable, and explicitness is consent.
- Same-version (`target == current`): still reinstalls (repair). `--check`
  reports `up to date` and exits 0.
- Exit codes: 0 on success and on successful `--check` regardless of
  direction (availability is information, not failure — keeps `--json-errors`
  semantics clean: nonzero always means an error line exists).

### 4. Checksum flow (which artifact, which URL, failure modes)

Artifact selection mirrors `npm/cf-scanner/install.js:15-19,51-56` exactly:

| Host triple (`std::env::consts`) | dist target | archive |
|---|---|---|
| linux x86_64 | `x86_64-unknown-linux-gnu` | `cf-scanner-<target>.tar.xz` |
| linux aarch64 | `aarch64-unknown-linux-gnu` | `cf-scanner-<target>.tar.xz` |
| windows x86_64 | `x86_64-pc-windows-msvc` | `cf-scanner-<target>.zip` |

- URLs: `https://github.com/qmahyar/cf-scanner/releases/download/<TAG>/
  <archive>` and its checksum sibling `<archive>.sha256`. These are the
  per-archive dist `.sha256` files (published by `build-local-artifacts`,
  attested + uploaded by `host`, `release.yml:152-167,289-301`) — **not**
  the aggregate `sha256.sum`, **not** the source tarball, **not** the
  shell/powershell installers, **not** the MSI.
- Fetch order: `.sha256` **first** (fail fast on unknown tag/platform before
  downloading megabytes), then the archive. Both fetches go through
  `ranges::HTTP_CLIENT` (`src/ranges/http.rs:11-25`: rustls, custom redirect
  policy ≤5 hops with `validate_fetch_url` per hop) with an explicit
  call-site `.timeout(...)` — 60s per call, mirroring xray `RealFetch`
  (`src/xray.rs:624-668`), since archives are tens of MB (20s
  `FETCH_TIMEOUT` in `http.rs:9` suits JSON bodies, not archives). Error
  scrubbing mirrors `RealFetch`: `sanitize_url_for_error` +
  `reqwest_msg_without_url`, never `{err:#}` with raw URL (leak contract
  tested in `http.rs:338-380`, `xray.rs:1180-1194`).
- Body caps: 64 MiB Content-Length precheck + streaming cap, identical to
  `RealFetch` (`MAX_BODY_BYTES = 64 MiB`, `src/xray.rs:627,648-664`) and the
  `fetch_tls_inner` chunked pattern (`http.rs:209-228`). Exceeding → abort
  before disk write.
- **Strictness — resolve the twin-parser subtlety here, not at
  implementation time.** `src/dgst.rs:9-29` accepts **only** the
  `SHA2-256= <64hex>[ filename]` (openssl-dgst) shape and would **reject**
  dist's bare-hash `.sha256` files. `install.js parseChecksum`
  (`install.js:155-171`) accepts **both** `sha2-256=` and bare
  `<64hex>[ *filename]` shapes, fail-closed. The implementation must therefore
  **port `parseChecksum` semantics to Rust** (new small pure function with
  vector tests), not reuse `dgst_sha256_hex` literally. Parity rules to port:
  trim + lowercase per line; accept `sha2-256= <64hex>[ <name>]` (exactly one
  space — double-space/tab rejected, matching `dgst.rs:88-136` and the npm
  twin); accept bare `<64hex>[ [*]<name>]`; a first line that *looks like* a
  digest but is malformed (≥65 hex run, `sha2-256=` with bad spacing) is
  **hard invalid** (return None → abort), not skipped; non-digest lines are
  skipped. Compare `sha256(archive_bytes)` hex-lowercased against expected;
  mismatch → delete temp, abort, error names both digests (hashes are not
  secrets — safe to print, unlike URLs/keys).
- Verify-then-write ordering (non-negotiable, mirrors
  `download_verifies_checksum_before_extract`, `xray.rs:981-1012`): bytes are
  hashed in memory; **no disk write happens before verification passes**.
  Temp files live in the executable's own directory (same volume → atomic
  rename) under an OsRng-salted `.tmp-<hex>` name (pattern:
  `paths::secret_temp_name`, `src/paths.rs:317-319` — never pid-derived),
  removed on every error path (pattern: `write_secret_atomic`,
  `src/paths.rs:321-335`).

Failure-mode table (each maps to a classified plain error, `install.js`
`classifyError` analogue in prose — checksum vs network vs platform vs
filesystem — so restricted-network users know which fix applies):

| Failure | Detection | Behavior |
|---|---|---|
| Unknown tag / unpublished version | 404 on `.sha256` fetch | Abort before archive download; "no release <tag>" + releases-page pointer |
| Unsupported OS/arch (macOS, x86, …) | triple not in §4 table | Abort with zero network; macOS message cites ADR-009 + releases page |
| Redirect-guard violation | `HTTP_CLIENT` policy error | Abort; SSRF-safe by construction (§6 `validate_fetch_url`) |
| Timeout / reset / 5xx / rate-limit | call-site timeout, `error_for_status` | Abort; retry nothing automatically (explicit tool — user re-runs) |
| Oversize body | Content-Length / streaming cap | Abort before write |
| Checksum missing/unparseable | ported `parseChecksum` → None | Abort; treat as tamper-or-publish-bug, never proceed |
| Checksum mismatch | hex compare | Abort; temp deleted; binary untouched |
| Non-writable install dir | temp-file probe write at preflight | Abort before any download (fail fast) |
| MSI-owned install | §6 detection | Refuse before any network |
| npm-managed install | §7 detection | Refuse before any network |

### 5. Platform matrix (incl. Windows dance + MSI rule)

Supported (== dist targets, `dist-workspace.toml:9` == `install.js:15-19`;
any drift between the three lists is a bug — implementation adds a comment
pointer at each list + a test asserting the triple set):

- linux x86_64 + aarch64: download `tar.xz`, extract, atomic rename over the
  running image (Unix keeps the running inode — safe), `chmod 0755`
  (mirrors `install.js:322-324` + `make_executable`, `xray.rs:1154-1165`).
  musl/Termux: proceed with the install.js-style stderr NOTE (glibc-linked
  archives; static-musl users take GitHub Releases directly). AGENTS.md
  Termux gotcha stands (document, don't fix).
- windows x86_64 portable zip: **rename-and-replace dance** (a running image
  can be renamed but not overwritten or deleted):
  1. Preflight (§5 failure table) + clean any stale `.old` left by a
     previous run (only when the current exe is healthy).
  2. Stage verified bytes → `cf-scanner.exe.new` (+ staged `bundled/`
     replacement — archives ship `data/bundled` per
     `dist-workspace.toml:11`; mirror `install.js relocateExtracted`,
     `install.js:240-252`: swap binary **and** bundled `xray.exe` together
     so the pair never desyncs; non-regular files refused, cf.
     `assertRegularTree`).
  3. Rename running `cf-scanner.exe` → `cf-scanner.exe.old`; rename
     `.new` → `cf-scanner.exe` (same-dir renames: atomic, no cross-volume
     move).
  4. Attempt `cf-scanner.exe.old` deletion now; expected failure while the
     old image is mapped is **not** an error — it is cleaned on the next
     start / next self-update. Document, don't retry-loop.
  5. Post-verify: execute the **new file** `cf-scanner.exe --version` and
     expect the target version string (same-file execution is safe — new
     handle, new image). Mismatch → roll back from `.old`, abort with error.
- MSI installs **refuse** (no network, hard error, nonzero exit). Detection
  (conservative OR; implementation verifies against a real MSI install on a
  Windows VM because path layouts are the load-bearing assumption):
  (a) `std::env::current_exe()` under `%ProgramFiles%\cf-scanner\bin\`
  (wix `APPLICATIONFOLDER`/`Bin`, `wix/main.wxs:39-77`, perMachine scope
  `:28`); (b) registry uninstall entry carrying the MSI `UpgradeCode`
  `B4B16BC8-2905-4E0E-A024-47552733A782` (`Cargo.toml:12`). Refusal message
  names the exact asset + URL:
  `MSI-owned install; upgrade in place with cf-scanner-<target>.msi from
  https://github.com/qmahyar/cf-scanner/releases/tag/<TAG>`.
  "Defer" (P1-7 wording) is hereby resolved: there is no scheduler and none
  is built — defer means the user re-runs the MSI later; the command itself
  only refuses. MSI-in-place upgrade (README:36) remains the supported path.
- Unsupported: macOS (any arch — ADR-009, hard error, zero network),
  anything outside the 3-row table (hard error naming supported triples +
  releases-page pointer).

Unix post-replace check mirrors Windows step 5 (`<new exe> --version`).
Ctrl+C mid-update: safe by construction — abort is only honored before the
same-dir rename(s); rename itself is not interruptible into a half-state;
temps are cleaned on the next run's stale-file sweep.

### 6. npm-wrapper interplay

- Detection (pure path check on `std::env::current_exe()`, before any
  network): path contains `node_modules/@qmahyar/cf-scanner` (install layout
  `npm/cf-scanner/bin/`, `install.js:245-263`) → **refuse**: `managed by
  npm; run npm i -g @qmahyar/cf-scanner@<X.Y.Z> (tag <TAG> minus leading v)
  instead`. Rationale: overwriting the npm tree would desync `RELEASE_TAG` /
  `package.json` / binary and break the version-parity invariant
  (`release-process.md:157-160`); the wrapper's own `verifyChecksum` path
  already covers npm users.
- Reverse direction (npm updating a self-updated binary): harmless — npm
  reinstalls `bin/` from the pinned release. No coordination needed.
- `cargo install` (`~/.cargo/bin`) copies: plain files, allow (Unix rename /
  Windows dance both work); stderr note suggesting `cargo install` as the
  idiomatic refresh is optional, not required.
- dist shell/powershell installer layouts: same as manual; allow.

### 7. Deliberately excluded and why

| Excluded | Why (constraint) |
|---|---|
| Automatic checks, startup banners, any network on existing paths | ADR-006: results ephemeral, no telemetry, no phone-home. A banner is a check. The updater is reachable **only** via the explicit subcommand; review rule: no `self_update` import outside `main.rs` dispatch. |
| `latest` resolution, `VERSION`-file polling, `/releases/latest` redirects | Map Out of scope + §07 rows 5/9: unpinned, checksum-less-adjacent, rate-limit-prone on restricted networks. Pin-or-nothing. |
| Aggregate `sha256.sum` / Sigstore attestation verification | Different jobs (§07 row 10): `.sha256` attests our per-target archive (sufficient — same trust root as the accepted `install.js` path); attestations are audit-time via `gh attestation verify` (`release-process.md:184`), and verifying them in-binary needs new crypto deps for zero restricted-network value. |
| MSI auto-upgrade / bundled-MSI download-and-exec | Would bypass Windows Installer ownership + perMachine ACLs (`wix/main.wxs:28`); SmartScreen-unsigned-exe execution of a fetched installer from inside the tool is the riskiest shape in this design space. Refuse-and-point instead. |
| Interactive confirmations, `--yes`/`--force` flags | Explicit invocation **is** consent; prompts break scriptability (pure CLI). Destructive scope is bounded to the tool's own files. |
| Delta updates, rollback subcommand, update history/state file | ADR-006 (no persisted state beyond explicit user saves); `.old` cleanup is transient hygiene, not history. Rollback = explicit `--tag` to the older release. |
| `--tag` pointing at xray / third-party assets | `.dgst` verifies the *upstream xray zip* at bundle/download time (§07 row 1) — orthogonal pipeline, untouched. |
| New scan-config / API surface | P1-7: Contract none. `ScanConfig` root stays non-strict forward-compat; updater adds zero fields. |
| UPX, Docker, AUR, Go-GC knobs, per-OS CI split | Rejected in §07 rows 2-4/6-7 (R14); unaffected by this design. |

### 8. Acceptance criteria for the future implementation ticket

One M ticket (≤5 files: `src/cli.rs`, `src/main.rs`, new
`src/self_update.rs`, `README.md`, + tests alongside), **gated on
maintainer approval of new dependencies** (ask-first per AGENTS.md — tar +
xz handling has no in-tree implementation today: `zip` is deflate-only,
`install.js` shells out to system `tar`, which is not portable to a Rust
binary; candidate crates e.g. `tar` + `xz2` need the dep gate resolved
before the ticket starts; shell-out is the fallback only if deps are
refused, with musl/Windows-no-tar behavior explicitly tested).

Must-haves (each is a checkbox on the implementation ticket):

1. `self-update [--tag vX.Y.Z] [--check]` parses per §2; `--tag` validator
   unit tests (accept `v1.2.3`, `v1.2.3-rc.1`; reject `latest`, `main`,
   `1.2.3`, URLs, empty/whitespace).
2. `--check` prints the exact §2 stdout line and performs zero network I/O
   (test asserts no fetch trait call + line regex); `--check` with no `--tag`
   exits 0 offline.
3. Checksum parser ports `install.js parseChecksum` vector-for-vector
   (valid both shapes; 65-hex run → invalid; double-space/tab → invalid;
   missing → invalid; first-malformed-line fail-closed). Mirror the
   `dgst.rs` test style (`src/dgst.rs:31-143`).
4. Offline fake-fetch tests (pattern: `xray.rs:981-1032` `FakeFetch`):
   mismatch → error + zero disk writes (assert mtime/content of a sentinel
   exe unchanged); oversize → abort pre-write; unknown tag (404 on `.sha256`)
   → abort before archive fetch (count fetch calls, cf.
   `concurrent_attempts_share_one_download`, `xray.rs:1383-1424`).
5. Redirect-guard + timeout reuse: violate-guard URL test fails offline via
   `validate_fetch_url` (pattern: `real_fetch_enforces_the_ssrf_guard…`,
   `xray.rs:1168-1177`); every new call site sets `.timeout(...)` (review
   grep, per v0.8.0 invariant).
6. MSI/npm classifiers as pure functions of an exe path (unit-tested with
   fabricated `Program Files`, `node_modules/@qmahyar/cf-scanner`,
   `~/.cargo/bin` paths); refusal happens before any fetch (call-count
   assertion).
7. Windows dance simulated on Unix (temp dir standing in for install dir:
   stage → swap → post `--version` check → stale `.old` sweep) + rollback
   path test (post-check mismatch restores `.old`).
8. `--check` stdout contract test (spec §6 line); `--json-errors` failure
   shape unchanged (existing `parse_error_line` path, no new code).
9. README Commands entries for `self-update --tag/--check` (required by the
   `every_long_…_documented_in_help_and_readme` test) + help-text presence
   (same test enforces it).
10. `cargo test` + `clippy --all-targets -- -D warnings` + `fmt --check`
    green; `cargo audit` clean after any new dep (per release-process
    pre-flight); manual matrix sign-off recorded on the ticket (linux
    x64/arm64 portable, Windows portable dance, Windows MSI-refuse,
    npm-refuse) — manual because CI must never self-replace its own runner
    binary.
11. No version bump, no tag, no workflow/`dist-workspace`/npm-file edit on
    the ticket (USER-GATED; propose nothing that auto-publishes).

### 9. Verdict: IMPLEMENT (conditional, low priority)

**Cut the §8 implementation ticket after P0; do not drop.** Reasoning: the
explicit-only shape fully preserves ADR-006 (no new network on any existing
path, no discovery, no persistence); the trust model reuses only
already-accepted mechanisms (`install.js` pinned-tag + `.sha256` +
`verifyChecksum` strictness, `HTTP_CLIENT` guard + call-site timeout, 64 MiB
caps, verify-before-write); and the residual risk (Windows dance, MSI/npm
heuristics) is contained by refuse-before-network + rollback + manual-matrix
sign-off. Value is narrow but real (§1): repair + explicit jumps for
portable-zip / manual-install users on restricted networks where npm and
re-running installers are friction. DROP would be defensible **only** if the
§8 dependency gate fails (no `tar`/`xz2`, shell-out deemed too fragile) —
in that case the documented fallback (npm wrapper + shell/powershell
installer + MSI in-place upgrade + manual release download, all
checksum-verified) already covers every segment, and this design stands as
the reasoned record of why.

Sharpest open question for implementation time: exact byte format of a
published dist `.sha256` (bare `<hex>[ *name]` vs labeled) — confirm by
fetching one `.sha256` from an existing release (e.g. `v0.14.0`) and pin it
as a parser vector test, so the ported strictness in §4 is tested against
reality, not against `install.js` source alone.

Spec: `../spec-best-in-class.md` §P1-7 (sketch input; ADR-006 and USER-GATED releases are hard constraints). Inherits spec §6 execution rules.

- [ ] Design covers: explicit-invocation-only shape (`--tag`/`--check`), pinned-target default, `.sha256`-strictness parity, redirect-guard + timeout reuse, Windows rename-and-replace + MSI refuse/defer, platform matrix, npm interplay
- [ ] Records what was deliberately left out (automatic checks, banners, `latest`, VERSION polling) and why
- [ ] Ends with either implementation tickets or a drop decision; no code lands here
