# Plan 001: Gate the Svelte UI in CI and give it its first automated tests

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- .github/workflows/checks.yml ui/package.json ui/src`
> If any of those paths changed since `51c4711`, compare the "Current state"
> excerpts below against the live code before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none (do this before any other UI plan)
- **Category**: tests / dx
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

The UI is half the product but has zero automated verification: `ui/package.json`
has no test script, no test runner dependency, and `.github/workflows/checks.yml`
contains no Node step at all. A type error or a broken build merges to main
silently, and `ui/dist` (which is committed and embedded into the binary via
rust-embed) ships whatever was last built on a contributor's machine. Every
other plan in this series that touches `ui/src` depends on this safety net
existing first. This plan also wires the existing shared grammar fixture
(`tests/fixtures/grammar-cases.json`) to the TypeScript validators, so
server-side grammar changes can no longer silently diverge from the UI mirror.

## Current state

- `.github/workflows/checks.yml` (~151 lines) — six jobs, all Rust-only.
  There is no `setup-node`, no `npm ci`, no `npm run check`, no `npm run build`
  anywhere in the file.
- `ui/package.json` — scripts are exactly: `dev`, `build`, `preview`, `check`.
  Dev deps: `@sveltejs/vite-plugin-svelte`, `@tailwindcss/vite`, `svelte
  ^5.48.0`, `svelte-check`, `tailwindcss`, `typescript`, `vite`. No vitest,
  no test script. `"version": "0.5.1"` (stale; product is 0.10.0 — this is
  bookkeeping only, the release version-parity job tracks `npm/cf-scanner/package.json`,
  NOT this file, so bumping it is safe).
- `ui/src/lib/validators.ts` (165 lines) — header comment declares it a
  "line-by-line TypeScript mirror" of the Rust grammar in `src/api/types.rs`
  and `src/ranges.rs`. Duplicated constants `MAX_*` at `validators.ts:8-16`
  mirror `src/api/types.rs:22-49`.
- `tests/fixtures/grammar-cases.json` — shared table of grammar cases
  (CIDR, endpoint, SNI, ports). Consumed today ONLY by Rust tests via
  `include_str!` (`src/api/types.rs:707`, `src/ranges.rs`).
- Zero test files: a glob of `ui/**/*.{test,spec}.*` returns nothing.
- CI convention: jobs in `checks.yml` run on `ubuntu-latest` and
  `windows-latest` legs; Rust jobs use `dtolnay/rust-toolchain@1.88` style
  pinning and `Swatinem/rust-cache`. Match the existing job style.

Repo conventions that apply:

- Rust gates are `cargo test`, `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check` (see `AGENTS.md` "Commands"). The UI equivalent per
  `AGENTS.md` is: `cd ui && npm run check && npm run build`, committing
  `ui/dist` together with `ui/src`.
- Commit style is conventional commits (`feat:`, `fix:`, `ci:`, `test:`,
  `docs:`, `chore:`) — see `git log --oneline -20`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Install UI deps | `cd ui; npm ci` | exit 0 |
| Typecheck UI | `cd ui; npm run check` | exit 0, no errors |
| Build UI | `cd ui; npm run build` | exit 0; writes `ui/dist` |
| UI unit tests (after this plan) | `cd ui; npm test` | all pass |
| Rust gates unchanged | `cargo test` | all pass |

(On Windows PowerShell use `cd ui; npm ci` — same commands as bash otherwise.)

## Scope

**In scope** (the only files you should modify or create):
- `.github/workflows/checks.yml` — add one UI job
- `ui/package.json` — add `test` script, vitest dev-deps, fix `version` to `0.10.0`
- `ui/package-lock.json` — regenerate via `npm install`
- `ui/src/lib/validators.test.ts` (create)
- `ui/src/lib/cfPorts.test.ts` (create)
- `ui/src/lib/cidrPresets.test.ts` (create)
- `ui/src/lib/grammarParity.test.ts` (create)
- `ui/src/lib/resultsView.test.ts` (create)

**Out of scope** (do NOT touch):
- `ui/src/lib/components/*.svelte` — component tests come later; this plan is
  the harness plus pure-module tests only.
- `ui/dist/**` — will change as a side effect of `npm run build` ONLY if the
  build output changes; if `git status` shows `ui/dist` modified, commit it
  together with src per repo convention (rust-embed serves the committed dist).
- `npm/cf-scanner/package.json` — that is the PUBLISHED wrapper's version,
  tracked by the release version-parity job. Never touch it.
- Any Rust file.

## Git workflow

- Branch: `advisor/001-ui-ci-baseline`
- Commits: conventional style, e.g. `ci: gate the svelte ui (check + build + dist drift)` then `test(ui): vitest harness + grammar parity against grammar-cases.json`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add vitest and the test script to the UI package

1. `cd ui`, then `npm install --save-dev vitest @testing-library/svelte@next jsdom`
   (if `@testing-library/svelte@next` fails to resolve, install plain
   `@testing-library/svelte` — the version that supports Svelte 5; check
   `npm view @testing-library/svelte peerDependencies` first and pick the
   major whose peer range includes svelte 5).
2. In `ui/package.json` add to `"scripts"`: `"test": "vitest run"` and
   `"test:watch": "vitest"`. Change `"version"` from `"0.5.1"` to `"0.10.0"`.
3. Create `ui/vitest.config.ts`:

```ts
import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
  },
});
```

**Verify**: `cd ui; npm test` → exit 0 with "no test files found" is
acceptable at this exact point (or create a throwaway test and delete it).
`npm run check` must still exit 0.

### Step 2: Write the first pure-module tests

Create table-driven tests mirroring the repo's Rust test style (see
`src/api/types.rs` tests: small tables of (input, expected) pairs):

1. `ui/src/lib/cfPorts.test.ts` — assert the CDN default port list and WARP
   default port list match the exported constants exactly, and that the
   extended list is sorted and duplicate-free.
2. `ui/src/lib/cidrPresets.test.ts` — assert each exported preset parses and
   round-trips (no throws), using the exported values themselves as the table.
3. `ui/src/lib/validators.test.ts` — table-driven: valid/invalid ports strings,
   CIDR strings, SNI strings through whatever exported validator functions
   `validators.ts` exposes (read it first; use its real exported names).
   Include at least: empty string, whitespace, `0` port, `65536` port,
   `10.0.0.0/8`, `::/0`, `999.1.2.3/24`.
4. `ui/src/lib/resultsView.test.ts` — test the exported filter/sort helpers
   with a small fixture array: latency filter boundary (row exactly at
   `maxLatency` is kept — confirm actual semantics by reading
   `ui/src/lib/resultsView.svelte.ts` and assert what the code does), sort
   ordering, chip filtering.

**Verify**: `cd ui; npm test` → all new tests pass. `npm run check` → exit 0.

### Step 3: Wire the grammar fixture to the TS validators

Create `ui/src/lib/grammarParity.test.ts`:

1. Read `tests/fixtures/grammar-cases.json` (repo root, `tests/fixtures/`).
   In vitest, load it with a relative import:
   `import cases from "../../tests/fixtures/grammar-cases.json";`
   (enable `resolveJsonModule` if `ui/tsconfig.json` doesn't already have it —
   check before editing).
2. The fixture's shape: inspect it and mirror how the Rust side consumes it
   (read the consuming test at `src/api/types.rs` around line 707 for the
   field names: each case has an input plus expected accept/reject per
   grammar kind). For every case of each kind (cidr / endpoint / sni / ports),
   call the corresponding exported function from `ui/src/lib/validators.ts`
   and assert accept/reject parity with the fixture.
3. If any case FAILS: that is a real drift bug. Do not fix the validator in
   this plan — mark the test `test.fails(...)` is NOT acceptable; instead
   STOP and report the failing cases per the STOP conditions below.

**Verify**: `cd ui; npm test` → grammarParity tests pass. If they pass on the
first run, also deliberately invert one assertion locally, re-run to see it
fail, then restore — proving the test reads the fixture.

### Step 4: Add the CI job

Append a new job to `.github/workflows/checks.yml` (keep YAML formatting
consistent with existing jobs):

```yaml
  ui:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: ui/package-lock.json
      - name: Install
        run: npm ci
        working-directory: ui
      - name: Check
        run: npm run check
        working-directory: ui
      - name: Test
        run: npm test
        working-directory: ui
      - name: Build
        run: npm run build
        working-directory: ui
      - name: Fail on un-rebuilt dist
        run: git diff --exit-code ui/dist
```

Notes: match the action versions ALREADY used elsewhere in the file if they
differ (read the file first; e.g. if it pins `@v4` for checkout, use `@v4`).
The `git diff --exit-code ui/dist` step fails CI when `ui/src` changed without
rebuilding the committed dist.

**Verify**: `cargo test` still passes (nothing Rust changed, but prove no
YAML accident broke other jobs' syntax by inspection — GitHub will parse on
push; locally validate indentation carefully). If the repo has `actionlint`
or `yamllint` available, run it on the file; otherwise visually diff against
an existing job's structure.

## Test plan

- New test files listed in Scope; patterns: table-driven like `src/api/types.rs`
  tests (Rust side) — plain arrays of cases, one `it` per rule with a loop body.
- The grammar parity test is the regression net for the repo's documented
  "TS mirrors the Rust grammar" invariant (`validators.ts:1-6`).
- Verification: `cd ui; npm test` → all pass; `cd ui; npm run check` → exit 0.

## Done criteria

- [ ] `cd ui; npm test` exits 0 with the four new test files passing
- [ ] `cd ui; npm run check` exits 0
- [ ] `cd ui; npm run build` exits 0
- [ ] `.github/workflows/checks.yml` contains a `ui` job with check, test, build, and dist-drift steps
- [ ] `ui/package.json` version is `0.10.0` and has a `test` script
- [ ] `npm/cf-scanner/package.json` is UNMODIFIED (`git diff --exit-code npm/cf-scanner/package.json`)
- [ ] No files outside the in-scope list modified (`git status`)

## STOP conditions

Stop and report back if:

- Any `grammarParity` case fails (that is a live UI/server grammar drift — a
  finding, not something to paper over here).
- `npm run check` fails for pre-existing reasons unrelated to your changes
  (report the errors; do not fix unrelated UI code in this plan).
- The vitest + `@testing-library/svelte` versions cannot be resolved for
  Svelte 5 (report versions tried).
- `ui/dist` build output differs massively from the committed one for reasons
  you cannot attribute to your changes (e.g. different vite version resolving
  from a stale lockfile).

## Maintenance notes

- Every future UI plan (003–009) assumes `npm test` and the CI `ui` job exist.
- When `src/api/types.rs` grammar constants change, the parity test is the
  tripwire — update the fixture and both implementations together.
- Component-level tests (ProPanel form flows) are deliberately deferred; the
  harness in Step 1 already supports `@testing-library/svelte` when needed.
- Reviewer should scrutinize: the dist-drift step can false-positive if the
  build is not deterministic across Node versions — if that happens, pin the
  Node version (already done via `node-version: 22`) rather than removing the step.
