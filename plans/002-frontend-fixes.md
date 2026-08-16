# Plan 002: Frontend fixes (review domain UI)

> **Executor instructions**: Follow this plan step by step. The single in-scope
> file is `embed/index.html` (embedded, single-file UI, vanilla JS). There are
> no automated UI tests — verification is: the file stays valid (the release
> build embeds it via `include_str!`), `cargo test --lib server` still passes
> (server tests reference the embedded UI), and your own reading of the edited
> paths. Report: branch, commit hash, verification output, and which items you
> changed with before/after behavior notes. If any cited location doesn't match
> (drift), stop and report.

## Status

- **Priority**: P2 — **Effort**: M — **Risk**: LOW
- **Depends on**: none at the code level (API item 13 pairs with plan 001
  step 4; works standalone)
- **Category**: bug, dx
- **Planned at**: commit `cd4e3a5`, 2026-08-16

## Why this matters

Frontend review (2026-08-13) found 12 UX/correctness issues in the embedded
UI: accessibility (live-region announces nothing, misused aria-pressed,
hidden progress text), broken behaviors (toast never dismisses under
prefers-reduced-motion, stale terminal events from an old run overwrite the
current run, sort keys/comparators wrong, profile load clobbers ports,
progress line never hides after finish), and reconnect/poll gaps.

## Current state

`embed/index.html` — one file, ~2400 lines. All cited locations were checked
at the base commit `cd4e3a5`. Locate each by function name first; line
numbers are anchors:

1. Toast auto-dismiss (:935-941 toast creation, :532 the reduced-motion CSS
   guard): under `prefers-reduced-motion`, the CSS animation that normally
   triggers `animationend` → dismiss never runs, so the toast stays forever.
2. Progress live region (:1291): the progress element carries `aria-live`,
   but updates replace innerHTML without announcing; also
   `document.title` progress updates (:1374-1410) run on every event with no
   throttle.
3. IP sort comparator (:1256-1260): string comparison — IPv6 sorts wrong
   against IPv4.
4. `reconcileTerminal` (:1961-1991): no generation guard — a terminal event
   replayed from a previous run (reconnect) overwrites the current run's
   state.
5. On `finished`/`failed` the progress text/element stays visible.
6. `beginRun` doesn't clear the phase-2 progress line (`#p2-progress`).
7. The phase-2/start buttons use a 3-state `aria-pressed` (undefined/"mixed")
   — must be strictly true/false.
8. Profile load (:2275, apply at :2071-2079) rewrites the ports field even
   when the user configured ports explicitly.
9. Results-table initial `sortKey` is not `latency_ms` (find the init —
   around the sort state declaration).
10. String-column sort comparator places null/undefined first instead of
    last.
11. The `/api/status` poll doesn't refresh `latestProgress` (so a reconnect
    shows a stale progress line).
12. `localStorage` must stay secret-free (no wgconf/keys ever persisted) —
    verify the current implementation is clean; fix if not.

Plus one API-pairing item:
13. `POST /api/warp/register` can now answer 409 "identity already
    registered" (plan 001). The Register button flow: on 409, show the
    message and automatically retry once with `{"overwrite":true}` (label
    the re-registered result clearly), so re-registration stays one click.

## Commands you will need

| Purpose | Command                 | Expected on success |
|---------|-------------------------|---------------------|
| Build   | `cargo build`           | exit 0 (file embeds) |
| Tests   | `cargo test --lib server` | all pass          |
| Lint    | `cargo clippy --all-targets -- -D warnings` | exit 0 |
| Format  | `cargo fmt --check`     | exit 0              |

## Scope

**In scope**: `embed/index.html` only.

**Out of scope**: all of `src/`, all docs, CI files, `embed` → server wiring
(no server changes needed for the 409 flow — the server accepts `overwrite`
already per plan 001; if plan 001 has NOT merged yet, the frontend still
works: a 409 without retry support would just show the message).

## Git workflow

- Branch: `review/r4-frontend` from `main` (`cd4e3a5`).
- One commit per item group is fine; message style `review: <what>`.
- Do NOT push or merge.

## Steps

For each item, open the cited code, fix, and re-read the edited region.

1. **Toast**: when creating the toast, add a fallback: if
   `matchMedia('(prefers-reduced-motion: reduce)').matches`, schedule
   `setTimeout(dismiss, 4000)` (and clear it on manual dismiss).
2. **Live region**: on `Progress` events set the live region's
   `textContent` (not innerHTML) so screen readers announce changes;
   throttle `document.title` updates to at most one per second (store
   `lastTitleUpdate`).
3. **Sort**: `ip` comparator: both IPv4 → numeric (`Number(parts.join(''))`
   style big-int or pairwise octet compare); mixed → IPv4 first; both IPv6 →
   numeric on parsed groups. Keep the existing latency/path comparators.
4. **Terminal guard**: introduce `let runGen = ++scanGeneration` in
   `beginRun`; capture the generation that started the current run and have
   `reconcileTerminal` ignore `finished`/`failed` whose generation differs.
5. **Finish/fail**: hide the progress text/element (`display:none` or a
   `hidden` class) when the terminal event applies.
6. **beginRun**: clear `#p2-progress` content.
7. **aria-pressed**: set strictly `true`/`false` (never undefined) on the
   toggle buttons; update on toggle.
8. **Profile load**: do not overwrite the ports input when applying a
   profile — preserve the user's current ports (unless the profile was
   explicitly saved with ports… keep the simple rule: never clobber ports on
   load; the review's intent is "user-configured ports survive profile
   loads").
9. **sortKey init**: default the results-table sort key to `latency_ms`.
10. **Nulls-last**: string/number comparators push `null`/`undefined` to the
    end (sort asc/desc consistently).
11. **Poll**: in the `/api/status` poll handler, refresh `latestProgress`
    (from `/api/results` or the stored progress) so a reconnect doesn't show
    a stale value.
12. **localStorage**: audit every `localStorage.setItem` call — none may
    store wgconf text, private keys, or configs containing secrets; if any
    exists, remove it and keep storage to UI prefs only.
13. **Register 409**: in the Register button handler, on HTTP 409 show the
    message and retry once with body `{"overwrite":true}`; display the
    outcome ("identity replaced" vs "registered").

## Test plan

No automated UI tests exist for the embedded file. Verification is:
- `cargo build` + `cargo test --lib server` (embed integrity).
- Manual smoke (document in your report): `cargo run -- serve`, open
  http://127.0.0.1:8765, confirm no console errors on: page load, starting a
  scan, sorting the results table, applying a profile, toggling buttons.

## Done criteria

ALL must hold:
- [ ] Every cited item 1-13 addressed or explicitly explained as already-fixed
- [ ] `cargo build` exit 0; `cargo test --lib server` all pass
- [ ] `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` exit 0
- [ ] `git status` shows only `embed/index.html` modified
- [ ] No `localStorage.setItem` call stores secret material (grep to confirm)
- [ ] Commit on `review/r4-frontend`; report hash + item-by-item notes

## STOP conditions

- Any cited location doesn't exist (drift) — report instead of guessing.
- A fix requires touching `src/` (it shouldn't).
- The 409 flow (item 13) requires a request-shape the server rejects (it
  doesn't — `overwrite` is optional).

## Maintenance notes

- The SSE stream can now be closed by the server when the consumer lags
  (plan 001 step 1). Verify the UI's reconnect path re-opens `/api/events`;
  if the UI uses fetch-based streaming, ensure a reconnect loop exists
  (item 4's generation guard makes replays safe).
- If plan 001's terminal replay ships, the UI will receive a `finished`
  event right after reconnecting to an idle server — the generation guard
  must accept it for the CURRENT generation (that is the fix, not an
  ignore-all).