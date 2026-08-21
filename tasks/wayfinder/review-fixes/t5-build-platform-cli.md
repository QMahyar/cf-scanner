---
name: Build cache integrity + autostart off-switch + typed interrupt
labels: [wayfinder:task]
state: closed
assignee: ox-alpha
branch: review/platform
blocked-by: []
---

## Question

Findings across `build.rs`, `src/tray.rs`, `src/main.rs`, `src/cli_wizard.rs`,
`src/xray.rs` on a `review/platform` branch.

1. **GeoIP build cache skips pin verification, writes non-atomically** —
   `build.rs:82,99,115,303-307`: `looks_valid` accepts any ≥100 KB file, so a
   truncated cache from a killed build persists forever; checksum runs only on
   the download path; `fs::write(&cache)` has no tmp+rename; `fs::copy(&cache,
   &dest)` result ignored (line 115). Fix: store the verified sha256 beside the
   cache and verify-before-use every build; tmp+rename both writes; fail loudly
   if the copy fails.
2. **dgst parsing duplicated** — `build.rs:266-273` vs `xray.rs:595-608`.
   Acceptable duplication across build/runtime crates? No — build.rs can depend
   on nothing in src; instead extract the shared grammar into a tiny shared
   module both include (e.g. `src/dgst.rs` re-exported, build.rs keeps its
   local copy WITH a cross-referencing comment), or accept and document. Pick
   the smaller diff; the point is one canonical spec of the format.
3. **Autostart has no off-switch; registers before bind** — sole caller is
   `tray::set_autostart(true)` (`main.rs:617`); the delete path
   (`tray.rs:195-200`) is dead code. Add a surface (e.g. `serve --autostart=remove`
   or a `--no-autostart` that unregisters) and move registration AFTER a
   successful listener bind (`main.rs:615-631`). Tests for the command shape.
4. **Wizard interrupt via string compare** — `main.rs:452` matches
   `err.to_string() == "interrupted"` while `cli_wizard.rs:227-233` already
   downcasts properly. Thread a typed marker (thiserror type or downcast in
   main) through instead of the string.

Acceptance: verification trio green; `dist plan --artifacts=all --tag=v0.5.1`
dry-run still succeeds (build.rs changed).

## Resolution

Fixed on eview/platform (worktree cfs-wt-platform), commit 819970b.
GeoIP cache: verify-before-use via .sha256 sidecar, tmp+rename writes, loud
copy failure — PROVEN LIVE (1-byte tampered cache self-healed to 8,284,207 B,
digest match). dgst grammar deduplicated into std-only src/dgst.rs included by
build.rs via #[path] and re-exported through src/xray.rs. --autostart now
takes enable|remove (bare = enable back-compat); remove runs pre-bind, enable
registers only post-bind; ensure_autostart_valid replaces clap requires.
WizardInterrupted typed marker downcast in main.rs. Gate green: 329 lib + 35
bin + 12 property + 3 doctests, 0 failed.
