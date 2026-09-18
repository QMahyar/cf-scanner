# 10: tune subcommand (fragment / junk / sni)

**What to build:** no more guessing obfuscation or fragment settings: a `tune` subcommand walks a bounded candidate list for junk, SNI, or fragment presets, prints live progress with the total cost up front, and ends with a copy-pasteable scan command at the first setting that meets the success threshold. It never logs configs or keys and never persists beyond existing retry-last.

**Blocked by:** 05 (junk/SNI tuners need the engine knobs from ticket 05; without them this half is dropped, not stubbed).

**Status:** done

## Result (driver-implemented 2026-09-18; subagents unavailable — invalid API key)

`tune junk|sni|fragment`: one fresh engine per candidate value at fixed seed
(`TUNE_SEED`), so every value sees the same sample and nothing leaks between
steps or into the last-scan store (no retry-save/enrich/NDJSON). Up-front
spend ceiling, per-step stderr progress, Ctrl+C keeps best-so-far, stdout
carries exactly one reusable command (first meeting the bar, else best-so-far
with a below-threshold note; hard error only when nothing was scanned).

- [x] `tune junk [--counts 8,32,64] [--candidates 50] [--need-pct 30]` (sizes
      fixed 10/50 per warpscout reference; 0 and >128 rejected; ≤8 values);
      `tune sni --snis HOST,...` (required, DNS-only via per-step validate);
      `tune fragment --config URI [--need 3]` (light→medium→heavy, bad URI
      fails fast in validation); all with `--timeout-ms`, all validated per
      step through `cfg.validate()`
- [x] New `src/tune.rs` lib module (thresholds, builders, command renderers,
      budget estimate; 6 unit tests); driver + shared Ctrl+C helper in
      `src/main.rs` (run_scan refactored onto the helper, behavior unchanged)
- [x] Candidate-list flags are CLI-local (no contract change); scan surface untouched
- [x] `cargo test` (732 lib + all targets, 0 failed) + `cargo clippy
      --all-targets -- -D warnings` + `cargo fmt --check` green; README rows
      added (help/README gate passes); live CLI smoke: help renders, bad
      `--counts`/missing `--snis` rejected with flag-named errors

Notes: junk wiring in `run_warp` (05's documented gap) was fixed by the
driver beforehand so tune junk measures live profiles; fragment steps need a
real xray binary like any phase-2 scan (surfaces naturally on failure).

Spec: `../spec-best-in-class.md` §P1-1. Inherits spec §6 execution rules.

- [ ] `tune junk`, `tune sni`, and `tune fragment --config <uri>` with bounded candidate lists, per-step stop/cancel checks, stderr progress + stdout reusable command
- [ ] Fragment tuner verifies a small fixed candidate subset through the existing verify path (light→medium→heavy, first preset meeting need wins)
- [ ] Candidate-list flags are CLI-local (no contract change); scan surface untouched
- [ ] Offline tests for threshold/stop logic; `cargo test` + clippy `-D warnings` + fmt green
