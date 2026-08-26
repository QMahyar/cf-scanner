# Plan 011: Fix WARP plan sampling — shared RNG and /31-/32 preset routing

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 51c4711..HEAD -- src/engine/warp.rs src/engine/plan.rs src/engine/cdn.rs src/engine/mod.rs`
> On mismatch with the excerpts below, STOP.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW (seeded-test expectations may shift — update deliberately)
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `51c4711`, 2026-08-26

## Why this matters

Two silent coverage bugs in scan planning:

1. **WARP sampling reseeds the RNG per plan item.** `src/engine/warp.rs:232`
   constructs `SplitMix64::new(seed)` fresh inside the per-item loop, so
   every sampled block consumes an IDENTICAL random stream. Under Quick/
   Normal presets the WARP pool decomposes into thousands of /24 `Sample`
   items (`src/engine/plan.rs:87-92`) and every one samples the same relative
   offsets — if that offset happens to be dead upstream, the whole preset
   scan reports 0 finds. The CDN engine already does this right:
   `src/engine/cdn.rs:112-121` hoists the RNG with a WHY comment.
2. **User-supplied /31–/32 custom CIDRs silently probe nothing under
   presets.** Dense-v4 sampling sets `draw_max = host_count - 2`
   (`src/engine/mod.rs:463-467`) → 0 for /31//32, so the iterator yields
   nothing; meanwhile `plan_preset` (`src/engine/plan.rs:87-92`) routes every
   v4 block with prefix ≥ 24 — including user /31–/32 — into `Sample`.
   Result: a /32 target under a preset produces a clean "0 scanned / 0 found"
   summary with no warning, while the same target under `Count`/Full probes
   correctly (those route to `PlanItem::Every` at `plan.rs:127-132`).

## Current state

- `src/engine/warp.rs:230-238` (verified):
  ```rust
  let plan = plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
  for item in &plan {
      for host in plan_hosts_iter(item, &mut SplitMix64::new(seed)) {
          match host {
              IpAddr::V4(ip) => groups.push((ip, ports.clone())),
              IpAddr::V6(_) => bail!("WARP pools must stay IPv4"),
          }
      }
  }
  ```
- `src/engine/cdn.rs:112-121` — the exemplar: RNGs hoisted per port outside
  the outer loop, with a WHY comment ("Hoisted RNG per port outside the
  outer loop so SplitMix64 is not recreated per item").
- `src/engine/plan.rs` — `plan_preset` (or equivalent) routes v4 blocks with
  `prefix >= 24` to `PlanItem::Sample { count: 1..=3 }` under Quick/Normal
  (~87-92) and to `PlanItem::Every` for `Count >= total`/Full (~127-132).
  Read the whole file (154 lines) before editing.
- `src/engine/mod.rs:463-474` — dense-v4 sampling: `draw_max =
  host_count - 2`; iterator yields nothing when `draw_max == 0`. A test at
  `mod.rs:791-802` PINS this sampler edge behavior — keep the sampler as-is;
  fix the ROUTING in plan.rs instead.
- Existing WARP tests use `Count`/custom endpoints (Hosts/Every items), so
  seeded Sample expectations barely shift — verify by running the suite.

Conventions: no comments unless WHY; clippy `-D warnings`; keep the
`i % concurrency` dispatch untouched (v0.8.0 invariant — this plan only
changes plan construction, not dispatch).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Engine tests | `cargo test engine` | all pass (some seeded expectations may need deliberate updates) |
| Full gates | `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` | exit 0 |

## Scope

**In scope**:
- `src/engine/warp.rs` (RNG hoist)
- `src/engine/plan.rs` (/31-/32 routing)
- Test modules in both files

**Out of scope** (do NOT touch):
- `src/engine/mod.rs` sampler internals (the `draw_max = host_count - 2`
  behavior and its pinning test stay)
- `src/engine/cdn.rs`, `phase2.rs`, dispatch code, verdict store
- `src/ranges.rs` CIDR parsing

## Git workflow

- Branch: `advisor/011-warp-sampling`
- Commits: `fix(engine): share one rng across warp plan items`, `fix(engine): probe /31-/32 targets fully under presets`

## Steps

### Step 1: Hoist the WARP RNG

Mirror `cdn.rs:112-121`: create ONE `SplitMix64` before the item loop and
pass `&mut rng` into each `plan_hosts_iter` call:

```rust
let plan = plan(&pool, &cfg.target, &mut SplitMix64::new(seed));
// One RNG across items: reseeding per item made every block sample the
// same offsets (cdn.rs hoists for the same reason).
let mut rng = SplitMix64::new(seed);
for item in &plan {
    for host in plan_hosts_iter(item, &mut rng) {
        ...
```

**Verify**: `cargo test engine` → all pass. If a test asserted specific
seeded hosts from Sample items, UPDATE its expectations deliberately and
note it in the report (the change is the point).

### Step 2: Route tiny CIDRs to Every

In `plan.rs`, wherever v4 blocks with `prefix >= 24` are routed to `Sample`
under Quick/Normal, add a guard: if `cidr.host_count() <= 2` (v4 /31–/32),
emit `PlanItem::Every` instead. Read how `host_count` is exposed on the CIDR
type (it's used at `mod.rs:463` — same crate path). Apply to ALL presets
(Quick/Normal/Full) for consistency — Full already maps to Every via the
Count path; just make the small-block guard unconditional for presets.

**Verify**: `cargo test engine` green; new test: `plan_preset` (or the
actual function name) over `203.0.113.5/32` with Quick yields exactly one
`Every` item covering that host; over a `/24` still yields `Sample`.

### Step 3: Tests

1. `warp_plan_shares_rng_across_items` — build a pool of ≥2 blocks that
   decompose to ≥2 Sample items with a fixed seed; collect the sampled hosts
   per item; assert the relative offsets DIFFER between items (e.g. collect
   `host - block_network_addr` sets and assert inequality). Mirror the
   existing engine test setup helpers (`ok_cfg`/`controller` style at
   `src/engine/mod.rs:589-621` — read them; for plan-level testing you may
   not need a controller at all, call the plan functions directly like
   existing plan tests do).
2. `preset_routes_tiny_cidrs_to_every` (from Step 2).

**Verify**: `cargo test` full suite green.

## Done criteria

- [ ] `rg -n "SplitMix64::new" src/engine/warp.rs` shows exactly ONE construction site in the groups function
- [ ] /31–/32 custom CIDRs under Quick produce `Every` items (test proves it)
- [ ] Full `cargo test` green; clippy/fmt clean
- [ ] Any updated seeded expectations are called out in the report

## STOP conditions

- `plan_hosts_iter`'s signature cannot take `&mut SplitMix64` because it
  already owns its RNG internally (different shape than reported) — report
  the actual signature; the fix becomes passing the seed differently, do not
  redesign the iterator.
- The /31–/32 routing change breaks the `mod.rs:791-802` sampler test — you
  touched the wrong layer; revert and re-read plan.rs.
- Existing WARP tests fail in ways NOT explained by seeded-expectation shifts
  (e.g. count mismatches) — report; something else depends on per-item
  reseeded streams.

## Maintenance notes

- The "one RNG per scan phase" convention now holds in both engines — new
  plan consumers must follow it (cdn.rs is the exemplar).
- If exclusion/pool logic ever yields blocks smaller than /32, the
  `host_count() <= 2` guard already covers them.
- Reviewer scrutiny: confirm dispatch/worker code untouched (`git diff` shows
  only warp.rs groups fn + plan.rs routing).
