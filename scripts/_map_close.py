import io

p = "tasks/wayfinder-map.md"
s = io.open(p, newline="", encoding="utf-8").read()

old_head = "### Follow-through after v0.8.0 (2026-08-25, unreleased on main)"
new_block = """### Follow-through after v0.8.0 (2026-08-25) \u2713

| # | Ticket | Files |
|---|--------|-------|
| F1 | Data-write gate + library facade | src/paths.rs, src/lib.rs, src/server/state.rs, src/ranges.rs, src/warpgen.rs, src/xray.rs |
| F2 | Server god-file split | src/server/{mod,state,error,guard,sse}.rs |
| F3 | Windows xray lifecycle (rustc-compiled fake) | tests/xray_lifecycle_windows.rs |
| F4 | ADR-012 + SBOM in release (best-effort on 22.04) | docs/decisions/ADR-012-*, .github/workflows/release.yml |
| F5 | CI toolchain ref fix (env\u2192@1.88, components via rustup) | .github/workflows/{checks,release}.yml |
| F6 | v0.9.0 release (tag \u2192 CI \u2192 Release \u2192 npm latest) | Cargo.toml, npm/*, CHANGELOG |

### Phase-separation effort (2026-08-25, on main after v0.9.0) \u2713

| # | Ticket | Files |
|---|--------|-------|
| T1 | Store read-side split (ResultsView) + has_candidates status seam + preserveResults freeze | ui/src/lib/resultsView.svelte.ts (new), ui/src/lib/store.svelte.ts, src/server/mod.rs |
| T3 | i18n Tunnel-test keys (12 keys \u00d7 EN/FA) | ui/src/lib/i18n.svelte.ts |
| T4 | Hybrid layout (bento lg+ / tabs below), Verify-banked idle path, tunnel card split with collapsed expert knobs, chip filters + Copy passing, fail-pill error tooltips, tunnel summary line | ui/src/lib/components/{ProPanel,ResultsTable,SimpleStart}.svelte, ui/src/App.svelte, ui/src/lib/types.ts |
| T5 | Compact targets: amounts inside preset labels (Quick ~4K / Normal ~12K / Full 1.5M), Custom reveals one inline field; hint lines removed; Simple adopts same pill row with per-mode amounts | SimpleStart.svelte, ProPanel.svelte |
| V1 | Gates: svelte-check 0/0, build ok, cargo test green (361+35+8+12+2), clippy -D warnings, fmt; Playwright self-QA: two cards @1440, tabs @900, chips filter+counts, independent copies, FA strings render, RTL, mobile 375 no-scroll, backdrop-filter header-only | this map |"""

assert old_head in s
idx = s.index(old_head)
# replace from the old heading through the end of the old F5 table row
end_marker = ".github/workflows/{checks,release}.yml` |"
end = s.index(end_marker) + len(end_marker)
s = s[:idx] + new_block + s[end:]
io.open(p, "w", newline="", encoding="utf-8").write(s)
print("map updated")
