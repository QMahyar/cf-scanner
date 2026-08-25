# Wayfinder Map - Phase separation: two lists, independently copyable (Hybrid)

## Destination

Pro UI renders phase-1 (handshake) and phase-2 (tunnel test) results as two
visually distinct lists - side-by-side cards at lg+, tabs below - each
independently sortable and copyable. Phase-2 knobs live in their own card;
a banked-candidates verify works while idle. Shipped behind svelte-check,
ui build, cargo gates, and Playwright visual QA (EN+FA, 375/768/1440).

## Notes

- Svelte 5 runes only; no new deps; existing Ethereal Glass tokens.
- Single source array app.results; split at READ side via ResultsView.
  Never duplicate rows or tag the store (5-critic consensus).
- UI changes commit ui/dist together with ui/src (AGENTS.md).
- Tracker = local markdown (this file). Blocking = frontier order below.
- Naming: CDN tier = "Tunnel test"; "Verified" stays WARP-keypair-only.

## Decisions so far

- Layout: Hybrid - bento two-column at >=lg (1024px), tabs below. User
  choice; critics ranked bento best desktop clarity, tabs best cost/mobile.
- Store: read-side split - one ResultsView class per column over stable
  app.results; per-view sort/filter/selection; shared filter object deleted.
- Naming: Tunnel test (mechanism nouns over outcome adjectives); keys move
  to table.tunnel.* plus a persistent {passed} of {total} summary line.
- Workflow: verify banked while idle - has_candidates on /api/status; idle
  Verify-banked button reuses phase2_only; preserveResults freezes the
  phase-1 list during that run instead of wiping it.
- Config: separate card - configs textarea stays visible; fragment/SNI/
  probe URLs collapse into a details card with a non-default summary;
  routed field errors force it open.
- Simple mode unchanged (user likes it); optional ResultsView adoption only.

## Tickets (frontier order; blocked-by in parentheses)

1. T1 Store + status seam [task, AFK] - blocked by nothing.
   resultsView.svelte.ts (ResultsView class: sort/filter/selection/copy
   pipeline per column, predicate "candidates" | "verified"); delete shared
   filter + resultFilter; /api/status gains has_candidates:boolean;
   startScan(cfg,{preserveResults}) freezes prior rows on phase2_only.
   Files: ui/src/lib/store.svelte.ts, ui/src/lib/resultsView.svelte.ts (new),
   src/server/mod.rs (status payload ~line 97).
2. T3 i18n tunnel rename [task, AFK] - blocked by nothing.
   Rename table.col.phase2->table.tunnel.col ("Tunnel test"/"آزمون تونل"),
   table.phase2.pass->table.tunnel.pass, .fail->table.tunnel.fail,
   pro.phase2.verifyLabel->pro.tunnel.toggle, pro.status.phase2Progress->
   pro.tunnel.progress; add table.tunnel.summary, table.filter.passingOnly,
   table.copyAll.passingTitle, pro.section.tunnelAdvanced. Both locales.
   Keep old keys as aliases during transition so check stays green before
   T4 lands.
3. T4 ProPanel hybrid layout + components [task, AFK] - blocked by T1+T3.
   ResultsTable becomes view-prop renderer (heading prop, filter chips
   All/Verified/Candidates scoped to view, Copy verified button, fail-pill
   title=phase2.error, tunnel summary line under heading). ProPanel:
   two-card bento at lg+ / tab bar below; Verify banked (N) idle button
   gated on has_candidates && configs>=1; phase-2 card split with details
   collapse for expert knobs (force-open on routed errors); preserveResults
   wiring for phase2_only runs. Files: ProPanel.svelte, ResultsTable.svelte,
   SimpleStart.svelte (adopt ResultsView for its best-list), App.svelte if
   props change. Rebuild ui/dist.
4. V1 Gates + visual QA [task, main session] - blocked by T4.
   cargo fmt/clippy/test; npm run check && build; Playwright pass at
   1440/768/375 in EN+FA covering: two cards side-by-side desktop, tabs
   mobile, independent copies, tunnel summary line, Verify banked idle flow.

## Shipped

## Shipped

All tickets above implemented and verified in-session: svelte-check 0/0,
ui build ok, cargo gates green (test/clippy/fmt), Playwright self-QA
passed - two cards at 1440, tabs at 900, chips filter+counts, independent
copies, FA strings render, RTL correct, mobile 375 no horizontal scroll,
backdrop-filter on header only.

Predecessor effort closed under this tracker (v0.8.0 remediation and
follow-through): data-write gate + library facade, server god-file split
into src/server/{mod,state,error,guard,sse}.rs, Windows xray lifecycle
suite, ADR-012 + best-effort SBOM, CI toolchain ref fix, and the v0.9.0
release (GitHub Release + npm latest).

## Not yet specified (fog)

- Whether profiles should persist the phase-2 card separately from the
  phase-1 form (credential-bearing configsText client-side) - decide during
  T4; default = reuse existing server-side profile persistence only.
- Numeric IP comparator + p2-latency-primary display (nice tier from QA
  critic) - fold into V1 polish only if trivial.

## Out of scope

- Backend ScanConfig shape changes (ADR-011); new dependencies; Simple-mode
  visual redesign; ports-validation relaxation for phase2_only (ask-first,
  not needed for this slice).
