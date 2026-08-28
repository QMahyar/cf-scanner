<script lang="ts">
  import { Check, Copy, Link2, ShieldCheck } from "@lucide/svelte";
  import { api } from "../api";
  import type { Verdict } from "../types";
  import { errorText, filteredEndpoints, ui } from "../store.svelte";
  import { keyOf, type ResultsView } from "../resultsView.svelte";
  import { t, type MsgKey } from "../i18n.svelte";

  let {
    view,
    headingKey,
    emptyKind,
  }: {
    /** One column's precomputed pipeline (predicate/sort/filter/selection);
     * this component only renders it. */
    view: ResultsView;
    headingKey: MsgKey;
    emptyKind: "candidates" | "verified" | "simple";
  } = $props();
  const app = ui();

  /** Chip subfilter (candidates card only): the view's phase predicate scopes
   * the column; these narrow what's displayed inside it. */
  type Chip = "all" | "verified" | "unverified";
  let chip = $state<Chip>("all");

  function chipPass(r: Verdict): boolean {
    if (chip === "all") return true;
    return chip === "verified" ? r.phase2?.passed === true : r.phase2?.passed !== true;
  }

  /** Chip applied over view.rows in view sort order; the render cap slices
   * THIS list so "show more" always reveals rows matching the active chip.
   * Counts for chips and copy buttons come from view.matched (uncapped). */
  const { chipRows, passedRows, tunnelSummary } = $derived.by(() => {
    const rows = view.rows;
    const matched = view.matched;
    let cr = rows;
    if (emptyKind === "candidates" && chip !== "all") cr = rows.filter(chipPass);
    let pr: Verdict[] | null = null;
    let ts: string | null = null;
    for (const r of matched) {
      if (r.phase2) {
        if (pr === null) pr = [];
        if (r.phase2.passed) pr.push(r);
      }
    }
    if (pr !== null) ts = t("table.tunnel.summary", { passed: pr.length, total: matched.length });
    return { chipRows: cr, passedRows: pr ?? [], tunnelSummary: ts };
  });
  const visibleRows = $derived(chipRows.slice(0, view.renderLimit));
  const capped = $derived(chipRows.length > view.renderLimit);

  // Approximates the old "new results array clears selection": selection now
  // lives on the view, whose source ref can't be observed from here — but a
  // fresh scan empties the column first, and that is the moment stale ticked
  // keys must go. Mid-run upserts keep total > 0, so they never reset.
  $effect(() => {
    if (view.total === 0) view.resetSelection();
  });

  let headCheckbox = $state<HTMLInputElement | null>(null);
  // indeterminate is property-only (no attribute), so drive it imperatively
  $effect(() => {
    if (headCheckbox)
      headCheckbox.indeterminate = view.picked.length > 0 && !view.allPicked;
  });

  let copiedIdx = $state<number | null>(null);
  let copiedAll = $state(false);
  let toast = $state("");
  let copiedUriIdx = $state<number | null>(null);
  let copiedPickedIps = $state(false);
  let copiedPickedUris = $state(false);
  let copiedPassing = $state(false);

  function announce(msg: string): void {
    toast = msg;
    setTimeout(() => (toast = ""), 2400);
  }

  async function copyText(text: string, n: number) {
    try {
      await navigator.clipboard.writeText(text);
      announce(t("toast.bulkCopied", { n }));
    } catch {
      /* clipboard unavailable */
    }
  }

  async function copyUri(r: Verdict, i: number) {
    try {
      await navigator.clipboard.writeText(`${r.ip}:${r.port}`);
      copiedIdx = i;
      setTimeout(() => (copiedIdx = null), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }

  async function copyAll() {
    await copyText(filteredEndpoints(chipRows, view.maxLatency), chipRows.length);
    copiedAll = true;
    setTimeout(() => (copiedAll = false), 1200);
  }

  /** The passing list copies independently of the active chip: banked
   * candidates stay visible while passing rows are what users actually
   * paste into a proxy client. */
  async function copyPassing() {
    await copyText(passedRows.map(keyOf).join("\n"), passedRows.length);
    copiedPassing = true;
    setTimeout(() => (copiedPassing = false), 1200);
  }

  /** The original config URI this row's phase 2 verified with; null when the
   * row never passed or the index points outside lastScanConfigs (fresh page
   * after F5 — the server keeps configs in memory only). */
  function exportableConfig(r: Verdict): string | null {
    if (!r.phase2?.passed) return null;
    return app.lastScanConfigs[r.phase2.config_index] ?? null;
  }

  async function copyImportable(r: Verdict, i: number) {
    const config = exportableConfig(r);
    if (!config) return;
    try {
      const { uri } = await api.exportUri(config, r.ip, r.port);
      await navigator.clipboard.writeText(uri);
      copiedUriIdx = i;
      setTimeout(() => (copiedUriIdx = null), 1200);
    } catch (e) {
      app.error = errorText(e);
    }
  }

  async function copyPickedIps() {
    await copyText(view.picked.map(keyOf).join("\n"), view.picked.length);
    copiedPickedIps = true;
    setTimeout(() => (copiedPickedIps = false), 1200);
  }

  /** Export each picked passing row through its original config; rows with
   * no usable config are skipped silently rather than failing the batch. */
  async function copyPickedUris() {
    const entries = view.picked
      .map((r) => ({ r, config: exportableConfig(r) }))
      .filter((e): e is { r: Verdict; config: string } => e.config !== null);
    if (entries.length === 0) return;
    try {
      const uris = await Promise.all(
        entries.map((e) => api.exportUri(e.config, e.r.ip, e.r.port)),
      );
      await copyText(uris.map((u) => u.uri).join("\n"), uris.length);
      copiedPickedUris = true;
      setTimeout(() => (copiedPickedUris = false), 1200);
    } catch (e) {
      app.error = errorText(e);
    }
  }

  function latencyClass(ms: number | null): string {
    if (ms === null) return "var(--ink-muted)";
    if (ms < 300) return "var(--lat-fast)";
    if (ms < 800) return "var(--lat-mid)";
    return "var(--lat-slow)";
  }

  const SKELETON_ROWS = 6;
</script>

<section class="shell fade-in">
  <div class="core overflow-hidden">
  <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-3">
    <h3 class="text-sm font-semibold">
      {t(headingKey)}
      <span class="mono" style="color: var(--ink-muted)">
        {chipRows.length}{chipRows.length !== view.total ? ` / ${view.total}` : ""}
      </span>
      {#if app.lastScanVerified}
        <span
          class="pill ms-2 align-middle"
          style="background: oklch(30% .06 155); color: var(--good)"
          title={t("table.verifiedTitle")}
        >
          <ShieldCheck class="size-3.5" />
          {t("table.verified")}
        </span>
      {/if}
    </h3>
    <div class="flex flex-wrap items-center gap-1 text-xs">
      {#if emptyKind === "candidates"}
        {@const verifiedCount = passedRows.length}
        <button
          class="pill cursor-pointer"
          aria-pressed={chip === "all"}
          style={chip === "all"
            ? "background: var(--paper-3); color: var(--accent)"
            : "background: var(--paper-3); color: var(--ink-muted)"}
          onclick={() => (chip = "all")}
        >
          {t("pro.field.ports.all")} {view.matched.length}
        </button>
        <button
          class="pill cursor-pointer"
          aria-pressed={chip === "verified"}
          style={chip === "verified"
            ? "background: var(--paper-3); color: var(--accent)"
            : "background: var(--paper-3); color: var(--ink-muted)"}
          onclick={() => (chip = "verified")}
        >
          {t("table.filter.passingOnly")} {verifiedCount}
        </button>
        <button
          class="pill cursor-pointer"
          aria-pressed={chip === "unverified"}
          style={chip === "unverified"
            ? "background: var(--paper-3); color: var(--accent)"
            : "background: var(--paper-3); color: var(--ink-muted)"}
          onclick={() => (chip = "unverified")}
        >
          {t("table.filter.untested")} {view.matched.length - verifiedCount}
        </button>
      {/if}
      <label
        class="me-1 flex items-center gap-1.5 whitespace-nowrap"
        style="color: var(--ink-muted)"
        title={t("table.maxLatency.hide")}
      >
        {t("table.maxLatency")}
        <!-- WHY select not free input: three meaningful ceilings match the
             latency colour bands; a text field invited arbitrary values the
             colour coding could never reflect. -->
        <select
          class="field mono !w-20 text-center"
          value={view.maxLatency ?? ""}
          onchange={(e) =>
            view.setMaxLatency(
              e.currentTarget.value === "" ? null : Number(e.currentTarget.value),
            )}
        >
          <option value="">—</option>
          <option value="300">≤300</option>
          <option value="800">≤800</option>
        </select>
      </label>
      <button
        class="pill"
        style={view.sortCol === "latency"
          ? "background: var(--paper-3); color: var(--accent)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        onclick={() => view.cycleSort("latency")}
      >
        {t("table.sort.latency")}{view.sortCol === "latency" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}
      </button>
      <button
        class="pill"
        style={view.sortCol === "ip"
          ? "background: var(--paper-3); color: var(--accent)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        onclick={() => view.cycleSort("ip")}
      >
        {t("table.sort.ip")}{view.sortCol === "ip" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}
      </button>
      <button
        class="pill"
        style={copiedAll
          ? "background: var(--paper-3); color: var(--good)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        title={t("table.copyAllTitle")}
        onclick={copyAll}
      >
        {copiedAll ? `${t("results.copied")} ✓` : t("results.copyAll")}
      </button>
      {#if passedRows.length > 0}
        <button
          class="pill"
          style={copiedPassing
            ? "background: var(--paper-3); color: var(--good)"
            : "background: var(--paper-3); color: var(--ink-muted)"}
          title={t("table.copyAll.passingTitle")}
          onclick={copyPassing}
        >
          {copiedPassing
            ? `${t("results.copied")} ✓`
            : `${t("results.copyAll")} · ${t("table.filter.passingOnly")}`}
        </button>
      {/if}
    </div>
  </div>
  {#if tunnelSummary}
    <p
      class="border-t px-4 py-1.5 text-xs"
      style="border-color: oklch(100% 0 0 / 6%); color: var(--ink-muted)"
    >
      {tunnelSummary}
    </p>
  {/if}
  {#if toast}
    <p class="fade-in border-t px-4 py-1.5 text-xs" role="status" style="border-color: oklch(100% 0 0 / 6%); color: var(--good)">
      {toast}
    </p>
  {/if}
  {#if view.picked.length > 0}
    <div
      class="fade-in flex flex-wrap items-center gap-2 border-t px-4 py-2 text-xs"
      style="border-color: oklch(100% 0 0 / 6%)"
    >
      <span class="mono font-semibold">{t("table.selected", { n: view.picked.length })}</span>
      <button
        class="pill cursor-pointer"
        style="background: var(--paper-3); color: {copiedPickedIps ? "var(--good)" : "var(--ink-muted)"}"
        title={t("table.copySelectedIps")}
        onclick={copyPickedIps}
      >
        {copiedPickedIps ? `${t("results.copied")} ✓` : t("table.copySelectedIps")}
      </button>
      <button
        class="pill cursor-pointer"
        style="background: var(--paper-3); color: {copiedPickedUris ? "var(--good)" : "var(--ink-muted)"}"
        title={t("table.copySelectedUris")}
        onclick={copyPickedUris}
      >
        {copiedPickedUris ? `${t("results.copied")} ✓` : t("table.copySelectedUris")}
      </button>
    </div>
  {/if}

  <!-- Skeleton rows while phase 1 runs with nothing banked yet (research §7:
       never show "no records" mid-run). -->
  {#if view.total === 0 && app.running}
    <div class="px-4 py-3 text-xs" aria-busy="true">
      <p class="mono" style="color: var(--ink-muted)">{t("table.skeleton")}</p>
      {#each Array(SKELETON_ROWS) as _, i (i)}
        <div class="mt-2 h-6 animate-pulse rounded" style="background: var(--paper-3); width: {88 - (i % 3) * 12}%"></div>
      {/each}
    </div>
  {:else if view.total === 0 && emptyKind === "verified"}
    <div class="px-4 py-5 text-sm">
      <p style="color: var(--ink-muted)">{t("pro.tunnel.toggle")}</p>
    </div>
  {:else if view.total === 0}
    <div class="px-4 py-5 text-sm">
      <p class="font-semibold">{t("empty.title")}</p>
      <p class="mt-1 max-w-lg text-xs" style="color: var(--ink-muted)">
        {t("empty.body")}
      </p>
    </div>
  {:else if chipRows.length === 0}
    <div class="px-4 py-5 text-sm">
      <p class="font-semibold">{t("empty.filtered.title")}</p>
      <p class="mt-1 text-xs" style="color: var(--ink-muted)">
        {t("empty.filtered.body", { hidden: view.total })}
      </p>
      <button
        class="btn btn-secondary btn-sm mt-2"
        onclick={() => {
          view.setMaxLatency(null);
          chip = "all";
        }}
      >
        {t("empty.filtered.clear")}
      </button>
    </div>
  {:else}
    <div class="max-h-[26rem] overflow-x-auto overflow-y-auto">
      <table class="w-full min-w-[38rem] border-collapse text-sm">
        <caption class="sr-only">Scan results</caption>
        <thead class="sticky top-0 z-10" style="background: var(--paper-2)">
          <tr class="text-start text-[11px] uppercase tracking-wider" style="color: var(--ink-muted)">
            <th class="w-11 px-1 py-2">
              <label class="mx-auto grid size-8 cursor-pointer place-items-center sm:size-9">
                <input
                  type="checkbox"
                  class="size-4 accent-[var(--accent)]"
                  bind:this={headCheckbox}
                  checked={view.allPicked}
                  onchange={(e) => view.setAll(e.currentTarget.checked)}
                  aria-label={t("table.select.all")}
                />
              </label>
            </th>
            <th class="sticky left-0 z-10 bg-[var(--paper-2)] px-4 py-2 font-medium border-e" scope="col" style="border-color: oklch(100% 0 0 / 9%)" aria-sort={view.sortCol === "ip" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <!-- svelte-ignore a11y_role_supports_aria_props_implicit -->
              <button class="uppercase tracking-wider" onclick={() => view.cycleSort("ip")} aria-sort={view.sortCol === "ip" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined} aria-label={view.sortCol === "ip" ? `${t("table.col.endpoint")} ${view.sortDir === "asc" ? "ascending" : "descending"}` : t("table.col.endpoint")}>{t("table.col.endpoint")}<span aria-hidden="true">{view.sortCol === "ip" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4 py-2 font-medium" scope="col" aria-sort={view.sortCol === "latency" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <!-- svelte-ignore a11y_role_supports_aria_props_implicit -->
              <button class="uppercase tracking-wider" onclick={() => view.cycleSort("latency")} aria-sort={view.sortCol === "latency" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined} aria-label={view.sortCol === "latency" ? `${t("table.col.latency")} ${view.sortDir === "asc" ? "ascending" : "descending"}` : t("table.col.latency")}>{t("table.col.latency")}<span aria-hidden="true">{view.sortCol === "latency" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4 py-2 font-medium" scope="col">{t("table.col.country")}</th>
            <th class="px-4 py-2 font-medium" scope="col">{t("table.tunnel.col")}</th>
            <th class="px-2 py-2"><span class="sr-only">{t("table.actions")}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each visibleRows as r, i (r.ip + ":" + r.port)}
            <tr class="border-t" style="border-color: oklch(100% 0 0 / 4%)">
              <td class="px-1 py-2 align-middle">
                <label class="mx-auto grid size-8 cursor-pointer place-items-center sm:size-9">
                  <input
                    type="checkbox"
                    class="size-4 accent-[var(--accent)]"
                    checked={view.selected.has(keyOf(r))}
                    onchange={(e) => view.toggleRow(r, e.currentTarget.checked)}
                    aria-label={t("table.row.select", { ep: keyOf(r) })}
                  />
                </label>
              </td>
              <td class="sticky left-0 z-10 bg-[var(--paper-2)] mono px-4 py-2 border-e" style="border-color: oklch(100% 0 0 / 9%)"><span dir="ltr">{r.ip}<span style="color: var(--ink-muted)">:{r.port}</span></span></td>
              <td class="mono px-4 py-2 text-end" style="color: {latencyClass(r.latency_ms)}">
                <span dir="ltr">{r.latency_ms}ms</span>
              </td>
              <td class="px-4 py-2" style="color: var(--ink-muted)">
                {r.country ?? "—"}{r.colo ? ` · ${r.colo}` : ""}
              </td>
              <td class="px-4 py-2">
                {#if r.phase2}
                  <span
                    class="pill"
                    title={r.phase2.error ?? undefined}
                    style={r.phase2.passed
                      ? "background: oklch(30% .06 155); color: var(--good)"
                      : "background: var(--paper-3); color: var(--ink-muted)"}>
                    {r.phase2.passed ? t("table.tunnel.pass", { ms: r.phase2.latency_ms ?? "?" }) : t("table.tunnel.fail")}
                  </span>
                {:else}
                  <span style="color: var(--ink-muted)">—</span>
                {/if}
              </td>
              <td class="px-2 py-2 text-end whitespace-nowrap">
                <button
                  class="btn btn-ghost btn-sm"
                  title={t("table.copyUriTitle")}
                  aria-label={t("table.copyUriAria")}
                  onclick={() => copyUri(r, i)}
                >
                  {#if copiedIdx === i}
                    <Check class="size-4" style="color: var(--good)" />
                  {:else}
                    <Copy class="size-4" />
                  {/if}
                </button>
                {#if exportableConfig(r)}
                  <button
                    class="btn btn-ghost btn-sm"
                    title={t("table.copyUriExport")}
                    aria-label={t("table.copyExportAria")}
                    onclick={() => copyImportable(r, i)}
                  >
                    {#if copiedUriIdx === i}
                      <Check class="size-4" style="color: var(--good)" />
                    {:else}
                      <Link2 class="size-4" />
                    {/if}
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if capped}
    <div class="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-xs" style="border-color: oklch(100% 0 0 / 6%); color: var(--ink-muted)">
      <span class="mono">
        {t("table.renderCap", { visible: visibleRows.length, total: chipRows.length })}
      </span>
      <button class="pill cursor-pointer" style="background: var(--paper-3); color: var(--ink)" onclick={() => (view.renderLimit += view.renderCap)}>
        {t("table.showMore", { n: Math.min(view.renderCap, chipRows.length - visibleRows.length) })}
      </button>
    </div>
  {/if}
  </div>
</section>
