<script lang="ts">
  import { Check, Copy, Link2, ShieldCheck } from "@lucide/svelte";
  import { api } from "../api";
  import type { Verdict } from "../types";
  import { errorText, filteredEndpoints, resultFilter, ui } from "../store.svelte";
  import { t } from "../i18n.svelte";

  let { results }: { results: Verdict[] } = $props();
  const app = ui();

  /** Tri-state per research §7: latency-asc → latency-desc → scan order.
   * `null` = unsorted ("scan order" is the engine's latency-sorted store). */
  type SortCol = "latency" | "ip";
  /** Active sort column; null = engine order (tri-state, research §7). */
  let sortOrder = $state<SortCol | null>("latency");
  let sortDir = $state<"asc" | "desc">("asc");
  let copiedIdx = $state<number | null>(null);
  let copiedAll = $state(false);
  let toast = $state("");
  let copiedUriIdx = $state<number | null>(null);
  let copiedPickedIps = $state(false);
  let copiedPickedUris = $state(false);

  const filter = resultFilter();
  let headCheckbox = $state<HTMLInputElement | null>(null);

  /** Row keys the user ticked, keyed ip:port. Selection lives on displayed
   * rows only — a new results array (new scan / F5 refresh) clears it,
   * in-place row updates during a scan keep it. */
  let selected = $state(new Set<string>());

  function compare(a: Verdict, b: Verdict): number {
    if (sortOrder === null) return 0;
    const sign = sortDir === "asc" ? 1 : -1;
    return sortOrder === "latency"
      ? sign * ((a.latency_ms ?? 9e9) - (b.latency_ms ?? 9e9))
      : sign * a.ip.localeCompare(b.ip);
  }

  function cycleSort(k: SortCol): void {
    if (sortOrder !== k) {
      sortOrder = k;
      sortDir = "asc";
    } else if (sortDir === "asc") {
      sortDir = "desc";
    } else {
      // Third click: back to the engine's own ordering.
      sortOrder = null;
    }
  }

  const sorted = $derived(sortOrder === null ? [...results] : [...results].sort(compare));

  /** Everything below renders/operates on this list: checkboxes, action-bar
   * copies, copy-all and the header count all respect the latency filter. */
  const shown = $derived(
    sorted.filter(
      (r) => filter.maxLatency === null || (r.latency_ms ?? 9e9) <= filter.maxLatency,
    ),
  );

  /** Render cap for very large scans (research §7): hundreds of DOM rows are
   * fine; tens of thousands are not. The cap is explicit and lift-able. */
  const RENDER_CAP = 500;
  let renderLimit = $state(RENDER_CAP);
  const capped = $derived(shown.length > renderLimit);
  const visibleRows = $derived(capped ? shown.slice(0, renderLimit) : shown);

  $effect(() => {
    void shown;
    renderLimit = Math.max(renderLimit, RENDER_CAP);
  });

  function keyOf(r: Verdict): string {
    return `${r.ip}:${r.port}`;
  }

  const pickedRows = $derived(shown.filter((r) => selected.has(keyOf(r))));
  const allShownPicked = $derived(
    shown.length > 0 && pickedRows.length === shown.length,
  );

  $effect(() => {
    void results;
    selected = new Set();
  });

  // indeterminate is property-only (no attribute), so drive it imperatively
  $effect(() => {
    if (headCheckbox)
      headCheckbox.indeterminate =
        pickedRows.length > 0 && !allShownPicked;
  });

  function announce(msg: string): void {
    toast = msg;
    setTimeout(() => (toast = ""), 2400);
  }

  function pickRow(r: Verdict, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(keyOf(r));
    else next.delete(keyOf(r));
    selected = next;
  }

  function pickAllDisplayed(on: boolean) {
    selected = on ? new Set(shown.map(keyOf)) : new Set();
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
    await copyText(filteredEndpoints(shown, null), shown.length);
    copiedAll = true;
    setTimeout(() => (copiedAll = false), 1200);
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
    await copyText(pickedRows.map(keyOf).join("\n"), pickedRows.length);
    copiedPickedIps = true;
    setTimeout(() => (copiedPickedIps = false), 1200);
  }

  /** Export each picked passing row through its original config; rows with
   * no usable config are skipped silently rather than failing the batch. */
  async function copyPickedUris() {
    const entries = pickedRows
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

<section class="card fade-in overflow-hidden">
  <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-3">
    <h3 class="text-sm font-semibold">
      {t("table.results")}
      <span class="mono" style="color: var(--ink-muted)">
        {shown.length}{shown.length !== results.length ? ` / ${results.length}` : ""}
      </span>
      {#if app.lastScanVerified}
        <span
          class="pill ms-2 align-middle"
          style="background: oklch(30% .06 155); color: var(--good)"
          title="Every probe ran under your wgconf private key, not a dummy key"
        >
          <ShieldCheck class="size-3.5" />
          {t("table.verified")}
        </span>
      {/if}
    </h3>
    <div class="flex flex-wrap items-center gap-1 text-xs">
      <label
        class="me-1 flex items-center gap-1.5 whitespace-nowrap"
        style="color: var(--ink-muted)"
        title={t("table.maxLatency.hide")}
      >
        {t("table.maxLatency")}
        <input
          class="field mono !w-20 text-center"
          type="number"
          min="0"
          placeholder="any"
          bind:value={filter.maxLatency}
        />
      </label>
      <button
        class="pill"
        style={sortOrder === "latency"
          ? "background: var(--paper-3); color: var(--accent)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        onclick={() => cycleSort("latency")}
      >
        {t("table.sort.latency")}{sortOrder === "latency" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
      </button>
      <button
        class="pill"
        style={sortOrder === "ip"
          ? "background: var(--paper-3); color: var(--accent)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        onclick={() => cycleSort("ip")}
      >
        {t("table.sort.ip")}{sortOrder === "ip" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
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
    </div>
  </div>
  {#if toast}
    <p class="fade-in border-t px-4 py-1.5 text-xs" role="status" style="border-color: oklch(100% 0 0 / 6%); color: var(--good)">
      {toast}
    </p>
  {/if}
  {#if pickedRows.length > 0}
    <div
      class="fade-in flex flex-wrap items-center gap-2 border-t px-4 py-2 text-xs"
      style="border-color: oklch(100% 0 0 / 6%)"
    >
      <span class="mono font-semibold">{t("table.selected", { n: pickedRows.length })}</span>
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
  {#if results.length === 0 && app.running}
    <div class="px-4 py-3 text-xs" aria-busy="true">
      <p class="mono" style="color: var(--ink-muted)">{t("table.skeleton")}</p>
      {#each Array(SKELETON_ROWS) as _, i (i)}
        <div class="mt-2 h-6 animate-pulse rounded" style="background: var(--paper-3); width: {88 - (i % 3) * 12}%"></div>
      {/each}
    </div>
  {:else if results.length > 0 && shown.length === 0 && filter.maxLatency !== null}
    <div class="px-4 py-5 text-sm">
      <p class="font-semibold">{t("empty.filtered.title")}</p>
      <p class="mt-1 text-xs" style="color: var(--ink-muted)">
        {t("empty.filtered.body", { hidden: results.length })}
      </p>
      <button
        class="btn btn-secondary btn-sm mt-2"
        onclick={() => (filter.maxLatency = null)}
      >
        {t("empty.filtered.clear")}
      </button>
    </div>
  {:else if shown.length > 0}
    <div class="max-h-[26rem] overflow-x-auto overflow-y-auto">
      <table class="w-full min-w-[38rem] border-collapse text-sm">
        <thead class="sticky top-0 z-10" style="background: var(--paper-2)">
          <tr class="text-start text-[11px] uppercase tracking-wider" style="color: var(--ink-muted)">
            <th class="w-11 px-1 py-2">
              <label class="mx-auto grid size-8 cursor-pointer place-items-center sm:size-9">
                <input
                  type="checkbox"
                  class="size-4 accent-[var(--accent)]"
                  bind:this={headCheckbox}
                  checked={allShownPicked}
                  onchange={(e) => pickAllDisplayed(e.currentTarget.checked)}
                  aria-label={t("table.select.all")}
                />
              </label>
            </th>
            <th class="px-4 py-2 font-medium" scope="col" aria-sort={sortOrder === "ip" ? (sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <!-- svelte-ignore a11y_role_supports_aria_props_implicit -->
              <button class="uppercase tracking-wider" onclick={() => cycleSort("ip")} aria-sort={sortOrder === "ip" ? (sortDir === "asc" ? "ascending" : "descending") : undefined} aria-label={sortOrder === "ip" ? `${t("table.col.endpoint")} ${sortDir === "asc" ? "ascending" : "descending"}` : t("table.col.endpoint")}>{t("table.col.endpoint")}<span aria-hidden="true">{sortOrder === "ip" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4 py-2 font-medium" scope="col" aria-sort={sortOrder === "latency" ? (sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <!-- svelte-ignore a11y_role_supports_aria_props_implicit -->
              <button class="uppercase tracking-wider" onclick={() => cycleSort("latency")} aria-sort={sortOrder === "latency" ? (sortDir === "asc" ? "ascending" : "descending") : undefined} aria-label={sortOrder === "latency" ? `${t("table.col.latency")} ${sortDir === "asc" ? "ascending" : "descending"}` : t("table.col.latency")}>{t("table.col.latency")}<span aria-hidden="true">{sortOrder === "latency" ? (sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4 py-2 font-medium" scope="col">{t("table.col.country")}</th>
            <th class="px-4 py-2 font-medium" scope="col">{t("table.col.phase2")}</th>
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
                    checked={selected.has(keyOf(r))}
                    onchange={(e) => pickRow(r, e.currentTarget.checked)}
                    aria-label={t("table.row.select", { ep: keyOf(r) })}
                  />
                </label>
              </td>
              <td class="mono px-4 py-2"><span dir="ltr">{r.ip}<span style="color: var(--ink-muted)">:{r.port}</span></span></td>
              <td class="mono px-4 py-2" style="color: {latencyClass(r.latency_ms)}">
                <span dir="ltr">{r.latency_ms}ms</span>
              </td>
              <td class="px-4 py-2" style="color: var(--ink-muted)">
                {r.country ?? "—"}{r.colo ? ` · ${r.colo}` : ""}
              </td>
              <td class="px-4 py-2">
                {#if r.phase2}
                  <span class="pill" style={r.phase2.passed
                    ? "background: oklch(30% .06 155); color: var(--good)"
                    : "background: var(--paper-3); color: var(--ink-muted)"}>
                    {r.phase2.passed ? t("table.phase2.pass", { ms: r.phase2.latency_ms ?? "?" }) : t("table.phase2.fail")}
                  </span>
                {:else}
                  <span style="color: var(--ink-muted)">—</span>
                {/if}
              </td>
              <td class="px-2 py-2 text-end whitespace-nowrap">
                <button
                  class="btn btn-ghost btn-sm"
                  title={t("table.copyUriTitle")}
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
        {t("table.renderCap", { visible: visibleRows.length, total: shown.length })}
      </span>
      <button class="pill cursor-pointer" style="background: var(--paper-3); color: var(--ink)" onclick={() => (renderLimit += RENDER_CAP)}>
        {t("table.showMore", { n: Math.min(RENDER_CAP, shown.length - visibleRows.length) })}
      </button>
    </div>
  {/if}
</section>
