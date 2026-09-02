<script lang="ts">
  import { onDestroy } from "svelte";
  import { Check, Copy, Download, FileJson2, FileSpreadsheet, Link2, QrCode, ShieldCheck } from "@lucide/svelte";
  import { api } from "../api";
  import type { Verdict } from "../types";
  import { downloadFile, errorText, exportText, filteredEndpoints, ui } from "../store.svelte";
  import { keyOf, type ResultsView } from "../resultsView.svelte";
  import { t, type MsgKey } from "../i18n.svelte";
  import { toast as pushToast } from "../toast.svelte";
  import QrModal from "./QrModal.svelte";

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

  // Every flash/announce timer is tracked so a mid-flight unmount can't fire
  // into dead state, and a rapid repeat click resets its previous timer.
  const timers = new Set<ReturnType<typeof setTimeout>>();
  function later(fn: () => void, ms: number): void {
    const id = setTimeout(() => {
      timers.delete(id);
      fn();
    }, ms);
    timers.add(id);
  }
  onDestroy(() => {
    for (const id of timers) clearTimeout(id);
    timers.clear();
  });

  function announce(msg: string): void {
    toast = msg;
    later(() => (toast = ""), 2400);
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
      later(() => (copiedIdx = null), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }

  async function copyAll() {
    await copyText(filteredEndpoints(chipRows, view.maxLatency), chipRows.length);
    copiedAll = true;
    later(() => (copiedAll = false), 1200);
  }

  /** The passing list copies independently of the active chip: banked
   * candidates stay visible while passing rows are what users actually
   * paste into a proxy client. */
  async function copyPassing() {
    await copyText(passedRows.map(keyOf).join("\n"), passedRows.length);
    copiedPassing = true;
    later(() => (copiedPassing = false), 1200);
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
      later(() => (copiedUriIdx = null), 1200);
    } catch (e) {
      app.error = errorText(e);
    }
  }

  async function copyPickedIps() {
    await copyText(view.picked.map(keyOf).join("\n"), view.picked.length);
    copiedPickedIps = true;
    later(() => (copiedPickedIps = false), 1200);
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
      later(() => (copiedPickedUris = false), 1200);
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

  // --- Bundle / metadata export + QR (competitor-derived) ------------------
  let qrPayload = $state<string | null>(null);
  let qrTitle = $state("");

  function openQr(text: string, label: string) {
    qrPayload = text;
    qrTitle = label;
  }

  async function exportBundle(format: "base64" | "raw" | "singbox" | "clash") {
    try {
      const text = await api.bundle(format);
      if (format === "singbox") {
        downloadFile(text, "cf-scanner-singbox.json", "application/json");
        pushToast(`${t("export.subscription")} ✓`);
      } else if (format === "clash") {
        downloadFile(text, "cf-scanner-clash.yaml", "text/yaml");
        pushToast(`${t("export.subscription")} ✓`);
      } else if (format === "raw") {
        pushToast(t("export.subscriptionRaw"));
      } else {
        pushToast(t("export.subscription"));
      }
    } catch (e) {
      pushToast(errorText(e), "err");
    }
  }

  async function exportResults(format: "json" | "csv") {
    try {
      const text = await api.resultsExport(format);
      const name = format === "json" ? "cf-scanner-results.json" : "cf-scanner-results.csv";
      downloadFile(text, name, format === "json" ? "application/json" : "text/csv");
      pushToast(`${format.toUpperCase()} ✓`);
    } catch (e) {
      pushToast(errorText(e), "err");
    }
  }

  /** Base64 subscription copied to the clipboard (mobile clients accept a
   * pasted blob directly). Falls back to a file download like exportText. */
  async function copySubscription() {
    try {
      const text = await api.bundle("base64");
      try {
        await navigator.clipboard.writeText(text);
        pushToast(`${t("export.subscription")} ✓`);
      } catch {
        const how = await exportText(text, "cf-scanner-sub.txt");
        pushToast(how === "download" ? t("results.saved") : `${t("export.subscription")} ✓`);
      }
    } catch (e) {
      pushToast(errorText(e), "err");
    }
  }

  async function qrSubscription() {
    try {
      const text = await api.bundle("raw");
      if (!text.trim()) {
        pushToast(t("empty.title"), "err");
        return;
      }
      openQr(text, t("export.subscription"));
    } catch (e) {
      pushToast(errorText(e), "err");
    }
  }

  /** The importable URI for one verified row, or null when the row has no
   * usable source config (fresh page after F5). */
  async function rowUri(r: Verdict): Promise<string | null> {
    const config = exportableConfig(r);
    if (!config) return null;
    try {
      const { uri } = await api.exportUri(config, r.ip, r.port);
      return uri;
    } catch {
      return null;
    }
  }

  async function qrRow(r: Verdict) {
    const uri = await rowUri(r);
    if (!uri) {
      pushToast(errorText(new Error("config unavailable — rerun the scan")), "err");
      return;
    }
    openQr(uri, `${r.ip}:${r.port}`);
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
          class="chip-status ok ms-2 align-middle"
          title={t("table.verifiedTitle")}
        >
          <ShieldCheck class="size-3" />
          {t("table.verified")}
        </span>
      {/if}
    </h3>
    <div class="flex flex-wrap items-center gap-1 text-xs">
      {#if emptyKind === "candidates"}
        {@const verifiedCount = passedRows.length}
        <button
          class="pill"
          aria-pressed={chip === "all"}
          onclick={() => (chip = "all")}
        >
          {t("pro.field.ports.all")} {view.matched.length}
        </button>
        <button
          class="pill"
          aria-pressed={chip === "verified"}
          onclick={() => (chip = "verified")}
        >
          {t("table.filter.passingOnly")} {verifiedCount}
        </button>
        <button
          class="pill"
          aria-pressed={chip === "unverified"}
          onclick={() => (chip = "unverified")}
        >
          {t("table.filter.untested")} {view.matched.length - verifiedCount}
        </button>
      {/if}
      <label
        class="me-1 flex items-center gap-1.5 whitespace-nowrap"
        style="color: var(--ink-muted)"
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
        aria-pressed={view.sortCol === "latency"}
        onclick={() => view.cycleSort("latency")}
      >
        {t("table.sort.latency")}{view.sortCol === "latency" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}
      </button>
      <button
        class="pill"
        aria-pressed={view.sortCol === "ip"}
        onclick={() => view.cycleSort("ip")}
      >
        {t("table.sort.ip")}{view.sortCol === "ip" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}
      </button>
      <button
        class="pill"
        aria-pressed={view.sortCol === "country"}
        onclick={() => view.cycleSort("country")}
      >
        {t("table.col.country")}{view.sortCol === "country" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}
      </button>
      <button
        class="pill"
        class:pill-on={copiedAll}
        title={t("table.copyAllTitle")}
        onclick={copyAll}
      >
        {copiedAll ? `${t("results.copied")} ✓` : t("results.copyAll")}
      </button>
      {#if passedRows.length > 0}
        <button
          class="pill"
          class:pill-on={copiedPassing}
          title={t("table.copyAll.passingTitle")}
          onclick={copyPassing}
        >
          {copiedPassing
            ? `${t("results.copied")} ✓`
            : `${t("results.copyAll")} · ${t("table.filter.passingOnly")}`}
        </button>
      {/if}
      {#if passedRows.length > 0 && emptyKind === "candidates"}
        <span class="mx-1 h-5 w-px" style="background: var(--border)" aria-hidden="true"></span>
        <button
          class="pill"
          title={t("export.subscriptionTitle")}
          onclick={copySubscription}
        >
          <Download class="size-3.5" aria-hidden="true" />
          {t("export.subscription")}
        </button>
        <button class="pill" title={t("export.subscriptionSingbox")} onclick={() => exportBundle("singbox")}>
          {t("export.subscriptionSingbox")}
        </button>
        <button class="pill" title={t("export.subscriptionClash")} onclick={() => exportBundle("clash")}>
          {t("export.subscriptionClash")}
        </button>
        <button class="pill" title="JSON" onclick={() => exportResults("json")}>
          <FileJson2 class="size-3.5" aria-hidden="true" />
          {t("export.json")}
        </button>
        <button class="pill" title="CSV" onclick={() => exportResults("csv")}>
          <FileSpreadsheet class="size-3.5" aria-hidden="true" />
          {t("export.csv")}
        </button>
        <button class="pill" title={t("export.qr")} onclick={() => void qrSubscription()}>
          <QrCode class="size-3.5" aria-hidden="true" />
          {t("export.qr")}
        </button>
      {/if}
    </div>
  </div>
  {#if tunnelSummary}
    <p
      class="border-t px-4 py-1.5 text-xs"
      style="border-color: var(--rule); color: var(--ink-muted)"
    >
      {tunnelSummary}
    </p>
  {/if}
  {#if toast}
    <p class="fade-in border-t px-4 py-1.5 text-xs" role="status" style="border-color: var(--rule); color: var(--good)">
      {toast}
    </p>
  {/if}
  {#if view.picked.length > 0}
    <div
      class="fade-in flex flex-wrap items-center gap-2 border-t px-4 py-2 text-xs"
      style="border-color: var(--rule)"
    >
      <span class="mono font-semibold">{t("table.selected", { n: view.picked.length })}</span>
      <button
        class="pill"
        class:pill-on={copiedPickedIps}
        title={t("table.copySelectedIps")}
        onclick={copyPickedIps}
      >
        {copiedPickedIps ? `${t("results.copied")} ✓` : t("table.copySelectedIps")}
      </button>
      <button
        class="pill"
        class:pill-on={copiedPickedUris}
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
      <p class="mono" style="color: var(--text-dim)">{t("table.skeleton")}</p>
      {#each Array(SKELETON_ROWS) as _, i (i)}
        <div class="skeleton mt-2 h-6" style="width: {88 - (i % 3) * 12}%"></div>
      {/each}
    </div>
  {:else if view.total === 0 && emptyKind === "verified"}
    <div class="px-4 py-5 text-sm">
      <p style="color: var(--text-dim)">{t("pro.tunnel.toggle")}</p>
    </div>
  {:else if view.total === 0}
    <div class="px-4 py-5 text-sm">
      <p class="font-semibold">{t("empty.title")}</p>
      <p class="mt-1 max-w-lg text-xs" style="color: var(--text-dim)">
        {t("empty.body")}
      </p>
    </div>
  {:else if chipRows.length === 0}
    <div class="px-4 py-5 text-sm">
      <p class="font-semibold">{t("empty.filtered.title")}</p>
      <p class="mt-1 text-xs" style="color: var(--text-dim)">
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
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div class="max-h-[26rem] overflow-x-auto overflow-y-auto" tabindex="0" role="region" aria-label={t(headingKey)}>
      <table class="tbl w-full min-w-[34rem]">
        <caption class="sr-only">{t("table.caption")}</caption>
        <thead class="sticky top-0 z-10" style="background: var(--bg-raised)">
          <tr>
            <th class="w-9 px-0 sm:w-11 sm:px-1">
              <label class="mx-auto grid size-8 cursor-pointer place-items-center sm:size-9">
                <input
                  type="checkbox"
                  bind:this={headCheckbox}
                  checked={view.allPicked}
                  onchange={(e) => view.setAll(e.currentTarget.checked)}
                  aria-label={t("table.select.all")}
                />
              </label>
            </th>
            <th class="sticky start-0 z-10 px-4 border-e" scope="col" style="background: var(--bg-raised); border-color: var(--border)" aria-sort={view.sortCol === "ip" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <button class="uppercase tracking-wider" onclick={() => view.cycleSort("ip")} aria-label={view.sortCol === "ip" ? `${t("table.col.endpoint")} ${view.sortDir === "asc" ? "ascending" : "descending"}` : t("table.col.endpoint")}>{t("table.col.endpoint")}<span aria-hidden="true">{view.sortCol === "ip" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4" scope="col" aria-sort={view.sortCol === "latency" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <button class="uppercase tracking-wider" onclick={() => view.cycleSort("latency")} aria-label={view.sortCol === "latency" ? `${t("table.col.latency")} ${view.sortDir === "asc" ? "ascending" : "descending"}` : t("table.col.latency")}>{t("table.col.latency")}<span aria-hidden="true">{view.sortCol === "latency" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4" scope="col" aria-sort={view.sortCol === "country" ? (view.sortDir === "asc" ? "ascending" : "descending") : undefined}>
              <button class="uppercase tracking-wider" onclick={() => view.cycleSort("country")} aria-label={t("table.col.country")}>{t("table.col.country")}<span aria-hidden="true">{view.sortCol === "country" ? (view.sortDir === "asc" ? " ▲" : " ▼") : ""}</span>
              </button>
            </th>
            <th class="px-4" scope="col">{t("table.tunnel.col")}</th>
            <th class="px-2"><span class="sr-only">{t("table.actions")}</span></th>
          </tr>
        </thead>
        <tbody>
          {#each visibleRows as r, i (r.ip + ":" + r.port)}
            <tr>
              <td class="px-0 align-middle sm:px-1">
                <label class="mx-auto grid size-8 cursor-pointer place-items-center sm:size-9">
                  <input
                    type="checkbox"
                    checked={view.selected.has(keyOf(r))}
                    onchange={(e) => view.toggleRow(r, e.currentTarget.checked)}
                    aria-label={t("table.row.select", { ep: keyOf(r) })}
                  />
                </label>
              </td>
              <td class="sticky start-0 z-10 mono px-4 border-e" data-l={t("table.col.endpoint")} style="background: var(--bg-raised); border-color: var(--border)"><span dir="ltr">{r.ip}<span style="color: var(--text-dim)">:{r.port}</span></span></td>
              <td class="mono px-4 text-end" data-l={t("table.col.latency")}>
                <span class="lat-cell" style="color: {latencyClass(r.latency_ms)}">
                  <span class="lat-bar" aria-hidden="true">
                    <i style="width: {r.latency_ms === null ? 0 : Math.max(4, Math.min(100, Math.round((1 - Math.min(r.latency_ms, 900) / 900) * 100)))}%; background: {latencyClass(r.latency_ms)}"></i>
                  </span>
                  <span dir="ltr">{r.latency_ms}ms</span>
                </span>
              </td>
              <td class="px-4" data-l={t("table.col.country")} style="color: var(--text-dim)">
                {r.country ?? "—"}{r.colo ? ` · ${r.colo}` : ""}
              </td>
              <td class="px-4" data-l={t("table.tunnel.col")}>
                {#if r.phase2}
                  <span
                    class="chip-status"
                    class:ok={r.phase2.passed}
                    class:bad={!r.phase2.passed}
                    title={r.phase2.error ?? undefined}>
                    {r.phase2.passed ? t("table.tunnel.pass", { ms: r.phase2.latency_ms ?? "?" }) : t("table.tunnel.fail")}
                  </span>
                {:else}
                  <span style="color: var(--text-dim)">—</span>
                {/if}
              </td>
              <td class="px-2 text-end whitespace-nowrap">
                <button
                  class="btn btn-ghost btn-sm"
                  title={t("table.copyUriTitle")}
                  aria-label={t("table.copyUriAria")}
                  onclick={() => copyUri(r, i)}
                >
                  {#if copiedIdx === i}
                    <Check class="size-4" aria-hidden="true" style="color: var(--success)" />
                  {:else}
                    <Copy class="size-4" aria-hidden="true" />
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
                      <Check class="size-4" aria-hidden="true" style="color: var(--success)" />
                    {:else}
                      <Link2 class="size-4" aria-hidden="true" />
                    {/if}
                  </button>
                  <button
                    class="btn btn-ghost btn-sm"
                    title={t("export.qr")}
                    aria-label={t("export.qr")}
                    onclick={() => void qrRow(r)}
                  >
                    <QrCode class="size-4" aria-hidden="true" />
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
    <div class="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-xs" style="border-color: var(--border); color: var(--text-dim)">
      <span class="mono">
        {t("table.renderCap", { visible: visibleRows.length, total: chipRows.length })}
      </span>
      <button
        class="pill"
        onclick={() => {
          view.renderLimit += view.renderCap;
          // renderLimit feeds the view's cached visible/capped getters; the
          // version-cache only invalidates on markDirty.
          view.markDirty();
        }}
      >
        {t("table.showMore", { n: Math.min(view.renderCap, chipRows.length - visibleRows.length) })}
      </button>
    </div>
  {/if}
  </div>
</section>

{#if qrPayload}
  <QrModal payload={qrPayload} title={qrTitle} onclose={() => (qrPayload = null)} />
{/if}
