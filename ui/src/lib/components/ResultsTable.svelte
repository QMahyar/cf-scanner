<script lang="ts">
  import { Check, Copy, Link2 } from "@lucide/svelte";
  import { api } from "../api";
  import type { Verdict } from "../types";
  import { errorText, ui } from "../store.svelte";

  let { results }: { results: Verdict[] } = $props();
  const app = ui();

  let sortKey = $state<"latency" | "ip">("latency");
  let copiedIdx = $state<number | null>(null);
  let copiedAll = $state(false);
  let copiedUriIdx = $state<number | null>(null);
  let copiedPickedIps = $state(false);
  let copiedPickedUris = $state(false);
  const sortOptions: readonly ("latency" | "ip")[] = ["latency", "ip"];

  /** Latency ceiling filter; empty input = no filter, garbage = ignored. */
  let maxLatencyText = $state("");
  let headCheckbox = $state<HTMLInputElement | null>(null);

  /** Row keys the user ticked, keyed ip:port. Selection lives on displayed
   * rows only — a new results array (new scan / F5 refresh) clears it,
   * in-place row updates during a scan keep it. */
  let selected = $state(new Set<string>());

  const maxLatency = $derived.by(() => {
    const token = maxLatencyText.trim();
    if (!token) return null;
    const n = Number(token);
    return Number.isFinite(n) && n >= 0 ? n : null;
  });

  const sorted = $derived(
    [...results].sort((a, b) =>
      sortKey === "latency"
        ? (a.latency_ms ?? 9e9) - (b.latency_ms ?? 9e9)
        : a.ip.localeCompare(b.ip),
    ),
  );

  /** Everything below renders/operates on this list: checkboxes, action-bar
   * copies, copy-all and the header count all respect the latency filter. */
  const shown = $derived(
    sorted.filter(
      (r) => maxLatency === null || (r.latency_ms ?? 9e9) <= maxLatency,
    ),
  );

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

  function pickRow(r: Verdict, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(keyOf(r));
    else next.delete(keyOf(r));
    selected = next;
  }

  function pickAllDisplayed(on: boolean) {
    selected = on ? new Set(shown.map(keyOf)) : new Set();
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
    try {
      const lines = shown.map((r) => `${r.ip}:${r.port}`).join("\n");
      await navigator.clipboard.writeText(lines);
      copiedAll = true;
      setTimeout(() => (copiedAll = false), 1200);
    } catch {
      /* clipboard unavailable */
    }
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
    try {
      await navigator.clipboard.writeText(pickedRows.map(keyOf).join("\n"));
      copiedPickedIps = true;
      setTimeout(() => (copiedPickedIps = false), 1200);
    } catch {
      /* clipboard unavailable */
    }
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
      await navigator.clipboard.writeText(uris.map((u) => u.uri).join("\n"));
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
</script>

<section class="card fade-in overflow-hidden">
  <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-3">
    <h3 class="text-sm font-semibold">
      Results
      <span class="mono" style="color: var(--ink-muted)">
        {shown.length}{shown.length !== results.length ? ` / ${results.length}` : ""}
      </span>
    </h3>
    <div class="flex flex-wrap items-center gap-1 text-xs">
      <label
        class="mr-1 flex items-center gap-1.5 whitespace-nowrap"
        style="color: var(--ink-muted)"
        title="Hide rows slower than this ceiling"
      >
        max latency (ms)
        <input
          class="field mono !w-20 text-center"
          type="number"
          min="0"
          placeholder="any"
          bind:value={maxLatencyText}
        />
      </label>
      {#each sortOptions as k (k)}
        <button
          class="pill"
          style={sortKey === k
            ? "background: var(--paper-3); color: var(--accent)"
            : "color: var(--ink-muted)"}
          onclick={() => (sortKey = k)}
        >
          sort {k}
        </button>
      {/each}
      <button
        class="pill"
        style={copiedAll
          ? "background: var(--paper-3); color: var(--good)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        title="Copy every displayed endpoint, one ip:port per line"
        onclick={copyAll}
      >
        {copiedAll ? "copied ✓" : "copy all"}
      </button>
    </div>
  </div>
  {#if pickedRows.length > 0}
    <div
      class="fade-in flex flex-wrap items-center gap-2 border-t px-4 py-2 text-xs"
      style="border-color: oklch(100% 0 0 / 6%)"
    >
      <span class="mono font-semibold">{pickedRows.length} selected</span>
      <button
        class="pill cursor-pointer"
        style="background: var(--paper-3); color: {copiedPickedIps ? "var(--good)" : "var(--ink-muted)"}"
        title="Copy the selected endpoints, one ip:port per line"
        onclick={copyPickedIps}
      >
        {copiedPickedIps ? "copied ✓" : "Copy ip:port"}
      </button>
      <button
        class="pill cursor-pointer"
        style="background: var(--paper-3); color: {copiedPickedUris ? "var(--good)" : "var(--ink-muted)"}"
        title="Export each selected passing row through its original phase-2 config (rows without one are skipped)"
        onclick={copyPickedUris}
      >
        {copiedPickedUris ? "copied ✓" : "Copy URIs (passing only)"}
      </button>
    </div>
  {/if}
  <div class="max-h-[26rem] overflow-x-auto overflow-y-auto">
    <table class="w-full min-w-[38rem] border-collapse text-sm">
      <thead class="sticky top-0" style="background: var(--paper-2)">
        <tr class="text-left text-[11px] uppercase tracking-wider" style="color: var(--ink-muted)">
          <th class="w-8 px-2 py-2">
            <input
              type="checkbox"
              class="accent-[var(--accent)]"
              bind:this={headCheckbox}
              checked={allShownPicked}
              onchange={(e) => pickAllDisplayed(e.currentTarget.checked)}
              aria-label="Select all displayed rows"
            />
          </th>
          <th class="px-4 py-2 font-medium">Endpoint</th>
          <th class="px-4 py-2 font-medium">Latency</th>
          <th class="px-4 py-2 font-medium">Country</th>
          <th class="px-4 py-2 font-medium">Phase 2</th>
          <th class="px-2 py-2"></th>
        </tr>
      </thead>
      <tbody>
        {#each shown as r, i (r.ip + ":" + r.port)}
          <tr class="border-t" style="border-color: oklch(100% 0 0 / 4%)">
            <td class="px-2 py-2 align-middle">
              <input
                type="checkbox"
                class="accent-[var(--accent)]"
                checked={selected.has(keyOf(r))}
                onchange={(e) => pickRow(r, e.currentTarget.checked)}
                aria-label={`Select ${keyOf(r)}`}
              />
            </td>
            <td class="mono px-4 py-2">{r.ip}<span style="color: var(--ink-muted)">:{r.port}</span></td>
            <td class="mono px-4 py-2" style="color: {latencyClass(r.latency_ms)}">
              {r.latency_ms}ms
            </td>
            <td class="px-4 py-2" style="color: var(--ink-muted)">
              {r.country ?? "—"}{r.colo ? ` · ${r.colo}` : ""}
            </td>
            <td class="px-4 py-2">
              {#if r.phase2}
                <span class="pill" style={r.phase2.passed
                  ? "background: oklch(30% .06 155); color: var(--good)"
                  : "background: var(--paper-3); color: var(--ink-muted)"}>
                  {r.phase2.passed ? `pass ${r.phase2.latency_ms ?? "?"}ms` : "fail"}
                </span>
              {:else}
                <span style="color: var(--ink-muted)">—</span>
              {/if}
            </td>
            <td class="px-2 py-2 text-right whitespace-nowrap">
              <button
                class="btn btn-ghost btn-sm"
                title="Copy ip:port"
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
                  title="Copy importable URI (config rewritten to this endpoint)"
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
</section>
