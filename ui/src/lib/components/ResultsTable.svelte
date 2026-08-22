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
  const sortOptions: readonly ("latency" | "ip")[] = ["latency", "ip"];

  const sorted = $derived(
    [...results].sort((a, b) =>
      sortKey === "latency"
        ? (a.latency_ms ?? 9e9) - (b.latency_ms ?? 9e9)
        : a.ip.localeCompare(b.ip),
    ),
  );

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
      const lines = sorted.map((r) => `${r.ip}:${r.port}`).join("\n");
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

  function latencyClass(ms: number | null): string {
    if (ms === null) return "var(--ink-muted)";
    if (ms < 300) return "var(--lat-fast)";
    if (ms < 800) return "var(--lat-mid)";
    return "var(--lat-slow)";
  }
</script>

<section class="card fade-in overflow-hidden">
  <div class="flex items-center justify-between px-4 py-3">
    <h3 class="text-sm font-semibold">
      Results <span class="mono" style="color: var(--ink-muted)">{results.length}</span>
    </h3>
    <div class="flex gap-1 text-xs">
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
        title="Copy every endpoint, one ip:port per line"
        onclick={copyAll}
      >
        {copiedAll ? "copied ✓" : "copy all"}
      </button>
    </div>
  </div>
  <div class="max-h-[26rem] overflow-x-auto overflow-y-auto">
    <table class="w-full min-w-[34rem] border-collapse text-sm">
      <thead class="sticky top-0" style="background: var(--paper-2)">
        <tr class="text-left text-[11px] uppercase tracking-wider" style="color: var(--ink-muted)">
          <th class="px-4 py-2 font-medium">Endpoint</th>
          <th class="px-4 py-2 font-medium">Latency</th>
          <th class="px-4 py-2 font-medium">Country</th>
          <th class="px-4 py-2 font-medium">Phase 2</th>
          <th class="px-4 py-2"></th>
        </tr>
      </thead>
      <tbody>
        {#each sorted as r, i (r.ip + ":" + r.port)}
          <tr class="border-t" style="border-color: oklch(100% 0 0 / 4%)">
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
