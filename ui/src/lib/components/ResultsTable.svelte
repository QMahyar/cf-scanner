<script lang="ts">
  import { Copy, Download } from "@lucide/svelte";
  import type { Verdict } from "../types";

  let { results }: { results: Verdict[] } = $props();

  let sortKey = $state<"latency" | "ip">("latency");
  let copiedIdx = $state<number | null>(null);
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

  function latencyClass(ms: number | null): string {
    if (ms === null) return "var(--ink-muted)";
    if (ms < 300) return "var(--good)";
    if (ms < 800) return "var(--accent)";
    return "var(--bad)";
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
    </div>
  </div>
  <div class="max-h-[26rem] overflow-y-auto">
    <table class="w-full border-collapse text-sm">
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
            <td class="px-2 py-2 text-right">
              <button
                class="btn btn-ghost !px-2"
                title="Copy ip:port"
                onclick={() => copyUri(r, i)}
              >
                {#if copiedIdx === i}
                  <Download class="size-4" style="color: var(--good)" />
                {:else}
                  <Copy class="size-4" />
                {/if}
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>
