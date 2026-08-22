<script lang="ts">
  import { Check, Copy, Gauge, Play, Square } from "@lucide/svelte";
  import { simpleConfig, startScan, stopScan, ui } from "../store.svelte";
  import type { Mode } from "../types";

  const app = ui();
  let scanMode = $state<Mode>("Cdn");
  let starting = $state(false);
  let findUpTo = $state(10);
  let copiedAll = $state(false);

  async function start() {
    starting = true;
    await startScan(simpleConfig(findUpTo, scanMode));
    starting = false;
  }

  const best = $derived(
    [...app.results]
      .filter((r) => (r.phase2 ? r.phase2.passed : true))
      .sort((a, b) => (a.latency_ms ?? 9e9) - (b.latency_ms ?? 9e9)),
  );

  const SHOWN = 9;
  const hiddenCount = $derived(Math.max(0, best.length - SHOWN));

  /** Rate/ETA recomputed on every progress tick — good enough for a hint. */
  const pace = $derived.by(() => {
    if (!app.running || app.startedAt === null || app.progress.scanned <= 0)
      return null;
    const elapsed = Math.max((Date.now() - app.startedAt) / 1000, 0.5);
    const rate = app.progress.scanned / elapsed;
    if (rate <= 0) return null;
    const eta =
      app.progress.total !== null
        ? Math.max(
            1,
            Math.round((app.progress.total - app.progress.scanned) / rate),
          )
        : null;
    return {
      rate:
        rate >= 100 ? String(Math.round(rate)) : rate.toFixed(1),
      eta,
    };
  });

  const finishedIdle = $derived(!app.running && app.summary !== null);

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(
        best.map((r) => `${r.ip}:${r.port}`).join("\n"),
      );
      copiedAll = true;
      setTimeout(() => (copiedAll = false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }
</script>

<section class="card card-lift fade-in px-6 py-6">
  <div class="flex flex-col items-start gap-6 sm:flex-row sm:items-center sm:justify-between">
    <div>
      <div
        class="mb-3 inline-flex items-center gap-1 rounded-full p-1"
        style="background: var(--paper-3)"
        role="group"
        aria-label="Scan target"
      >
        <button
          type="button"
          class="btn btn-sm btn-secondary"
          class:btn-state-on={scanMode === "Cdn"}
          aria-pressed={scanMode === "Cdn"}
          onclick={() => (scanMode = "Cdn")}
        >
          CDN
        </button>
        <button
          type="button"
          class="btn btn-sm btn-secondary"
          class:btn-state-on={scanMode === "Warp"}
          aria-pressed={scanMode === "Warp"}
          onclick={() => (scanMode = "Warp")}
        >
          WARP
        </button>
      </div>
      <p class="mono text-xs uppercase tracking-widest" style="color: var(--accent)">
        cloudflare endpoint finder
      </p>
      <h2
        class="mt-2 text-3xl font-semibold sm:text-4xl"
        style="letter-spacing:-0.03em"
      >
        {scanMode === "Warp"
          ? "One tap to working endpoints."
          : "One tap to working IPs."}
      </h2>
      <p class="mt-2 max-w-md text-sm" style="color: var(--ink-muted)">
        Scans Cloudflare's edge from your network and ranks what actually
        answers. Results never leave this machine — scans talk only to
        Cloudflare. Working = answered a real TLS handshake.
      </p>
    </div>
    {#if app.running}
      <button class="btn btn-secondary btn-lg" onclick={stopScan}>
        <Square class="size-5" />
        Stop
      </button>
    {:else}
      <div class="flex flex-col items-start gap-1.5 sm:items-end">
        <div class="flex items-center gap-4">
          <label
            class="flex items-center gap-2 text-xs whitespace-nowrap"
            style="color: var(--ink-muted)"
          >
            Find up to
            <input
              class="field mono !w-20 text-center"
              type="number"
              min="5"
              max="100"
              step="1"
              bind:value={findUpTo}
              onchange={() =>
                (findUpTo = Math.min(
                  100,
                  Math.max(5, Math.trunc(Number(findUpTo)) || 10),
                ))}
            />
          </label>
          <button
            class="btn btn-primary btn-lg"
            onclick={start}
            disabled={starting}
            data-state={starting ? "loading" : undefined}
          >
            <Play class="size-5" />
            {starting
              ? "Starting…"
              : scanMode === "Warp"
                ? "Scan WARP"
                : "Start scan"}
          </button>
        </div>
        <span class="mono text-[11px]" style="color: var(--ink-muted)">
          usually finishes in under a minute
        </span>
      </div>
    {/if}
  </div>

  {#if app.running || app.summary}
    {@const pct =
      app.progress.total
        ? Math.min(100, Math.round((app.progress.scanned / app.progress.total) * 100))
        : null}
    <div class="fade-in mt-8" role="status" aria-live="polite">
      {#if finishedIdle}
        <div class="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
          <p class="text-sm font-semibold">
            {app.summary.cancelled
              ? "Stopped early — partial results kept below."
              : `Scan complete — ${app.summary.found} working ${app.summary.found === 1 ? "endpoint" : "endpoints"} below.`}
          </p>
          <span class="mono text-xs" style="color: var(--ink-muted)">
            done in {(app.summary.duration_ms / 1000).toFixed(1)}s
          </span>
        </div>
      {:else}
        <div class="flex items-baseline justify-between text-sm">
          <span>
            <span class="mono font-semibold" style="color: var(--accent)">
              {app.progress.found}</span>
            <span title="passed a real TLS handshake">working</span>
            <span style="color: var(--ink-muted)">· {app.progress.scanned} {scanMode === "Warp" ? "endpoints checked" : "checked"}{pct !== null ? ` · ${pct}%` : ""}</span>
          </span>
          {#if pace}
            <span class="mono text-xs" style="color: var(--ink-muted)">
              ≈{pace.rate}/s{pace.eta !== null ? ` · ~${pace.eta}s left` : ""}
            </span>
          {/if}
        </div>
      {/if}
      <div
        class="mt-2 h-1.5 overflow-hidden rounded-full"
        style="background: var(--paper-3)"
      >
        <div
          class="h-full rounded-full transition-all duration-300"
          style="width: {pct ?? 6}%; background: var(--accent);"
        ></div>
      </div>
    </div>
  {/if}
</section>

{#if !app.running && app.summary === null && best.length === 0}
  <section
    class="card fade-in flex flex-wrap items-center justify-center gap-x-3 gap-y-2 px-4 py-3"
    aria-label="What a scan does"
  >
    <span class="flex items-center gap-1.5 text-xs whitespace-nowrap" style="color: var(--ink-muted)">
      <Play class="size-3.5" />
      Scan Cloudflare's edge
    </span>
    <span aria-hidden="true" class="h-0 w-6 sm:w-10 border-t border-dashed" style="border-color: oklch(100% 0 0 / 15%)"></span>
    <span class="flex items-center gap-1.5 text-xs whitespace-nowrap" style="color: var(--ink-muted)">
      <Gauge class="size-3.5" />
      Rank by real latency
    </span>
    <span aria-hidden="true" class="h-0 w-6 sm:w-10 border-t border-dashed" style="border-color: oklch(100% 0 0 / 15%)"></span>
    <span class="flex items-center gap-1.5 text-xs whitespace-nowrap" style="color: var(--ink-muted)">
      <Copy class="size-3.5" />
      Copy what works
    </span>
  </section>
{/if}

{#if finishedIdle && app.results.length === 0}
  <section class="card fade-in px-6 py-6" aria-label="No results guidance">
    <h3 class="text-base font-semibold">No working endpoints found</h3>
    <p class="mt-2 max-w-lg text-sm" style="color: var(--ink-muted)">
      Your network may be blocking Cloudflare probes on these ports. Try more
      ports (2053, 2083, 8443), a longer timeout, or the Full preset in Pro
      mode.
    </p>
  </section>
{/if}

{#if best.length > 0}
  <section class="fade-in flex flex-col gap-3" aria-label="Working endpoints">
    <div class="flex flex-wrap items-end justify-between gap-2 px-1">
      <div class="min-w-0">
        <h3 class="text-sm font-semibold">Working endpoints</h3>
        <p class="mt-0.5 text-xs" style="color: var(--ink-muted)">
          These answer real TLS handshakes fastest — paste ip:port as your
          proxy client's server address. Working = answered a real TLS
          handshake.
        </p>
      </div>
      <button
        class="pill shrink-0 cursor-pointer"
        style={copiedAll
          ? "background: oklch(30% .06 155); color: var(--good)"
          : "background: var(--paper-3); color: var(--ink-muted)"}
        title="Copy every endpoint (ip:port, one per line)"
        onclick={copyAll}
      >
        {#if copiedAll}
          <Check class="size-3.5" />
          copied
        {:else}
          <Copy class="size-3.5" />
          Copy all
        {/if}
      </button>
    </div>
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {#each best.slice(0, SHOWN) as r, i (r.ip + ":" + r.port)}
        <article class="card card-lift flex items-center justify-between gap-3 px-4 py-3">
          <div class="min-w-0">
            <p class="mono truncate text-sm font-semibold">{r.ip}:{r.port}</p>
            <p class="text-xs" style="color: var(--ink-muted)">
              {r.latency_ms}ms{r.country ? ` · ${r.country}` : ""}{i === 0 ? " · fastest" : ""}
            </p>
          </div>
          <button
            class="btn btn-ghost btn-sm"
            title="Copy this endpoint (ip:port)"
            onclick={() => navigator.clipboard.writeText(`${r.ip}:${r.port}`)}
          >
            <Copy class="size-4" />
          </button>
        </article>
      {/each}
    </div>
    {#if hiddenCount > 0}
      <p class="mono px-1 text-[11px]" style="color: var(--ink-muted)">
        showing fastest {Math.min(SHOWN, best.length)} of {best.length}
      </p>
    {/if}
  </section>
{/if}

<p class="mono px-1 text-[11px]" style="color: var(--ink-muted)">
  flip the Pro switch up top for phase-2 verification, WARP identity, profiles and exports
</p>
