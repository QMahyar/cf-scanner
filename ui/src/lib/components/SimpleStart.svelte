<script lang="ts">
  import { Copy, Play, Square } from "@lucide/svelte";
  import { api } from "../api";
  import { resetResults, simpleConfig, ui } from "../store.svelte";

  const app = ui();
  let starting = $state(false);

  async function start() {
    starting = true;
    app.error = null;
    resetResults();
    try {
      await api.scan(simpleConfig());
      app.running = true;
    } catch (e) {
      app.error = String(e);
    }
    starting = false;
  }

  async function stop() {
    await api.cancel();
  }

  const best = $derived(
    [...app.results]
      .filter((r) => r.phase2 ? r.phase2.passed : true)
      .sort((a, b) => (a.latency_ms ?? 9e9) - (b.latency_ms ?? 9e9)),
  );
</script>

<section class="card card-lift fade-in px-6 py-8 sm:px-10 sm:py-12">
  <div class="flex flex-col items-start gap-6 sm:flex-row sm:items-center sm:justify-between">
    <div>
      <p class="mono text-xs uppercase tracking-widest" style="color: var(--accent)">
        cloudflare endpoint finder
      </p>
      <h2
        class="mt-2 text-3xl font-semibold sm:text-4xl"
        style="letter-spacing:-0.03em"
      >
        One tap to working IPs.
      </h2>
      <p class="mt-2 max-w-md text-sm" style="color: var(--ink-muted)">
        Scans Cloudflare's edge from your network and ranks what actually
        answers. Nothing leaves this machine.
      </p>
    </div>
    {#if app.running}
      <button class="btn btn-secondary !px-7 !py-3.5 !text-base" onclick={stop}>
        <Square class="size-5" />
        Stop
      </button>
    {:else}
      <button
        class="btn btn-primary !px-8 !py-4 !text-base"
        onclick={start}
        disabled={starting}
        data-state={starting ? "loading" : undefined}
      >
        <Play class="size-5" />
        {starting ? "Starting…" : "Start scan"}
      </button>
    {/if}
  </div>

  {#if app.running || app.summary}
    {@const pct =
      app.progress.total
        ? Math.min(100, Math.round((app.progress.scanned / app.progress.total) * 100))
        : null}
    <div class="fade-in mt-8" role="status" aria-live="polite">
      <div class="flex items-baseline justify-between text-sm">
        <span>
          <span class="mono font-semibold" style="color: var(--accent)">
            {app.progress.found}</span> working
          <span style="color: var(--ink-muted)">· {app.progress.scanned} checked{pct !== null ? ` · ${pct}%` : ""}</span>
        </span>
        {#if app.summary}
          <span class="mono text-xs" style="color: var(--ink-muted)">
            done in {(app.summary.duration_ms / 1000).toFixed(1)}s{app.summary.cancelled ? " · cancelled" : ""}
          </span>
        {/if}
      </div>
      <div
        class="mt-2 h-1.5 overflow-hidden rounded-full"
        style="background: var(--paper-3)"
      >
        <div
          class="h-full rounded-full transition-all duration-300"
          style="width: {pct ?? 6}%; background: var(--accent); box-shadow: 0 0 16px var(--bloom-a);"
        ></div>
      </div>
    </div>
  {/if}
</section>

{#if best.length > 0}
  <section class="fade-in grid gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-label="Working endpoints">
    {#each best.slice(0, 9) as r, i (r.ip + ":" + r.port)}
      <article class="card card-lift flex items-center justify-between gap-3 px-4 py-3">
        <div class="min-w-0">
          <p class="mono truncate text-sm font-semibold">{r.ip}:{r.port}</p>
          <p class="text-xs" style="color: var(--ink-muted)">
            {r.latency_ms}ms{r.country ? ` · ${r.country}` : ""}{i === 0 ? " · fastest" : ""}
          </p>
        </div>
        <button
          class="btn btn-ghost !px-2"
          title="Copy a ready-to-import URI for this IP"
          onclick={() => navigator.clipboard.writeText(`${r.ip}:${r.port}`)}
        >
          <Copy class="size-4" />
        </button>
      </article>
    {/each}
  </section>
{/if}

<p class="mono px-1 text-[11px]" style="color: var(--ink-muted)">
  flip the Pro switch up top for phase-2 verification, WARP identity, profiles and exports
</p>
