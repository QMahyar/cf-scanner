<script lang="ts">
  import { onMount } from "svelte";
  import { Radar, Rocket, SlidersHorizontal } from "@lucide/svelte";
  import { api, subscribe } from "./lib/api";
  import {
    applyResult,
    resetResults,
    setProMode,
    ui,
  } from "./lib/store.svelte";
  import SimpleStart from "./lib/components/SimpleStart.svelte";
  import ProPanel from "./lib/components/ProPanel.svelte";

  const app = ui();
  let version = $state("");
  let live = $state<"connecting" | "live" | "offline">("connecting");

  onMount(() => {
    api.status().then((s) => (version = s.version)).catch(() => {});
    subscribe({
      onProgress: (p) => {
        app.progress = p;
        app.running = true;
      },
      onResult: (v) => applyResult(v),
      onPhase2: (p) => (app.phase2 = p),
      onFinished: (s) => {
        app.summary = s;
        app.running = false;
        app.phase2 = null;
        api.results().then((r) => (app.results = r.results)).catch(() => {});
      },
      onFailed: (msg) => {
        app.error = msg;
        app.running = false;
      },
    }).onerror = () => {
      live = navigator.onLine ? "connecting" : "offline";
    };
    // The stream stays open across scans; mark it live once connected.
    setTimeout(() => (live = "live"), 800);
  });

  function togglePro() {
    setProMode(!app.proMode);
  }
</script>

<div class="mx-auto flex min-h-screen max-w-6xl flex-col px-4 sm:px-6">
  <header class="flex items-center justify-between py-5">
    <div class="flex items-center gap-3">
      <div
        class="grid size-10 place-items-center rounded-full"
        style="background: var(--accent); box-shadow: 0 0 24px var(--bloom-a);"
      >
        <Radar class="size-5" color="var(--accent-ink)" strokeWidth={2.4} />
      </div>
      <div>
        <h1 class="text-lg font-semibold tracking-tight" style="letter-spacing:-0.03em">
          CF-Scanner
        </h1>
        <p class="mono text-[11px]" style="color: var(--ink-muted)">
          find working Cloudflare endpoints
        </p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <span class="pill" style="background: var(--paper-3); color: var(--ink-muted);">
        <span
          class="size-1.5 rounded-full"
          style="background: {live === 'live'
            ? 'var(--good)'
            : live === 'offline'
              ? 'var(--bad)'
              : 'var(--accent)'}"
        ></span>
        {live}
      </span>
      <button
        type="button"
        class="btn btn-secondary"
        class:btn-primary={app.proMode}
        onclick={togglePro}
        aria-pressed={app.proMode}
        title="Reveal every control: profiles, phase-2 verification, WARP identity, exports"
      >
        <SlidersHorizontal class="size-4" />
        Pro
      </button>
    </div>
  </header>

  <main class="flex flex-1 flex-col gap-6 pb-10">
    {#if app.error}
      <div
        class="fade-in card px-4 py-3 text-sm"
        style="background: oklch(22% 0.06 25 / 40%); color: var(--bad);"
        role="alert"
      >
        {app.error}
        <button class="btn btn-ghost ml-2 !px-2 !py-1" onclick={() => (app.error = null)}>
          dismiss
        </button>
      </div>
    {/if}

    {#if app.proMode}
      <ProPanel />
    {:else}
      <SimpleStart />
    {/if}
  </main>

  <footer
    class="flex flex-wrap items-center justify-between gap-2 border-t py-4 text-xs"
    style="border-color: oklch(100% 0 0 / 6%); color: var(--ink-muted);"
  >
    <span class="mono">v{version || "…"} · last-scan-only · nothing leaves this machine</span>
    <span>
      GeoIP data by
      <a
        class="underline decoration-dotted"
        style="color: var(--accent)"
        href="https://db-ip.com"
        rel="noopener noreferrer"
        target="_blank">db-ip.com</a> (CC BY 4.0)
    </span>
  </footer>
</div>
