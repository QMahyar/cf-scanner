<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { Languages, Radar, SlidersHorizontal } from "@lucide/svelte";
  import { api, subscribe, type LiveStatus } from "./lib/api";
  import { currentLocale, t, toggleLocale } from "./lib/i18n.svelte";
  import { applyResult, recordTick, setProMode, ui } from "./lib/store.svelte";
  import SimpleStart from "./lib/components/SimpleStart.svelte";
  import ProPanel from "./lib/components/ProPanel.svelte";

  const app = ui();
  let version = $state("");
  let live = $state<LiveStatus>("connecting");
  const liveLabel = $derived(
    live === "live"
      ? t("live.live")
      : live === "offline"
        ? t("live.offline")
        : t("live.connecting"),
  );

  /** F5 mid-scan: the engine keeps last-scan state in memory, so pull it
   * once instead of showing a blank page until the next SSE tick. */
  async function hydrate() {
    try {
      const [s, r] = await Promise.all([api.status(), api.results()]);
      version = s.version;
      for (const v of r.results) applyResult(v);
      if (r.summary) {
        app.summary = r.summary;
        app.progress.scanned = Math.max(app.progress.scanned, r.summary.scanned);
        app.progress.found = Math.max(app.progress.found, r.summary.found);
      }
      if (s.is_running) app.running = true;
    } catch {
      /* server unreachable; the live pill reports connectivity */
    }
  }

  let es: EventSource | null = null;
  let hadLive = $state(false);
  const showReconnecting = $derived(hadLive && live !== "live");

  $effect(() => {
    if (live === "live") hadLive = true;
  });

  onMount(() => {
    void hydrate();
    es = subscribe({
      onProgress: (p) => {
        recordTick(p);
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
      onStatus: (s) => (live = s),
      onReconnect: () => void hydrate(),
    });
  });

  onDestroy(() => es?.close());

  function togglePro() {
    setProMode(!app.proMode);
  }
</script>

<div
  class="mx-auto flex min-h-screen max-w-6xl flex-col ps-[max(1rem,env(safe-area-inset-left))] pe-[max(1rem,env(safe-area-inset-right))] sm:ps-[max(1.5rem,env(safe-area-inset-left))] sm:pe-[max(1.5rem,env(safe-area-inset-right))]"
>
  <header class="flex flex-wrap items-center justify-between gap-x-4 gap-y-3 py-5">
    <div class="flex items-center gap-3">
      <div
        class="grid size-10 place-items-center rounded-full"
        style="background: var(--accent); box-shadow: 0 0 12px var(--bloom-a);"
      >
        <Radar class="size-5" color="var(--accent-ink)" strokeWidth={2.4} />
      </div>
      <div>
        <h1 class="text-lg font-semibold" style="letter-spacing:-0.03em">
          CF-Scanner
        </h1>
        <p class="mono hidden text-[11px] sm:block" style="color: var(--ink-muted)">
          {t("app.tagline")}
        </p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <span
        class="version-badge mono"
        title={live === "live" ? t("app.live.liveTitle") : live === "offline" ? t("app.live.offlineTitle") : t("app.live.connectingTitle")}
      >
        <span
          class="size-1.5 rounded-full"
          style="background: {live === 'live'
            ? 'var(--good)'
            : live === 'offline'
              ? 'var(--bad)'
              : 'var(--ink-muted)'}"
        ></span>
        {liveLabel} · v{version || "…"}
      </span>
      <button
        type="button"
        class="btn btn-secondary btn-sm"
        onclick={toggleLocale}
        title="فارسی / English"
        aria-label="Switch language"
      >
        <Languages class="size-4" />
        {currentLocale() === "fa" ? "EN" : "فا"}
      </button>
      <button
        type="button"
        class="btn btn-secondary"
        class:btn-state-on={app.proMode}
        onclick={togglePro}
        aria-pressed={app.proMode}
        title={t("mode.pro.title")}
      >
        <SlidersHorizontal class="size-4" />
        {t("mode.pro")}
      </button>
    </div>
  </header>

  {#if showReconnecting}
    <div
      class="fade-in mb-2 rounded-md border px-3 py-2 text-xs"
      style="border-color: oklch(100% 0 0 / 8%); background: var(--paper-2); color: var(--ink-muted)"
      role="status"
      aria-live="polite"
    >
      {live === "offline" ? t("live.offline") : t("live.connecting")} · {live === "offline"
        ? t("app.live.offlineTitle")
        : t("app.live.connectingTitle")}
    </div>
  {/if}

  <main class="flex flex-1 flex-col gap-6 pb-10">
    {#if app.error}
      <div
        class="fade-in card flex items-start gap-2 px-4 py-3 text-sm"
        style="background: oklch(22% 0.06 25 / 40%); color: var(--bad);"
        role="alert"
      >
        <span class="flex-1">{app.error}</span>
        <button class="btn btn-ghost btn-sm" onclick={() => (app.error = null)}>
          {t("error.dismiss")}
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
    class="border-t pt-4 pb-[max(1rem,env(safe-area-inset-bottom))] text-xs"
    style="border-color: oklch(100% 0 0 / 6%); color: var(--ink-muted);"
  >
    <span>{t("app.footer.geo").split("db-ip.com")[0]}<a
        class="underline decoration-dotted"
        style="color: var(--accent)"
        href="https://db-ip.com"
        rel="noopener noreferrer"
        target="_blank">db-ip.com</a> (CC BY 4.0)
    </span>
  </footer>
</div>
