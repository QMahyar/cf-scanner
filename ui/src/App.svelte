<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { Languages, SlidersHorizontal } from "@lucide/svelte";
  import { api, subscribe, type LiveStatus } from "./lib/api";
  import { currentLocale, t, toggleLocale } from "./lib/i18n.svelte";
  import { applyResult, recordTick, setProMode, setResults, ui } from "./lib/store.svelte";
  import { reveal } from "./lib/reveal";
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
      app.statusHasCandidates = s.has_candidates ?? false;
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
  let bannerDismissed = $state(false);
  const showReconnecting = $derived(hadLive && live !== "live" && !bannerDismissed);

  $effect(() => {
    if (live === "live") {
      hadLive = true;
      bannerDismissed = false;
    }
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
        api.results().then((r) => setResults(r.results)).catch(() => {});
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

<a href="#main" class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-[var(--paper)] focus:px-3 focus:py-1 focus:text-sm">Skip to content</a>
<div
  class="mx-auto flex min-h-dvh max-w-6xl flex-col ps-[max(1rem,env(safe-area-inset-left))] pe-[max(1rem,env(safe-area-inset-right))] sm:ps-[max(1.5rem,env(safe-area-inset-left))] sm:pe-[max(1.5rem,env(safe-area-inset-right))]"
>
  <header
    class="sticky top-0 z-30 border-b-[3px] border-[var(--ink)] bg-[var(--paper)]"
    style="border-bottom: 3px solid var(--ink)"
  >
    <div class="flex w-full flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 sm:px-8">
      <div class="min-w-0 shrink-0">
        <h1 class="display text-xl font-semibold leading-tight" style="letter-spacing:-0.02em">
          CF-Scanner
        </h1>
        <p class="mono hidden text-[11px] sm:block" style="color: var(--ink-3); letter-spacing:0.03em">
          {t("app.tagline")}
        </p>
      </div>
      <div class="flex min-w-0 flex-wrap items-center justify-end gap-2">
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
                : 'var(--ink-3)'}"
          ></span>
          {liveLabel}
        </span>
        <span class="mono ms-1 text-[11px]" style="color: var(--ink-3)" aria-hidden="false">v{version || "…"}</span>
        <button
          type="button"
          class="btn btn-secondary btn-sm"
          onclick={toggleLocale}
          title="فارسی / English"
          aria-label={t("app.switchLanguage")}
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
    </div>
  </header>

  {#if showReconnecting}
    <div
      class="fade-in mb-2 flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs"
      style="border-color: var(--rule); background: var(--wash); color: var(--ink-muted)"
      role="status"
      aria-live="polite"
    >
      <span>{live === "offline" ? t("live.offline") : t("live.connecting")} · {live === "offline"
        ? t("app.live.offlineTitle")
        : t("app.live.connectingTitle")}</span>
      <button class="btn btn-ghost btn-sm shrink-0" onclick={() => (bannerDismissed = true)} aria-label={t("error.dismiss")}>×</button>
    </div>
  {/if}

  <main id="main" class="flex flex-1 flex-col gap-8 pb-16">
    {#if app.error}
      <div
        class="fade-in shell-sm flex items-start gap-2 px-4 py-3 text-sm"
        style="background: var(--verm-soft); color: var(--bad);"
        role="alert"
      >
        <span class="flex-1">{app.error}</span>
        <button class="btn btn-ghost btn-sm" onclick={() => (app.error = null)}>
          {t("error.dismiss")}
        </button>
      </div>
    {/if}

    {#if app.proMode}
      <div use:reveal>
        <ProPanel />
      </div>
    {:else}
      <div use:reveal>
        <SimpleStart />
      </div>
    {/if}
  </main>

  <footer
    class="border-t-[3px] border-[var(--ink)] pt-5 pb-[max(1.25rem,env(safe-area-inset-bottom))] text-xs"
    style="color: var(--ink-3);"
  >
    <span>{t("app.footer.geoPrefix")} <a
        class="underline"
        style="color: var(--ink-muted); text-underline-offset: 3px; text-decoration-color: var(--rule-strong)"
        href="https://db-ip.com"
        rel="noopener noreferrer"
        target="_blank">db-ip.com</a> {t("app.footer.geoSuffix")}
    </span>
  </footer>
</div>
