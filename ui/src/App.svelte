<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { Languages, Radar, SlidersHorizontal } from "@lucide/svelte";
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
    class="sticky top-3 z-30 mx-auto mt-4 mb-8 flex w-full flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-[1.6rem] px-4 py-2.5 backdrop-blur-2xl sm:rounded-full sm:px-3"
    style="
      background: oklch(12% 0.01 260 / 72%);
      box-shadow:
        0 0 0 1px var(--hairline),
        0 18px 48px oklch(0% 0 0 / 40%);
    "
  >
    <div class="flex items-center gap-3">
      <div
        class="grid size-9 place-items-center rounded-full"
        style="background: var(--accent); box-shadow: 0 0 16px var(--orb-c);"
      >
        <Radar class="size-[1.15rem]" color="var(--accent-ink)" strokeWidth={1.8} />
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
        {liveLabel}
      </span>
      <span class="mono ms-1 text-[11px]" style="color: var(--ink-muted)" aria-hidden="false">v{version || "…"}</span>
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
  </header>

  {#if showReconnecting}
    <div
      class="fade-in mb-2 flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs"
      style="border-color: oklch(100% 0 0 / 8%); background: var(--paper-2); color: var(--ink-muted)"
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
    class="border-t pt-5 pb-[max(1.25rem,env(safe-area-inset-bottom))] text-xs"
    style="border-color: oklch(100% 0 0 / 6%); color: var(--ink-muted);"
  >
    <span>{t("app.footer.geoPrefix")} <a
        class="underline decoration-dotted"
        style="color: var(--accent)"
        href="https://db-ip.com"
        rel="noopener noreferrer"
        target="_blank">db-ip.com</a> {t("app.footer.geoSuffix")}
    </span>
  </footer>
</div>
