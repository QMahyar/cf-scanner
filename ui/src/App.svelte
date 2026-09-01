<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { Moon, Sun } from "@lucide/svelte";
  import { api, subscribe, type LiveStatus } from "./lib/api";
  import { currentLocale, t, toggleLocale } from "./lib/i18n.svelte";
  import { applyResult, recordTick, setProMode, setResults, ui } from "./lib/store.svelte";
  import { reveal } from "./lib/reveal";
  import {
    ACCENTS,
    accent,
    initTheme,
    setAccent,
    theme,
    toggleTheme,
  } from "./lib/theme.svelte";
  import { dismissToast, toasts } from "./lib/toast.svelte";
  import SimpleStart from "./lib/components/SimpleStart.svelte";
  import ProPanel from "./lib/components/ProPanel.svelte";

  initTheme();

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
  const liveColor = $derived(
    live === "live" ? "var(--success)" : live === "offline" ? "var(--danger)" : "var(--text-ghost)",
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

  function setMode(pro: boolean) {
    setProMode(pro);
  }

  const toastList = $derived(toasts());
  const themeNow = $derived(theme());
  const accentNow = $derived(accent());
</script>

<a
  href="#main"
  class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-[var(--bg-raised)] focus:px-3 focus:py-1 focus:text-sm"
>{t("app.tagline")}</a>
<div class="texture-wrap" aria-hidden="true">
  <div class="dotgrid"></div>
  <div class="noise"></div>
  <div class="blob blob-a"></div>
  <div class="blob blob-b"></div>
</div>

<header class="topbar">
  <div class="brand">
    <span class="logo-tile" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7" /><path d="m15.5 15.5 5 5" /></svg>
    </span>
    CF-Scanner
  </div>
  <div class="tabs" role="tablist" aria-label={t("mode.pro.title")}>
    <button
      type="button"
      class="tab"
      role="tab"
      aria-selected={!app.proMode}
      onclick={() => setMode(false)}
    >
      {t("mode.simple")}
    </button>
    <button
      type="button"
      class="tab"
      role="tab"
      aria-selected={app.proMode}
      onclick={() => setMode(true)}
      title={t("mode.pro.title")}
    >
      {t("mode.pro")}
    </button>
  </div>
  <div class="topbar__end">
    <span
      class="stat-chip"
      title={live === "live" ? t("app.live.liveTitle") : live === "offline" ? t("app.live.offlineTitle") : t("app.live.connectingTitle")}
    >
      <span class="dot" style="background: {liveColor}"></span>
      {liveLabel}
    </span>
    <span class="stat-chip" aria-hidden="false">v{version || "…"}</span>
    <div class="swatches" role="group" aria-label={t("app.accent")}>
      {#each ACCENTS as a (a.id)}
        <button
          type="button"
          class="swatch swatch--{a.id}"
          data-action="accent"
          data-accent={a.id}
          aria-pressed={accentNow === a.id}
          aria-label={a.label}
          title={a.label}
          onclick={() => setAccent(a.id)}
        ></button>
      {/each}
    </div>
    <div class="seg" role="group" aria-label={t("app.switchLanguage")}>
      <button
        type="button"
        role="radio"
        aria-checked={currentLocale() === "en"}
        onclick={() => {
          if (currentLocale() !== "en") toggleLocale();
        }}
      >
        EN
      </button>
      <button
        type="button"
        role="radio"
        aria-checked={currentLocale() === "fa"}
        onclick={() => {
          if (currentLocale() !== "fa") toggleLocale();
        }}
      >
        فا
      </button>
    </div>
    <button
      type="button"
      class="btn btn-ghost"
      style="width:36px;height:36px;padding:0;border-radius:0.7rem"
      onclick={toggleTheme}
      aria-label={t("app.themeToggle")}
      title={t("app.themeToggle")}
    >
      {#if themeNow === "light"}
        <Moon class="size-4" />
      {:else}
        <Sun class="size-4" />
      {/if}
    </button>
  </div>
</header>

<main id="main" class="flex flex-1 flex-col gap-4">
  {#if showReconnecting}
    <div
      class="fade-in flex items-center justify-between gap-2 rounded-xl border px-3 py-2 text-xs"
      style="border-color: rgba(251, 191, 36, 0.25); background: var(--warning-bg); color: var(--warning)"
      role="status"
      aria-live="polite"
    >
      <span>{live === "offline" ? t("live.offline") : t("live.connecting")} · {live === "offline"
        ? t("app.live.offlineTitle")
        : t("app.live.connectingTitle")}</span>
      <button
        class="btn btn-ghost btn-sm shrink-0"
        style="color: inherit"
        onclick={() => (bannerDismissed = true)}
        aria-label={t("error.dismiss")}>×</button
      >
    </div>
  {/if}

  {#if app.error}
    <div
      class="fade-in card card--danger flex items-start gap-2 text-sm"
      style="padding: 12px 16px"
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
  class="relative z-[1] pb-[max(1.25rem,env(safe-area-inset-bottom))] pt-2 text-xs"
  style="color: var(--text-ghost); max-width: 1080px; margin-inline: auto; padding-inline: 16px"
>
  <span>{t("app.footer.geoPrefix")} <a
      class="underline"
      style="color: var(--text-dim); text-underline-offset: 3px; text-decoration-color: var(--border-strong)"
      href="https://db-ip.com"
      rel="noopener noreferrer"
      target="_blank">db-ip.com</a> {t("app.footer.geoSuffix")}
  </span>
</footer>

<div class="toasts" role="status" aria-live="polite">
  {#each toastList as entry (entry.id)}
    <div
      class="toast"
      class:toast--err={entry.kind === "err"}
      class:toast--out={entry.leaving}
      role={entry.kind === "err" ? "alert" : undefined}
    >
      <svg class="ticon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        {#if entry.kind === "err"}
          <path d="M18 6 6 18M6 6l12 12" />
        {:else}
          <path d="M20 6 9 17l-5-5" />
        {/if}
      </svg>
      <span class="toast__msg">{entry.msg}</span>
      <button
        type="button"
        class="toast__close"
        aria-label={t("error.dismiss")}
        onclick={() => dismissToast(entry.id)}
      >
        <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12" /></svg>
      </button>
      <i class="toast-bar" style="animation-duration: {entry.total}ms"></i>
    </div>
  {/each}
</div>
