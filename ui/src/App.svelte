<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { Moon, Sun } from "@lucide/svelte";
  import { api, subscribe, type LiveStatus } from "./lib/api";
  import type { ScanSummary } from "./lib/types";
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
        // The final refetch is async; if the user starts scan B before it
        // lands, its payload belongs to scan A and must not repopulate the
        // (already reset) results list. startedAt is re-stamped on every
        // start, so a changed value disqualifies the in-flight fetch.
        const gen = app.startedAt;
        app.summary = s;
        app.running = false;
        app.phase2 = null;
        api
          .results()
          .then((r) => {
            if (app.startedAt === gen) setResults(r.results);
          })
          .catch(() => {});
        notifyFinished(s);
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

  /** Desktop notification on scan completion — tab may be in the background
   * during a multi-minute scan. Opt-in via Notification permission (prompted
   * on first Start); silently no-ops when denied/unavailable. */
  function notifyFinished(s: ScanSummary) {
    try {
      if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
      const title = s.cancelled ? t("done.cancelled") : t("done.complete", { n: s.found });
      const n = new Notification("CF-Scanner", { body: `${title} · ${t("done.in", { s: (s.duration_ms / 1000).toFixed(1) })}` });
      n.onclick = () => {
        window.focus();
        n.close();
      };
    } catch {
      /* Notification unavailable */
    }
  }

  /** APG tabs keyboard pattern: arrows move selection + focus, Home/End jump. */
  function tabKeydown(e: KeyboardEvent) {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight" && e.key !== "Home" && e.key !== "End")
      return;
    e.preventDefault();
    const next = e.key === "Home" ? false : e.key === "End" ? true : !app.proMode;
    setMode(next);
    queueMicrotask(() =>
      document.getElementById(next ? "tab-pro" : "tab-simple")?.focus(),
    );
  }

  const toastOk = $derived(toasts().filter((x) => x.kind === "ok"));
  const toastErr = $derived(toasts().filter((x) => x.kind === "err"));
  const themeNow = $derived(theme());
  const accentNow = $derived(accent());
</script>

<a
  href="#main"
  class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:start-2 focus:z-50 focus:rounded focus:bg-[var(--bg-raised)] focus:px-3 focus:py-1 focus:text-sm"
>{t("app.skip")}</a>
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
  <div class="tabs" role="tablist" aria-label={t("mode.pro.title")} tabindex={-1} onkeydown={tabKeydown}>
    <button
      type="button"
      class="tab"
      role="tab"
      id="tab-simple"
      aria-controls="panel-simple"
      aria-selected={!app.proMode}
      tabindex={app.proMode ? -1 : 0}
      onclick={() => setMode(false)}
    >
      {t("mode.simple")}
    </button>
    <button
      type="button"
      class="tab"
      role="tab"
      id="tab-pro"
      aria-controls="panel-pro"
      aria-selected={app.proMode}
      tabindex={app.proMode ? 0 : -1}
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
    <div class="seg" role="radiogroup" aria-label={t("app.switchLanguage")}>
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
      class="btn btn-ghost btn-icon"
      onclick={toggleTheme}
      aria-label={t("app.themeToggle")}
      title={t("app.themeToggle")}
    >
      {#if themeNow === "light"}
        <Moon class="size-4" aria-hidden="true" />
      {:else}
        <Sun class="size-4" aria-hidden="true" />
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
    <div id="panel-pro" role="tabpanel" aria-labelledby="tab-pro" use:reveal>
      <ProPanel />
    </div>
  {:else}
    <div id="panel-simple" role="tabpanel" aria-labelledby="tab-simple" use:reveal>
      <SimpleStart />
    </div>
  {/if}
</main>

<footer
  class="relative z-[1] flex flex-wrap items-center gap-x-3 gap-y-1 pb-[max(1.25rem,env(safe-area-inset-bottom))] pt-2 text-xs"
  style="color: var(--text-ghost); max-width: 1080px; margin-inline: auto; padding-inline: 16px"
>
  <span>{t("app.footer.geoPrefix")} <a
      class="underline"
      style="color: var(--text-dim); text-underline-offset: 3px; text-decoration-color: var(--border-strong)"
      href="https://db-ip.com"
      rel="noopener noreferrer"
      target="_blank">db-ip.com</a> {t("app.footer.geoSuffix")}
  </span>
  {#if version}
    <a
      class="underline"
      style="color: var(--text-dim); text-underline-offset: 3px; text-decoration-color: var(--border-strong)"
      href="https://github.com/QMahyar/cf-scanner/releases/tag/v{version}"
      rel="noopener noreferrer"
      target="_blank">v{version}</a
    >
  {/if}
  <span>{t("app.footer.localOnly")}</span>
</footer>

<div class="toasts">
  {#each toastOk as entry (entry.id)}
    <div class="toast" class:toast--out={entry.leaving} role="status" aria-live="polite">
      <svg class="ticon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
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
<div class="toasts" style="top: calc(64px + env(safe-area-inset-top))">
  {#each toastErr as entry (entry.id)}
    <div class="toast toast--err" class:toast--out={entry.leaving} role="alert">
      <svg class="ticon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12" /></svg>
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
