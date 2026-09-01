<script lang="ts">
  import { onDestroy } from "svelte";
  import { Check, Copy, Download, Gauge, Play, Radar, Share2, Square } from "@lucide/svelte";
  import {
    exportText,
    filteredEndpoints,
    simpleConfig,
    startScan,
    stopScan,
    ui,
    type ExportHow,
  } from "../store.svelte";
  import { ResultsView } from "../resultsView.svelte";
  import { t } from "../i18n.svelte";
  import { humanizeSeconds } from "../validators";
  import { toast } from "../toast.svelte";
  import type { Mode, Verdict } from "../types";

  const app = ui();
  let scanMode = $state<Mode>("Cdn");
  let starting = $state(false);
  let findUpTo = $state(20);
  let testUpTo = $state(800);
  let copiedAll = $state<ExportHow | null>(null);
  let tick = $state(0);

  // Throttled screen-reader announcement: update at most every 10 s so the
  // aria-live region doesn't chatter on every tick. Side-effect moved to
  // $effect — $derived must stay pure.
  let lastAnnounce = 0;
  let announced = $state("");
  const progressAnnounce = $derived(announced);
  $effect(() => {
    void tick;
    void app.progress.found;
    void app.progress.scanned;
    const now = Date.now();
    if (announced !== "" && now - lastAnnounce < 10_000) return;
    lastAnnounce = now;
    announced = t("simple.progressAnnounce", {
      working: app.progress.found,
      checked: app.progress.scanned,
    });
  });

  // Preset sample sizes; CDN samples candidates on 443, WARP sweeps
  // endpoints across the official port set. Custom reveals one field.
  type SizeKey = "quick" | "normal" | "big" | "custom";
  const SIZES: Record<SizeKey, { cdn: number; warp: number }> = {
    quick: { cdn: 4_000, warp: 2_000 },
    normal: { cdn: 12_000, warp: 3_500 },
    big: { cdn: 50_000, warp: 5_000 },
    custom: { cdn: 0, warp: 0 },
  };
  let sizeChoice = $state<SizeKey>("normal");
  const kFmt = (n: number) => (n >= 1000 ? `${Math.round(n / 1000)}K` : `${n}`);
  const effectiveTest = $derived(
    sizeChoice === "custom"
      ? testUpTo
      : scanMode === "Warp"
        ? SIZES[sizeChoice].warp
        : SIZES[sizeChoice].cdn,
  );

  $effect(() => {
    if (!app.running) return;
    const id = setInterval(() => tick++, 1000);
    return () => clearInterval(id);
  });

  async function start() {
    starting = true;
    await startScan(simpleConfig(findUpTo, scanMode, effectiveTest));
    starting = false;
  }

  /** Simple mode's "best" bar, unchanged: passed the tunnel test or never
   * had one to run. Lives here (not resultsView.ts) because T4 may not edit
   * that file; ResultsView still owns sort/latency-filter/cap semantics. */
  const passOrUntested = (r: Verdict) => (r.phase2 ? r.phase2.passed : true);

  const unfilteredBest = $derived(app.results.filter(passOrUntested));
  const bestView = new ResultsView(() => unfilteredBest, "candidates");
  onDestroy(() => bestView.destroy());

  const best = $derived(bestView.rows);

  const SHOWN = 9;
  const hiddenCount = $derived(Math.max(0, best.length - SHOWN));

  /** Rate/ETA recomputed on every progress tick — good enough for a hint. */
  const pace = $derived.by(() => {
    void tick;
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
    const lines = filteredEndpoints(unfilteredBest, bestView.maxLatency);
    copiedAll = await exportText(lines, "cf-scanner-endpoints.txt");
    toast(copiedAll === "clipboard"
      ? t("results.copied")
      : copiedAll === "share"
        ? t("results.shared")
        : t("results.saved"));
    setTimeout(() => (copiedAll = null), 1600);
  }

  async function copyOne(r: Verdict) {
    try {
      await navigator.clipboard.writeText(`${r.ip}:${r.port}`);
      toast(t("results.copied"));
    } catch {
      // Clipboard API can fail (e.g. insecure context); the bulk export path
      // has a download fallback, but per-card copy has no fallback.
      toast(t("simple.copyFailed"), "err");
    }
  }
</script>

<section class="shell fade-in">
  <div class="core px-6 py-8 sm:px-8 sm:py-10">
    <div class="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
      <div class="min-w-0 flex-1 lg:min-w-[320px]">
        <h1 class="view-title" style="margin-block: 0 12px">
          {scanMode === "Warp" ? t("simple.heading.warp") : t("simple.heading.cdn")}
        </h1>
        <p class="max-w-lg text-sm leading-relaxed" style="color: var(--text-faint)">
          {t("simple.intro")}
        </p>
        <div class="mt-4 flex flex-wrap items-center gap-2" role="group" aria-label={t("simple.target")}>
          <div class="seg" role="group" aria-label={t("simple.target")}>
            <button
              type="button"
              role="radio"
              aria-checked={scanMode === "Cdn"}
              onclick={() => (scanMode = "Cdn")}
            >
              CDN
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={scanMode === "Warp"}
              onclick={() => (scanMode = "Warp")}
            >
              WARP
            </button>
          </div>
        </div>
        <div
          class="mt-3 flex flex-wrap items-center gap-2"
          role="group"
          aria-label={t("simple.sizeGroup")}
        >
          {#each Object.entries(SIZES) as [key, amounts] (key)}
            {@const sKey = key as SizeKey}
            <button
              type="button"
              class="pill"
              aria-pressed={sizeChoice === sKey}
              title={sKey === "custom"
                ? undefined
                : sKey === "quick"
                  ? t("simple.size.quickHint")
                  : sKey === "normal"
                    ? t("simple.size.normalHint")
                    : t("simple.size.bigHint")}
              onclick={() => (sizeChoice = sKey)}
            >
              {t(`simple.size.${sKey}`)}
              {#if sKey !== "custom"}
                <span class="mono" style="font-size: 10px; color: var(--text-dim)">
                  ~{kFmt(scanMode === "Warp" ? amounts.warp : amounts.cdn)}
                </span>
              {/if}
            </button>
          {/each}
          {#if sizeChoice === "custom"}
            <input
              class="field mono field-num"
              type="number"
              min={scanMode === "Warp" ? 100 : 100}
              max={scanMode === "Warp" ? 5000 : 100000}
              step={scanMode === "Warp" ? 50 : 500}
              bind:value={testUpTo}
              onchange={() => {
                const cap = scanMode === "Warp" ? 5000 : 100_000;
                testUpTo = Math.min(cap, Math.max(100, Math.trunc(Number(testUpTo)) || 800));
              }}
              aria-label={t("simple.testUpTo")}
            />
            <span class="mono" style="font-size: 10px; color: var(--text-dim)">
              {scanMode === "Warp"
                ? t("simple.size.endpointsShort")
                : t("simple.size.candidatesShort")}
            </span>
          {/if}
        </div>
        {#if scanMode === "Warp" && testUpTo >= 5000}
          <p class="field__hint mt-1">{t("simple.warpCapHint")}</p>
        {/if}
      </div>
    {#if app.running}
      <button class="btn btn-secondary btn-lg" onclick={stopScan}>
        <Square class="size-5" />
        {t("simple.stop")}
      </button>
    {:else}
      <div class="flex w-full flex-col gap-2 sm:w-auto sm:items-end">
        <div class="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:gap-x-4 sm:gap-y-2">
          <label
            class="flex items-center gap-2 text-xs whitespace-nowrap"
            style="color: var(--text-dim)"
          >
            {t("simple.stopAfter")}
            <input
              class="field mono field-num"
              type="number"
              min="5"
              max="100"
              step="1"
              bind:value={findUpTo}
              onchange={() =>
                (findUpTo = Math.min(
                  100,
                  Math.max(5, Math.trunc(Number(findUpTo)) || 20),
                ))}
            />
          </label>
          <button
            class="btn btn-primary btn-lg group"
            onclick={start}
            disabled={starting}
            data-state={starting ? "loading" : undefined}
          >
            <span class="icon-chip">
              <Play class="size-4" />
            </span>
            {starting
              ? t("simple.starting")
              : scanMode === "Warp"
                ? t("simple.start.warp")
                : t("simple.start.cdn")}
          </button>
        </div>
        <span class="mono max-w-prose text-xs leading-snug" style="color: var(--text-ghost)">
          {t("simple.finishHint")} · {t("simple.overshootHint")}
        </span>
      </div>
    {/if}
  </div>

  {#if app.running || app.summary}
    {@const pct =
      app.progress.total
        ? Math.min(100, Math.round((app.progress.scanned / app.progress.total) * 100))
        : null}
    <div class="fade-in mt-8">
      {#if finishedIdle && app.summary}
        <div class="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
          <p class="text-sm font-semibold">
            {app.summary.cancelled
              ? t("done.cancelled")
              : t("done.complete", { n: app.summary.found })}
          </p>
          <span class="mono text-xs" style="color: var(--text-dim)">
            {t("done.in", { s: (app.summary.duration_ms / 1000).toFixed(1) })}
          </span>
        </div>
      {:else}
        <div class="flex flex-wrap items-baseline justify-between gap-2 text-sm">
          <span class="flex flex-wrap items-center gap-2">
            <span class="stat-chip">
              <span class="dot dot-cyan"></span>
              <span class="mono font-semibold" style="color: var(--cyan)">
                {app.progress.found}</span>
              {t("progress.working")}
            </span>
            <span class="stat-chip">
              <span class="dot" style="background: var(--text-ghost)"></span>
              {app.progress.scanned}
              {scanMode === "Warp" ? t("progress.endpointsChecked") : t("progress.checked")}{pct !== null
                ? ` · ${pct}%`
                : ""}
            </span>
          </span>
          {#if pace}
            <span class="mono text-xs" style="color: var(--text-dim)">
              ≈{pace.rate}/s{pace.eta !== null ? ` · ~${humanizeSeconds(pace.eta)}` : ""}
            </span>
          {/if}
        </div>
      {/if}
      <div class="progress mt-2">
        <i style="width: {pct ?? 33}%"></i>
      </div>
      {#if app.running}
        <p class="field__hint mt-2">
          {t("simple.reassure")}
        </p>
      {/if}
    </div>
  {/if}
  {#if progressAnnounce}
    <span role="status" class="sr-only">{progressAnnounce}</span>
  {/if}
  </div>
</section>

{#if !app.running && app.summary === null && best.length === 0}
  <section class="card fade-in" aria-label={t("simple.howtoAria")} style="padding: 12px 16px">
    <div class="flex flex-wrap items-center justify-center gap-x-3 gap-y-2">
      <span class="flex items-center gap-1.5 text-xs whitespace-nowrap" style="color: var(--text-dim)">
        <Play class="size-3.5" />
        {t("howto.scan")}
      </span>
      <span aria-hidden="true" class="h-0 w-6 border-t border-dashed sm:w-10" style="border-color: var(--border)"></span>
      <span class="flex items-center gap-1.5 text-xs whitespace-nowrap" style="color: var(--text-dim)">
        <Gauge class="size-3.5" />
        {t("howto.rank")}
      </span>
      <span aria-hidden="true" class="h-0 w-6 border-t border-dashed sm:w-10" style="border-color: var(--border)"></span>
      <span class="flex items-center gap-1.5 text-xs whitespace-nowrap" style="color: var(--text-dim)">
        <Copy class="size-3.5" />
        {t("howto.copy")}
      </span>
    </div>
  </section>
{/if}

{#if finishedIdle && app.results.length === 0}
  <section class="empty-card fade-in" aria-label={t("simple.emptyGuidanceAria")}>
    <div class="empty-icon"><Radar class="size-6" /></div>
    <h3 class="empty-title">{t("empty.title")}</h3>
    <p class="empty-msg">
      {t("empty.body")}
    </p>
  </section>
{/if}

{#if best.length > 0}
  <section class="fade-in flex flex-col gap-3" aria-label={t("results.heading")}>
    <div class="flex flex-wrap items-end justify-between gap-2 px-1">
      <div class="min-w-0">
        <h2 class="card__title text-base">{t("results.heading")}</h2>
        <p class="field__hint mt-0.5">
          {t("results.sub")}
        </p>
      </div>
      <button
        class="pill shrink-0"
        class:pill-on={copiedAll !== null}
        title={t("table.copyAllTitle")}
        onclick={copyAll}
        aria-live="polite"
      >
        {#if copiedAll !== null}
          <Check class="size-3.5" />
          {copiedAll === "clipboard"
            ? t("results.copied")
            : copiedAll === "share"
              ? t("results.shared")
              : t("results.saved")}
        {:else}
          <Copy class="size-3.5" />
          {t("results.copyAll")}
        {/if}
      </button>
      <span role="status" aria-live="polite" class="sr-only">{copiedAll !== null ? (copiedAll === "clipboard" ? t("results.copied") : copiedAll === "share" ? t("results.shared") : t("results.saved")) : ""}</span>
    </div>
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {#each best.slice(0, SHOWN) as r, i (r.ip + ":" + r.port)}
        <article
          class="shell-sm fade-in flex items-center justify-between gap-3 px-4 py-3"
          style="animation-delay: {Math.min(i, 8) * 45}ms; transition: border-color .2s var(--ease), box-shadow .2s var(--ease)"
        >
          <div class="min-w-0">
            <p class="mono truncate text-sm font-semibold" style="color: var(--cyan-pale)"><span dir="ltr">{r.ip}:{r.port}</span></p>
            <p class="mono mt-0.5 text-xs" style="color: var(--text-ghost)">
              <span dir="ltr">{r.latency_ms}ms</span>{r.country ? ` — ${r.country}` : ""}
              {#if i === 0}
                <span class="chip-status ok ms-1.5 align-middle">{t("card.fastest")}</span>
              {/if}
            </p>
          </div>
          <button
            class="btn btn-ghost btn-sm shrink-0"
            title={t("card.copyTitle")}
            aria-label={t("card.copyTitle")}
            onclick={() => copyOne(r)}
          >
            <Copy class="size-4" aria-hidden="true" />
          </button>
        </article>
      {/each}
    </div>
    {#if hiddenCount > 0 || copiedAll === "download"}
      <div class="flex flex-wrap items-center justify-between gap-2 px-1">
        <p class="mono text-[11px]" style="color: var(--text-dim)">
          {hiddenCount > 0
            ? t("results.showing", { shown: Math.min(SHOWN, best.length), total: best.length })
            : ""}
        </p>
        {#if copiedAll === "download"}
          <span class="pill pill-on fade-in">
            <Download class="size-3.5" /> cf-scanner-endpoints.txt
          </span>
        {:else if copiedAll === "share"}
          <span class="pill pill-on fade-in">
            <Share2 class="size-3.5" />
          </span>
        {/if}
      </div>
    {/if}
  </section>
{/if}

<p class="field__hint px-1">
  {t("pro.hint")}
</p>
