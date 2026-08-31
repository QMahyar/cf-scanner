<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import Segmented from "./Segmented.svelte";
  import {
    Gauge,
    Play,
    ShieldCheck,
    Square,
  } from "@lucide/svelte";
  import {
    api,
    type XrayStatusPayload,
  } from "../api";
  import {
    errorText,
    hasCandidates,
    lowYieldWindow,
    startScan,
    stopScan,
    ui,
  } from "../store.svelte";
  import { ResultsView } from "../resultsView.svelte";
  import {
    buildConfig,
    defaultFormState,
    defaultSelectedPorts,
    FORM_PERSIST_KEY,
    formStateFromPersisted,
    persistedFormState,
    portCatalog,
    FormValidationError,
  } from "../formState";
  import CustomCidrsCard from "./CustomCidrsCard.svelte";
  import Phase2TunnelCard from "./Phase2TunnelCard.svelte";
  import WarpIdentityCard from "./WarpIdentityCard.svelte";
  import WarpRegistrationCard from "./WarpRegistrationCard.svelte";
  import {
    normalizeLines,
    parseCidr,
    parseEndpoint,
  } from "../validators";
  import { t, type MsgKey } from "../i18n.svelte";
  import type { CdnPreset, Mode } from "../types";
  import type { FieldIssue, FormField, FormState } from "../formState";
  import ResultsTable from "./ResultsTable.svelte";

  const app = ui();
  let starting = $state(false);
  let validationErrors = $state<FieldIssue[]>([]);
  let form = $state<FormState>(defaultFormState());

  /** Keys the user has edited — live inline validation only lights up these
   * so untouched fields stay quiet until a submit attempt. */
  let touched = $state<Partial<Record<FormField, boolean>>>({});
  /** Server 400/422 messages routed to identifiable fields; cleared per
   * field as soon as the user edits it again. */
  let serverFieldErrors = $state<Partial<Record<FormField, string>>>({});
  /** Flip after the localStorage restore attempt so the persist effect
   * never writes defaults over a saved form before hydration. */
  let hydrated = $state(false);

  let xray = $state<XrayStatusPayload | null>(null);
  let xrayBusy = $state(false);
  let xrayError = $state<string | null>(null);

  /** WARP endpoints file import (local to WARP section). */
  const WARP_RANGES_MAX_BYTES = 256 * 1024;
  let warpRangesFileInput = $state<HTMLInputElement | null>(null);
  let warpRangesNote = $state<{ ok: boolean; text: string } | null>(null);

  function importWarpRangesFile(
    e: Event & { currentTarget: EventTarget & HTMLInputElement },
  ) {
    const input = e.currentTarget;
    const file = input.files?.[0] ?? null;
    input.value = "";
    warpRangesNote = null;
    if (!file) return;
    if (file.size > WARP_RANGES_MAX_BYTES) {
      warpRangesNote = {
        ok: false,
        text: t("pro.warp.rangesSizeError", { name: file.name, kb: Math.ceil(file.size / 1024) }),
      };
      return;
    }
    void file.text().then((raw) => {
      const existing = form.warpEndpoints
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      const seen = new Set(existing);
      let imported = 0;
      let skipped = 0;
      for (const line of raw.split(/\r?\n/).map((s) => s.trim())) {
        if (!line || line.startsWith("#")) continue;
        let entry: string | null = null;
        const v = parseEndpoint(line);
        if (v.ok) entry = v.value;
        else if (parseCidr(line).ok) entry = line.split("/")[0];
        if (entry === null) {
          skipped += 1;
          continue;
        }
        if (!seen.has(entry)) {
          seen.add(entry);
          existing.push(entry);
          imported += 1;
        }
      }
      form.warpEndpoints = existing.join("\n");
      touched.warpEndpoints = true;
      delete serverFieldErrors.warpEndpoints;
      warpRangesNote = {
        ok: imported > 0,
        text: imported === 0 && skipped === 0 ? t("pro.warp.rangesEmpty", { name: file.name }) : skipped > 0 ? t("pro.warp.rangesImportedSkipped", { count: imported, s: imported === 1 ? "" : "s", skipped }) : t("pro.warp.rangesImported", { count: imported, s: imported === 1 ? "" : "s" }),
      };
    });
  }

  /** Skip-to-Phase-2 (plan T6): cancel the running phase-1 scan, then verify
   * its banked candidates immediately via phase2_only. preserveResults
   * freezes the current rows into frozenPhase1 instead of wiping them, so
   * the candidates list keeps its content while tunnel verdicts upsert over
   * the live rows. */
  let skipping = $state(false);

  const configsListed = $derived(
    form.configsText
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const canSkipToPhase2 = $derived(
    app.running &&
      !skipping &&
      app.phase2 === null &&
      form.mode === "Cdn" &&
      form.phase2On &&
      configsListed.length > 0,
  );
  const suggestSkip = $derived(canSkipToPhase2 && lowYieldWindow() === true);

  function waitForIdle(timeoutMs = 20_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    return new Promise((resolve) => {
      const poll = () => {
        if (!app.running) return resolve(true);
        if (Date.now() > deadline) return resolve(false);
        setTimeout(poll, 150);
      };
      poll();
    });
  }

  async function skipToPhase2() {
    const foundSoFar = app.progress.found;
    if (
      foundSoFar < 5 &&
      !confirm(t("pro.confirm.skipLow", { found: foundSoFar, s: foundSoFar === 1 ? "" : "s" }))
    )
      return;
    skipping = true;
    try {
      await api.cancel();
      if (!(await waitForIdle())) {
        app.error = t("pro.error.stopTimeout");
        return;
      }
      const cfg = buildConfig(form); // may throw FormValidationError
      cfg.phase2_only = true;
      validationErrors = [];
      await startScan(cfg, { preserveResults: true });
    } catch (e) {
      if (e instanceof FormValidationError) {
        validationErrors = e.errors;
        queueMicrotask(() => {
          const el = document.querySelector('[aria-invalid="true"]') as HTMLElement | null;
          el?.focus();
        });
      } else app.error = errorText(e);
    } finally {
      skipping = false;
    }
  }

  /** Verify banked while idle (wayfinder T4): same phase2_only path as
   * skip-to-phase-2 but with no cancel step — nothing is running. The form
   * is the config source so profile/persisted values apply unchanged. */
  let verifyingBanked = $state(false);
  const canVerifyBanked = $derived(
    !app.running &&
      !verifyingBanked &&
      form.mode === "Cdn" &&
      form.phase2On &&
      configsListed.length > 0 &&
      hasCandidates(),
  );

  const verifyBankedDisabledReason = $derived.by(() => {
    if (!form.phase2On) return t("pro.verify.reason.phase2Off");
    if (configsListed.length === 0) return t("pro.verify.reason.noConfigs");
    if (!hasCandidates()) return t("pro.verify.reason.noCandidates");
    return "";
  });

  async function verifyBanked() {
    verifyingBanked = true;
    try {
      const cfg = buildConfig(form); // may throw FormValidationError
      // phase2_only never dials phase-1 targets, but the wire contract still
      // demands at least one port — pin the CDN default rather than shipping
      // the scan form's whole port list.
      cfg.ports = [443];
      cfg.phase2_only = true;
      validationErrors = [];
      app.error = null;
      const outcome = await startScan(cfg, { preserveResults: true });
      if (!outcome.ok && outcome.rejected) {
        const routed = routeServerDetail(outcome.rejected.detail);
        if (Object.keys(routed).length > 0) {
          app.error = null; // routed to the fields; keep the banner quiet
          serverFieldErrors = { ...serverFieldErrors, ...routed };
        }
      }
    } catch (e) {
      if (e instanceof FormValidationError) {
        validationErrors = e.errors;
        queueMicrotask(() => {
          const el = document.querySelector('[aria-invalid="true"]') as HTMLElement | null;
          el?.focus();
        });
      } else app.error = errorText(e);
    }
    verifyingBanked = false;
  }

  // --- Two-list phase separation (wayfinder T4) ---
  // Read-side split over ONE store array, never duplicated: candidates shows
  // the frozen pre-verify snapshot when one exists (frozen rows all lack
  // phase2 — freeze only happens on phase2_only+preserveResults starts), so
  // it can never double-count rows that also appear as verified.
  const candidatesView = new ResultsView(
    () => app.frozenPhase1 ?? app.results,
    "candidates",
  );
  const verifiedView = new ResultsView(() => app.results, "verified");

  /** lg breakpoint mirror for JS-side card switching; CSS still owns layout
   * via grid-cols-2 so a missed event can only affect which cards render. */
  let wide = $state(false);
  $effect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    wide = mq.matches;
    const onChange = (e: MediaQueryListEvent) => (wide = e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  });

  /** Which list renders below lg; ignored at lg+ where both cards show. */
  let activeList = $state<"all" | "verified">("all");

  const showCandidatesCard = $derived(app.results.length > 0 || app.running);
  const showVerifiedCard = $derived(
    app.frozenPhase1 !== null || (form.mode === "Cdn" && form.phase2On),
  );

  let scanAdvancedOpen = $state(false);
  let warpAdvancedOpen = $state(false);
  /** Custom-ports field renders only on demand; a restored form that
      already carries custom ports reopens it automatically. */
  let customPortsOpen = $state(false);

  // A routed error on any collapsed knob pops the disclosure open so its
  // inline message is never hidden inside it.
  $effect(() => {
    if (fieldErrors.concurrency || fieldErrors.timeoutMs || fieldErrors.capText)
      scanAdvancedOpen = true;
  });
  $effect(() => {
    if (fieldErrors.warpProbes || fieldErrors.warpEndpoints) warpAdvancedOpen = true;
  });
  $effect(() => {
    if (form.customPortsText.trim()) customPortsOpen = true;
  });

  const allIssues = $derived.by(() => {
    try {
      buildConfig(form);
      return [] as FieldIssue[];
    } catch (e) {
      return e instanceof FormValidationError ? e.issues : [];
    }
  });

  // The click-time summary list is a snapshot; once the form validates
  // cleanly again (or the mode flip resets ports), retire it so a stale
  // "Fix these before starting" can't outlive its problems.
  $effect(() => {
    if (allIssues.length === 0 && validationErrors.length > 0) {
      validationErrors = [];
    }
  });

  const liveIssues = $derived(
    allIssues.filter((i) => i.field !== null && touched[i.field]),
  );

  /** field → first translated message: client issues for touched fields,
   * overlaid by server-routed errors (which are cleared on edit). */
  const fieldErrors = $derived.by(() => {
    const map: Partial<Record<FormField, string>> = {};
    for (const i of liveIssues)
      if (i.field !== null && map[i.field] === undefined) map[i.field] = t(i.key as MsgKey, i.params);
    return Object.assign(map, serverFieldErrors);
  });

  /** Server ConfigError strings → form fields, most-specific-first:
   * "invalid endpoint …: port is not a number" must hit warpEndpoints
   * before the generic port rule. Unmatched messages stay in the banner. */
  const SERVER_FIELD_MATCHERS: ReadonlyArray<readonly [RegExp, FormField]> = [
    [/wgconf|wireguard|amnezia/i, "wgconf"],
    [/probes_per_endpoint/i, "warpProbes"],
    [/snis?\b/i, "snis"],
    [/fragment|unknown variant/i, "fragment"],
    [/probe[._]?url/i, "probeUrl"],
    [/cidr/i, "customCidrs"],
    [/exclude/i, "exclude"],
    [/config/i, "configsText"],
    [/preset|target count|\bcount\b/i, "count"],
    [/endpoint/i, "warpEndpoints"],
    [/concurrency/i, "concurrency"],
    [/timeout/i, "timeoutMs"],
    [/\bcap\b/i, "capText"],
    [/stop\.found|\bstop\b/i, "stopFound"],
    [/\bports?\b/i, "customPortsText"],
  ];

  function routeServerDetail(detail: string): Partial<Record<FormField, string>> {
    const field = SERVER_FIELD_MATCHERS.find(([re]) => re.test(detail))?.[1];
    return field ? { [field]: detail } : {};
  }

  async function start() {
    starting = true;
    serverFieldErrors = {};
    try {
      const cfg = buildConfig(form);
      validationErrors = [];
      const outcome = await startScan(cfg);
      if (!outcome.ok && outcome.rejected) {
        const routed = routeServerDetail(outcome.rejected.detail);
        if (Object.keys(routed).length > 0) {
          app.error = null; // routed to the fields; keep the banner quiet
          serverFieldErrors = routed;
        }
      }
    } catch (e) {
      if (e instanceof FormValidationError) {
        validationErrors = e.errors;
        for (const i of e.issues) if (i.field !== null) touched[i.field] = true;
        queueMicrotask(() => {
          const el = document.querySelector('[aria-invalid="true"]') as HTMLElement | null;
          el?.focus();
        });
      } else {
        app.error = errorText(e);
      }
    }
    starting = false;
  }

  function markTouched(e: Event) {
    const name = (e.target as HTMLElement | null)?.getAttribute?.("name");
    if (!name || !(name in form)) return;
    touched[name as FormField] = true;
    delete serverFieldErrors[name as FormField];
  }

  function togglePort(p: number) {
    form.selectedPorts = form.selectedPorts.includes(p)
      ? form.selectedPorts.filter((x) => x !== p)
      : [...form.selectedPorts, p];
    touched.selectedPorts = true;
    delete serverFieldErrors.customPortsText;
  }

  /** Chip-row shortcuts: select the mode's whole catalog (primary +
   * extended, regardless of whether the details list is expanded) or wipe
   * the selection. Both mark touched so live validation reacts. */
  function selectAllPorts() {
    const catalog = portCatalog(form.mode);
    form.selectedPorts = [...catalog.primary, ...catalog.extended];
    touched.selectedPorts = true;
    delete serverFieldErrors.customPortsText;
  }

  function clearPorts() {
    form.selectedPorts = [];
    touched.selectedPorts = true;
    delete serverFieldErrors.customPortsText;
  }

  // Flipping CDN ↔ WARP swaps the chip catalog: re-default the selection so
  // stale cross-family ports can't linger silently. The guard keeps this
  // from firing on hydration or cross-mode profile loads (either would wipe
  // the restored selection back to defaults) — only a real user flip after
  // hydration resets, and a profile load suppresses it once.
  let lastMode = $state<Mode | null>(null);
  let suppressPortReset = $state(false);
  $effect(() => {
    void form.mode;
    if (!hydrated || lastMode === null || lastMode === form.mode) {
      lastMode = form.mode;
      return;
    }
    lastMode = form.mode;
    if (suppressPortReset) {
      suppressPortReset = false;
      return;
    }
    form.selectedPorts = defaultSelectedPorts(form.mode);
    form.customPortsText = "";
  });

  /** Blur-time cleanup for the line-based textareas: trims, drops blank and
   * duplicate lines — a pasted bulk list can never leave ghost empties. */
  function normalizeField(field: "customCidrs" | "exclude" | "warpEndpoints" | "configsText") {
    const next = normalizeLines(form[field]);
    if (next !== form[field]) {
      form[field] = next;
      touched[field] = true;
    }
  }

  function onFormSubmit(e: SubmitEvent) {
    e.preventDefault();
    void start();
  }

  function onFormKeydown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      void start();
    }
  }

  async function loadXray() {
    try {
      xray = await api.xrayStatus();
    } catch {
      /* status endpoint unreachable; chip stays hidden */
    }
  }

  async function downloadXray() {
    xrayBusy = true;
    xrayError = null;
    try {
      const res = await api.xrayDownload();
      if (!res.success) xrayError = res.error ?? t("pro.error.downloadFailed");
      await loadXray();
    } catch (e) {
      xrayError = errorText(e);
    }
    xrayBusy = false;
  }

  /** Persist every change (debounced ~300 ms); wgconf is excluded inside
   * persistedFormState so keys never reach disk. The snapshot awaiting its
   * debounce is also flushed on unmount, so toggling Pro off right after an
   * edit cannot lose the last keystrokes. */
  let pendingPersist: string | null = null;
  $effect(() => {
    if (!hydrated) return;
    const snapshot = persistedFormState(form);
    pendingPersist = snapshot;
    const t = setTimeout(() => {
      pendingPersist = null;
      try {
        localStorage.setItem(FORM_PERSIST_KEY, snapshot);
      } catch {
        /* storage unavailable (private mode/quota): persistence is best-effort */
      }
    }, 300);
    return () => clearTimeout(t);
  });

  onDestroy(() => {
    candidatesView.destroy();
    verifiedView.destroy();
    if (pendingPersist !== null) {
      try {
        localStorage.setItem(FORM_PERSIST_KEY, pendingPersist);
      } catch {
        /* storage unavailable */
      }
      pendingPersist = null;
    }
  });

  onMount(() => {
    try {
      const raw = localStorage.getItem(FORM_PERSIST_KEY);
      if (raw !== null) {
        const restored = formStateFromPersisted(raw);
        if (restored) form = restored;
      }
    } catch {
      /* storage unavailable */
    }
    hydrated = true;

    void loadXray();
  });
  // Throttled screen-reader announcement for phase-2 progress: update at
  // most every 10 s so the aria-live region doesn't chatter on every tick.
  let lastPhase2Announce = 0;
  let phase2Announced = "";
  const phase2Announce = $derived.by(() => {
    if (!app.phase2) { lastPhase2Announce = 0; return ""; }
    const now = Date.now();
    if (now - lastPhase2Announce < 10_000) return phase2Announced;
    lastPhase2Announce = now;
    phase2Announced = t("pro.tunnel.progress", { done: app.phase2.done, total: app.phase2.total });
    return phase2Announced;
  });
</script>

{#snippet fieldError(name: FormField)}
  {#if fieldErrors[name]}
    <span
      id="err-{name}"
      class="fade-in mt-1 block text-[11px] leading-snug"
      style="color: var(--bad)"
      role="alert">{fieldErrors[name]}</span
    >
  {/if}
{/snippet}

<div class="fade-in flex flex-col gap-8">
  <!-- scan form -->
  <section class="shell">
    <div class="core px-6 py-8 sm:px-8 sm:py-10">
    <!-- delegated touched/server-error tracking + Ctrl+Enter accelerator -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <form onsubmit={onFormSubmit} oninput={markTouched} onchange={markTouched} onkeydown={onFormKeydown}>
      <h2 class="flex items-center gap-2 text-sm font-semibold">
        <Gauge class="size-4" style="color: var(--accent)" /> {t("pro.section.scanConfig")}
      </h2>

      {#if validationErrors.length > 0}
        <div class="fade-in mt-3 text-xs" role="alert" style="color: var(--bad)">
          <p class="font-semibold">{t("pro.validation.fixBefore")}</p>
          <ul class="mt-1 list-inside list-disc space-y-0.5">
            {#each validationErrors as issue}
              <li>{t(issue.key as MsgKey, issue.params)}</li>
            {/each}
          </ul>
        </div>
      {/if}

      <div class="mt-4 grid-form">
        <div class="text-xs" style="color: var(--ink-muted)">
          <span class="mb-1 block">{t("pro.field.mode")}</span>
          <Segmented
            options={[{ value: "Cdn", label: t("pro.field.mode.cdn") }, { value: "Warp", label: t("pro.field.mode.warp") }]}
            value={form.mode}
            label={t("pro.field.mode")}
            onchange={(v) => (form.mode = v as typeof form.mode)}
          />
        </div>

        {#if form.mode === "Cdn"}
          <div class="text-xs span-all">
            <span class="mb-1 block" style="color: var(--ink-muted)">
              {t("pro.field.target")}
            </span>
            <!-- Amounts live in the labels; no separate hint line, no
                 custom-count checkbox — Custom reveals the field itself. -->
            <div
              class="flex flex-wrap items-center gap-1.5 rounded-2xl p-1.5"
              style="background: var(--paper-3)"
              role="group"
              aria-label={t("pro.field.target")}
            >
              {#each [["Quick", "~4K"], ["Normal", "~12K"], ["Full", "1.5M"]] as [preset, amount] (preset)}
                <button
                  type="button"
                  class="btn btn-sm btn-secondary"
                  class:btn-state-on={form.preset === (preset as CdnPreset) && !form.useCount}
                  aria-pressed={form.preset === (preset as CdnPreset) && !form.useCount}
                  onclick={() => {
                    form.preset = preset as CdnPreset;
                    form.useCount = false;
                  }}
                >
                  {preset}
                  <span class="mono text-[10px]" style="color: var(--ink-muted)">{amount}</span>
                </button>
              {/each}
              <button
                type="button"
                class="btn btn-sm btn-secondary"
                class:btn-state-on={form.useCount}
                aria-pressed={form.useCount}
                onclick={() => (form.useCount = true)}
              >
                {t("simple.size.custom")}
              </button>
              {#if form.useCount}
                <input
                  class="field mono field-num"
                  type="number"
                  min="1"
                  max="100000"
                  name="count"
                  aria-invalid={fieldErrors.count ? "true" : undefined}
                  aria-describedby={fieldErrors.count ? "err-count" : undefined}
                  bind:value={form.count}
                />
                {@render fieldError("count")}
              {/if}
            </div>
          </div>
        {/if}

        {#if form.mode === "Warp"}
          <label class="text-xs" style="color: var(--ink-muted)">
            {t("pro.field.candidates")}
            <input
              class="field mono mt-1"
              type="number"
              min="1"
              max="100000"
              name="count"
              aria-invalid={fieldErrors.count ? "true" : undefined}
              aria-describedby={fieldErrors.count ? "err-count" : undefined}
              bind:value={form.count}
            />
            {@render fieldError("count")}
          </label>
        {/if}

        <div class="text-xs span-all">
          <div class="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
            <span style="color: var(--ink-muted)">
              {t("pro.field.ports")}{#if form.mode === "Warp"}<span class="mono text-[10px]">{t("pro.field.ports.warpNote")}</span>{:else}<span class="mono text-[10px]">{t("pro.field.ports.cdnNote")}</span>
              {/if}
            </span>
            <span class="flex items-center gap-1">
              <button
                type="button"
                class="pill cursor-pointer"
                style="background: var(--paper-3); color: var(--ink-muted)"
                title={t("pro.field.ports.allTitle")}
                onclick={selectAllPorts}
              >{t("pro.field.ports.all")}</button>
              <button
                type="button"
                class="pill cursor-pointer"
                style="background: var(--paper-3); color: var(--ink-muted)"
                title={t("pro.field.ports.noneTitle")}
                onclick={clearPorts}
              >{t("pro.field.ports.none")}</button>
            </span>
          </div>
          <div class="mt-1.5 flex flex-wrap gap-1.5">
            {#each portCatalog(form.mode).primary as p (p)}
              <button
                type="button"
                class="pill"
                style={form.selectedPorts.includes(p)
                  ? "background: var(--accent); color: var(--accent-ink)"
                  : "background: var(--paper-3); color: var(--ink)"}
                aria-pressed={form.selectedPorts.includes(p)}
                onclick={() => togglePort(p)}
              >
                {p}
              </button>
            {/each}
            <button
              type="button"
              class="pill"
              style={customPortsOpen
                ? "background: var(--accent); color: var(--accent-ink)"
                : "background: var(--paper-3); color: var(--ink)"}
              aria-pressed={customPortsOpen}
              onclick={() => (customPortsOpen = !customPortsOpen)}
            >
              {t("simple.size.custom")}
            </button>
          </div>
          {#if customPortsOpen}
            <label class="mt-1.5 block text-xs" style="color: var(--ink-muted)">
              {t("pro.field.customPorts")}
              <input
                class="field mono mt-1"
                name="customPortsText"
                placeholder={t("pro.field.customPorts.placeholder")}
                aria-invalid={fieldErrors.customPortsText ? "true" : undefined}
                aria-describedby={fieldErrors.customPortsText ? "err-customPortsText" : undefined}
                bind:value={form.customPortsText}
              />
              {@render fieldError("customPortsText")}
            </label>
          {/if}
          {#if form.mode === "Warp" && portCatalog(form.mode).extended.length > 0}
            <details class="mt-2">
              <summary class="cursor-pointer" style="color: var(--ink-muted)">
                {t("pro.field.ports.extended", { n: portCatalog(form.mode).extended.length })}
              </summary>
              <div class="mt-1.5 flex flex-wrap gap-1.5">
                {#each portCatalog(form.mode).extended as p (p)}
                  <button
                    type="button"
                    class="pill"
                    style={form.selectedPorts.includes(p)
                      ? "background: var(--accent); color: var(--accent-ink)"
                      : "background: var(--paper-3); color: var(--ink)"}
                    aria-pressed={form.selectedPorts.includes(p)}
                    onclick={() => togglePort(p)}
                  >
                    {p}
                  </button>
                {/each}
              </div>
            </details>
          {/if}
          {@render fieldError("selectedPorts")}
        </div>

        <label
          class="text-xs"
          style="color: var(--ink-muted)"
        >
          {t("pro.field.stopAfter")}
          <input
            class="field mono mt-1 field-num"
            type="number"
            min="1"
            name="stopFound"
            aria-invalid={fieldErrors.stopFound ? "true" : undefined}
            aria-describedby={fieldErrors.stopFound ? "err-stopFound" : undefined}
            bind:value={form.stopFound}
          />
          {@render fieldError("stopFound")}
        </label>

        <!-- Tuning knobs live behind one disclosure: concurrency is how many
             probes run at once, the cap is a run-wide probe budget. Related
             but rarely touched together with target/ports selection. -->
        <div class="span-all">
          <details bind:open={scanAdvancedOpen}>
            <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
              {t("pro.section.scanAdvanced")}
            </summary>
            <div class="mt-3 grid gap-4 grid-form">
              <label class="text-xs" style="color: var(--ink-muted)">{t("pro.field.concurrency")}
                <input
                  class="field mono mt-1"
                  type="number"
                  min="1"
                  max="1000"
                  name="concurrency"
                  aria-invalid={fieldErrors.concurrency ? "true" : undefined}
                  aria-describedby={fieldErrors.concurrency ? "err-concurrency" : undefined}
                  bind:value={form.concurrency}
                />
                {@render fieldError("concurrency")}
              </label>

              <label class="text-xs" style="color: var(--ink-muted)">{t("pro.field.timeout")}
                <input
                  class="field mono mt-1"
                  type="number"
                  min="100"
                  max="30000"
                  name="timeoutMs"
                  aria-invalid={fieldErrors.timeoutMs ? "true" : undefined}
                  aria-describedby={fieldErrors.timeoutMs ? "err-timeoutMs" : undefined}
                  bind:value={form.timeoutMs}
                />
                {@render fieldError("timeoutMs")}
              </label>

              <label class="text-xs" style="color: var(--ink-muted)">
                {t("pro.field.hardCap")}
                <input
                  class="field mono mt-1"
                  type="text"
                  inputmode="numeric"
                  placeholder={t("pro.field.hardCap.placeholder")}
                  name="capText"
                  aria-invalid={fieldErrors.capText ? "true" : undefined}
                  aria-describedby={fieldErrors.capText ? "err-capText" : undefined}
                  bind:value={form.capText}
                />
                {@render fieldError("capText")}
              </label>

              {#if form.mode === "Cdn"}
                <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
                  <input type="checkbox" name="includeV6" bind:checked={form.includeV6} class="accent-[var(--accent)]" />
                  {t("pro.field.includeV6")}
                </label>
              {/if}
            </div>
          </details>
        </div>
      </div>

      <CustomCidrsCard
        form={form}
        fieldErrors={fieldErrors}
        touched={touched}
        serverFieldErrors={serverFieldErrors}
        onNormalize={normalizeField}
      />

      {#if form.mode === "Warp"}
        <div class="mt-4">
          <details bind:open={warpAdvancedOpen}>
            <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
              {t("pro.section.warpAdvanced")}
            </summary>
            <div class="mt-3 grid gap-4 grid-form">
              <label class="text-xs" style="color: var(--ink-muted)">
                {t("pro.warp.probes")}
                <input
                  class="field mono mt-1"
                  type="number"
                  min="1"
                  max="10"
                  name="warpProbes"
                  aria-invalid={fieldErrors.warpProbes ? "true" : undefined}
                  aria-describedby={fieldErrors.warpProbes ? "err-warpProbes" : undefined}
                  bind:value={form.warpProbes}
                />
                {@render fieldError("warpProbes")}
              </label>
              <label class="text-xs" style="color: var(--ink-muted)">
                {t("pro.warp.endpoints")}
                <textarea
                  class="field mono mt-1"
                  rows="2"
                  name="warpEndpoints"
                  aria-invalid={fieldErrors.warpEndpoints ? "true" : undefined}
                  aria-describedby={fieldErrors.warpEndpoints ? "err-warpEndpoints" : undefined}
                  bind:value={form.warpEndpoints}
                  onchange={() => normalizeField("warpEndpoints")}></textarea>
                {@render fieldError("warpEndpoints")}
              </label>
              <div class="flex flex-wrap items-center gap-1.5 span-all">
                <button
                  type="button"
                  class="pill cursor-pointer"
                  style="background: var(--paper-3); color: var(--ink)"
                  title={t("pro.warp.endpointsImportTitle")}
                  onclick={() => warpRangesFileInput?.click()}
                >{t("pro.field.importList")}</button>
                {#if warpRangesNote}
                  <span
                    class="fade-in mono text-[10px]"
                    role="status"
                    style={warpRangesNote.ok ? "color: var(--good)" : "color: var(--bad)"}
                  >
                    {warpRangesNote.text}
                  </span>
                {/if}
              </div>
              <input
                bind:this={warpRangesFileInput}
                class="hidden"
                type="file"
                accept=".txt,.csv,.list,.text,text/plain"
                onchange={importWarpRangesFile}
              />
            </div>
          </details>

          <div class="mt-3 grid gap-4 grid-form">
          <WarpIdentityCard
            bind:form
            fieldErrors={fieldErrors}
            bind:touched
            bind:serverFieldErrors
          />

          <WarpRegistrationCard bind:form />
          </div>
        </div>
      {:else}
        <!-- phase-2 toggle sits above the section it reveals -->
        <label class="mt-4 flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" name="phase2On" bind:checked={form.phase2On} class="accent-[var(--accent)]" />
          <ShieldCheck class="size-3.5" style="color: var(--accent)" />
          {t("pro.tunnel.toggle")}
        </label>
        {#if xray && !xray.found}
          <p class="mt-1 ps-6 text-[11px]" style="color: var(--ink-muted)">
            {t("pro.phase2.xrayHint")}
          </p>
        {/if}

        {#if form.phase2On}
          <Phase2TunnelCard
            form={form}
            fieldErrors={fieldErrors}
            onNormalize={normalizeField}
            xray={xray}
            xrayBusy={xrayBusy}
            xrayError={xrayError}
            onDownloadXray={downloadXray}
          />
        {/if}
      {/if}

      <div aria-hidden="true" class="h-[7.25rem] sm:h-20"></div>
      <!-- sticky actions: one canonical Start/Stop pair, visible even with
           phase-2/WARP textareas expanded -->
      <div
        class="sticky bottom-0 z-10 -ms-6 sm:-ms-8 -me-6 sm:-me-8 -mb-8 sm:-mb-10 mt-5 border-t-2 px-6 sm:px-8 pt-3"
        style="border-color: var(--ink); background: var(--paper); padding-bottom: max(1rem, env(safe-area-inset-bottom));"
      >
        <div class="flex flex-wrap items-stretch justify-end gap-2">
          {#if app.running}
            {#if canSkipToPhase2}
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                style={suggestSkip ? "box-shadow: 0 0 0 1px var(--ring)" : undefined}
                disabled={skipping}
                data-state={skipping ? "loading" : undefined}
                title={t("pro.action.skipTitle")}
                onclick={skipToPhase2}
              >
                <ShieldCheck class="size-3.5" />
                {app.progress.found > 0 ? t("pro.action.skipWithCount", { n: app.progress.found }) : t("pro.action.skip")}
              </button>
            {/if}
            <button type="button" class="btn btn-secondary" onclick={stopScan}>
              <Square class="size-3.5" /> {t("pro.action.stop")}
            </button>
          {:else}
            {#if form.mode === "Cdn" && hasCandidates()}
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                disabled={!canVerifyBanked}
                data-state={verifyingBanked ? "loading" : undefined}
                title={verifyBankedDisabledReason || t("pro.action.skipTitle")}
                aria-describedby="verify-banked-reason"
                onclick={verifyBanked}
              >
                <ShieldCheck class="size-3.5" />
                {t("pro.action.verifyBanked", { n: app.results.length })}
              </button>
              {#if verifyBankedDisabledReason}
                <span id="verify-banked-reason" class="sr-only">{verifyBankedDisabledReason}</span>
              {/if}
            {/if}
            <button
              type="submit"
              class="btn btn-primary group"
              disabled={starting}
              data-state={starting ? "loading" : undefined}
            >
              <span class="icon-chip !size-7">
                <Play class="size-3.5" />
              </span>
              {t("pro.action.start")}
            </button>
          {/if}
        </div>
        {#if !form.capText.trim() && form.concurrency >= 512}
          <p class="fade-in mt-2 text-[11px]" role="note" style="color: var(--ink-muted)">
            {t("pro.hint.noCap")}
          </p>
        {/if}
      </div>
    </form>
    </div>
  </section>

  {#if app.phase2}
    {#if phase2Announce}
      <span role="status" class="sr-only">{phase2Announce}</span>
    {/if}
    <p class="mono fade-in px-1 text-xs" style="color: var(--accent)">
      {t("pro.tunnel.progress", { done: app.phase2.done, total: app.phase2.total })}
    </p>
  {:else if app.running && suggestSkip}
    <p class="fade-in px-1 text-xs" role="status" style="color: var(--ink-muted)">
      {t("pro.hint.skipSuggestion", { found: app.progress.found })}
    </p>
  {/if}

  {#if showCandidatesCard || showVerifiedCard}
    {#if wide}
      <!-- lg+: bento — both lists side by side, each independently
           sortable/copyable via its own ResultsView. -->
      <div class="grid items-start gap-4 lg:grid-cols-2">
        {#if showCandidatesCard}
          <ResultsTable
            view={candidatesView}
            headingKey="results.candidatesHeading"
            emptyKind="candidates"
          />
        {/if}
        {#if showVerifiedCard}
          <ResultsTable
            view={verifiedView}
            headingKey="results.verifiedHeading"
            emptyKind="verified"
          />
        {/if}
      </div>
    {:else}
      {#if showCandidatesCard && showVerifiedCard}
        <div class="flex justify-center">
          <!-- Same segmented pattern as the simple-mode CDN/WARP switch. -->
          <div
            class="inline-flex items-center rounded-full p-1"
            style="background: var(--paper-3)"
            role="group"
            aria-label={t("results.heading")}
          >
            <button
              type="button"
              class="btn btn-sm btn-secondary"
              class:btn-state-on={activeList === "all"}
              aria-pressed={activeList === "all"}
              onclick={() => (activeList = "all")}
            >
              {t("results.candidatesHeading")}
            </button>
            <button
              type="button"
              class="btn btn-sm btn-secondary"
              class:btn-state-on={activeList === "verified"}
              aria-pressed={activeList === "verified"}
              onclick={() => (activeList = "verified")}
            >
              {t("results.verifiedHeading")}
            </button>
          </div>
        </div>
      {/if}
      {#if showCandidatesCard && (activeList === "all" || !showVerifiedCard)}
        <ResultsTable
          view={candidatesView}
          headingKey="results.candidatesHeading"
          emptyKind="candidates"
        />
      {:else if showVerifiedCard && (activeList === "verified" || !showCandidatesCard)}
        <ResultsTable
          view={verifiedView}
          headingKey="results.verifiedHeading"
          emptyKind="verified"
        />
      {/if}
    {/if}
  {/if}
</div>

<style>
  :global(html) {
    scroll-padding-bottom: 6rem;
  }
</style>
