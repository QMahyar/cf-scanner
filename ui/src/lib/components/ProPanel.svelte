<script lang="ts">
  import { onMount } from "svelte";
  import Segmented from "./Segmented.svelte";
  import {
    Check,
    Copy,
    Download,
    FolderOpen,
    Gauge,
    Info,
    KeyRound,
    Play,
    Save,
    ShieldCheck,
    Square,
    Trash2,
  } from "@lucide/svelte";
  import {
    api,
    assertOk,
    type ProfilePayload,
    type RangesPayload,
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
    formStateFromConfig,
    formStateFromPersisted,
    persistedFormState,
    portCatalog,
    FormValidationError,
  } from "../formState";
  import WgNoiseEditor from "./WgNoiseEditor.svelte";
  import {
    MAX_CIDRS,
    normalizeLines,
    parseCidr,
    parseEndpoint,
  } from "../validators";
  import { t } from "../i18n.svelte";
  import type { CdnPreset, Mode } from "../types";
  import type { FieldIssue, FormField, FormState } from "../formState";
  import { EXCLUDE_WARP_INGRESS } from "../cidrPresets";
  import ResultsTable from "./ResultsTable.svelte";

  const app = ui();
  let starting = $state(false);
  let validationErrors = $state<string[]>([]);
  let form = $state<FormState>(defaultFormState());
  let rangesInfo = $state<RangesPayload | null>(null);

  /** Keys the user has edited — live inline validation only lights up these
   * so untouched fields stay quiet until a submit attempt. */
  let touched = $state<Partial<Record<FormField, boolean>>>({});
  /** Server 400/422 messages routed to identifiable fields; cleared per
   * field as soon as the user edits it again. */
  let serverFieldErrors = $state<Partial<Record<FormField, string>>>({});
  /** Flip after the localStorage restore attempt so the persist effect
   * never writes defaults over a saved form before hydration. */
  let hydrated = $state(false);

  let profiles = $state<ProfilePayload[]>([]);
  let selectedProfile = $state("");
  let profileNameInput = $state("");
  let profileBusy = $state(false);
  let profileStatus = $state<{ ok: boolean; text: string } | null>(null);

  let xray = $state<XrayStatusPayload | null>(null);
  let xrayBusy = $state(false);
  let xrayError = $state<string | null>(null);

  let licenseInput = $state("");
  let registering = $state(false);
  let registerError = $state<string | null>(null);
  let offerOverwrite = $state(false);
  let registeredConf = $state("");
  let confCopied = $state(false);

  /** wgconf file import: hidden picker + visible button. Files above this
   * ceiling are rejected before reading — a wgconf is a few KB; anything
   * bigger is the wrong file. */
  const WGCONF_MAX_BYTES = 64 * 1024;
  let wgconfFileInput = $state<HTMLInputElement | null>(null);
  let wgconfFileName = $state("");
  let wgconfFileError = $state<string | null>(null);

  async function loadWgconfFile(
    e: Event & { currentTarget: EventTarget & HTMLInputElement },
  ) {
    const input = e.currentTarget;
    const file = input.files?.[0] ?? null;
    // Reset so re-picking the same file fires change again.
    input.value = "";
    wgconfFileError = null;
    if (!file) return;
    if (file.size > WGCONF_MAX_BYTES) {
      wgconfFileError = t("pro.warp.wgconfSizeError", { name: file.name, kb: Math.ceil(file.size / 1024) });
      return;
    }
    try {
      form.wgconf = await file.text();
      form.verifyWarp = true;
      wgconfFileName = file.name;
      delete serverFieldErrors.wgconf;
    } catch {
      wgconfFileError = t("pro.warp.wgconfReadError", { name: file.name });
    }
  }

  /** Ranges import (plan T4 + addendum T9): one IP/CIDR per line, the
   * standard published list format. Lines are validated with the same
   * grammar the server enforces (validators.ts); bare IPv4s become /32s for
   * CDN CIDR import and plain endpoints for WARP; anything unparseable is
   * skipped and counted. Merges deduped into the caller-named textarea. */
  const RANGES_MAX_BYTES = 256 * 1024;
  let rangesFileInput = $state<HTMLInputElement | null>(null);
  let rangesTarget = $state<"customCidrs" | "warpEndpoints">("customCidrs");
  let rangesNote = $state<{ ok: boolean; text: string } | null>(null);

  function importRangesFile(
    e: Event & { currentTarget: EventTarget & HTMLInputElement },
  ) {
    const input = e.currentTarget;
    const file = input.files?.[0] ?? null;
    input.value = "";
    rangesNote = null;
    const field = rangesTarget;
    if (!file) return;
    if (file.size > RANGES_MAX_BYTES) {
      rangesNote = {
        ok: false,
        text: t("pro.warp.rangesSizeError", { name: file.name, kb: Math.ceil(file.size / 1024) }),
      };
      return;
    }
    void file.text().then((raw) => {
      const existing = form[field]
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      const seen = new Set(existing);
      const cap = field === "customCidrs" ? MAX_CIDRS : null;
      let imported = 0;
      let skipped = 0;
      for (const line of raw.split(/\r?\n/).map((s) => s.trim())) {
        if (!line || line.startsWith("#")) continue;
        let entry: string | null = null;
        if (field === "customCidrs") {
          // Published dual-stack lists carry v6 CIDRs too — accept both.
          const v = parseCidr(line);
          if (v.ok) entry = line;
          else if (parseEndpoint(line).ok) entry = `${line}/32`;
        } else {
          const v = parseEndpoint(line);
          if (v.ok) entry = v.value;
          else if (parseCidr(line).ok) entry = line.split("/")[0];
        }
        if (entry === null || (cap !== null && existing.length >= cap)) {
          skipped += 1;
          continue;
        }
        if (!seen.has(entry)) {
          seen.add(entry);
          existing.push(entry);
          imported += 1;
        }
      }
      form[field] = existing.join("\n");
      touched[field] = true;
      delete serverFieldErrors[field];
      rangesNote = {
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

  let tunnelAdvancedOpen = $state(false);
  let scanAdvancedOpen = $state(false);
  let warpAdvancedOpen = $state(false);
  /** Custom-ports field renders only on demand; a restored form that
      already carries custom ports reopens it automatically. */
  let customPortsOpen = $state(false);

  const DEFAULT_PROBE_URL = defaultFormState().probeUrl;

  /** Digest for the collapsed expert-knob summary: only deviations from
     defaults appear, as raw technical tokens (preset ids / hosts) that need
     no translation. */
  const tunnelAdvancedSummary = $derived.by(() => {
    const bits: string[] = [];
    if (form.fragment !== "off") bits.push(form.fragment);
    const sniList = form.snis.split(",").map((s) => s.trim()).filter(Boolean);
    if (sniList.length > 0)
      bits.push(sniList[0] + (sniList.length > 1 ? ` +${sniList.length - 1}` : ""));
    const probe = form.probeUrl.trim();
    if (probe && probe !== DEFAULT_PROBE_URL)
      bits.push(probe.length > 28 ? `${probe.slice(0, 28)}…` : probe);
    return bits.join(" · ");
  });

  // A routed error on any collapsed knob pops the disclosure open so its
  // inline message is never hidden inside it.
  $effect(() => {
    if (fieldErrors.snis || fieldErrors.fragment || fieldErrors.probeUrl)
      tunnelAdvancedOpen = true;
  });
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

  /** field → first message: client issues for touched fields, overlaid by
   * server-routed errors (which are cleared on edit). */
  const fieldErrors = $derived.by(() => {
    const map: Partial<Record<FormField, string>> = {};
    for (const i of liveIssues)
      if (i.field !== null && map[i.field] === undefined) map[i.field] = i.message;
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

  /** Append the WARP-ingress preset to the exclusions, deduping against
   * lines already present so clicking twice never duplicates a CIDR. */
  function excludeWarpIngress() {
    const kept = form.exclude
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const seen = new Set(kept);
    form.exclude = [
      ...kept,
      ...EXCLUDE_WARP_INGRESS.filter((c) => !seen.has(c)),
    ].join("\n");
    touched.exclude = true;
    delete serverFieldErrors.exclude;
  }

  function clearExclusions() {
    form.exclude = "";
    touched.exclude = true;
    delete serverFieldErrors.exclude;
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

  async function loadRangeInfo() {
    try {
      rangesInfo = await api.ranges();
      app.error = null;
    } catch (e) {
      app.error = errorText(e);
    }
  }

  async function refreshProfiles() {
    profiles = await api.profiles();
    if (!profiles.some((p) => p.name === selectedProfile))
      selectedProfile = "";
  }

  function loadSelectedProfile() {
    const p = profiles.find((x) => x.name === selectedProfile);
    if (!p) return;
    // The form swap may change form.mode; the port-reset effect must not
    // clobber the profile's own port selection right after it lands.
    suppressPortReset = true;
    form = formStateFromConfig(p.config);
    touched = {};
    serverFieldErrors = {};
    validationErrors = [];
  }

  async function saveProfile() {
    const name = profileNameInput.trim();
    if (!name) {
      profileStatus = { ok: false, text: t("pro.profile.needName") };
      return;
    }
    profileBusy = true;
    try {
      await assertOk(await api.saveProfile(name, buildConfig(form)));
      profileStatus = { ok: true, text: t("pro.profile.saved", { name }) };
      profileNameInput = "";
      await refreshProfiles();
      selectedProfile = name;
    } catch (e) {
      profileStatus = {
        ok: false,
        text: e instanceof FormValidationError ? e.message : errorText(e),
      };
    }
    profileBusy = false;
  }

  async function deleteSelectedProfile() {
    if (!selectedProfile || !confirm(t("pro.profile.deleteConfirm", { name: selectedProfile })))
      return;
    profileBusy = true;
    const deleted = selectedProfile;
    try {
      await assertOk(await api.deleteProfile(deleted));
      profileStatus = { ok: true, text: t("pro.profile.deleted", { name: deleted }) };
      await refreshProfiles();
    } catch (e) {
      profileStatus = { ok: false, text: errorText(e) };
    }
    profileBusy = false;
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

  /** The register flow can take up to ~45 s server-side; a conflict asks for
   * explicit overwrite consent (retried from the inline button), and the
   * cooldown message is shown verbatim. */
  async function registerWarp(overwrite: boolean) {
    registering = true;
    registerError = null;
    offerOverwrite = false;
    try {
      const res = await api.warpRegister(licenseInput.trim() || null, overwrite);
      registeredConf = res.wgconf;
    } catch (e) {
      const msg = errorText(e);
      registerError = msg;
      offerOverwrite = /overwrite/i.test(msg);
    }
    registering = false;
  }

  async function copyConf() {
    try {
      await navigator.clipboard.writeText(registeredConf);
      confCopied = true;
      setTimeout(() => (confCopied = false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }

  function useRegisteredConf() {
    form.wgconf = registeredConf;
    form.verifyWarp = true;
    registeredConf = "";
    registerError = null;
  }

  /** Persist every change (debounced ~300 ms); wgconf is excluded inside
   * persistedFormState so keys never reach disk. */
  $effect(() => {
    if (!hydrated) return;
    const snapshot = persistedFormState(form);
    const t = setTimeout(() => {
      try {
        localStorage.setItem(FORM_PERSIST_KEY, snapshot);
      } catch {
        /* storage unavailable (private mode/quota): persistence is best-effort */
      }
    }, 300);
    return () => clearTimeout(t);
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

    void refreshProfiles().catch((e) => {
      profileStatus = { ok: false, text: errorText(e) };
    });
    void loadXray();
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
    <!-- profiles bar: outside the <form> so Enter here never starts a scan -->
    <div
      class="mb-4 flex flex-wrap items-center gap-2 border-b pb-4"
      style="border-color: oklch(100% 0 0 / 6%)"
    >
      <span
        class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider"
        style="color: var(--ink-muted)"
      >
        <FolderOpen class="size-3.5" style="color: var(--accent)" /> {t("pro.profile.heading")}
      </span>
      <select
        class="field !w-auto text-xs"
        bind:value={selectedProfile}
        onchange={loadSelectedProfile}
        disabled={profiles.length === 0}
        title={t("pro.profile.loadTitle")}
      >
        <option value="">
          {profiles.length === 0 ? t("pro.profile.noSaved") : t("pro.profile.loadPlaceholder")}
        </option>
        {#each profiles as p (p.name)}
          <option value={p.name}>{p.name}</option>
        {/each}
      </select>
      <input
        class="field mono !w-44 text-xs"
        placeholder={t("pro.profile.namePlaceholder")}
        maxlength="64"
        bind:value={profileNameInput}
      />
      <button
        class="btn btn-secondary btn-sm"
        onclick={saveProfile}
        disabled={profileBusy}
        title={t("pro.profile.saveTitle")}
      >
        <Save class="size-3.5" /> {t("pro.profile.save")}
      </button>
      <button
        class="btn btn-secondary btn-sm"
        onclick={deleteSelectedProfile}
        disabled={!selectedProfile || profileBusy}
        title={t("pro.profile.deleteTitle")}
      >
        <Trash2 class="size-3.5" /> {t("pro.profile.delete")}
      </button>
      {#if profileStatus}
        <span
          class="fade-in text-xs"
          role="status"
          style={profileStatus.ok
            ? "color: var(--good)"
            : "color: var(--bad)"}
        >
          {profileStatus.text}
        </span>
      {/if}
    </div>

    <!-- delegated touched/server-error tracking + Ctrl+Enter accelerator -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <form onsubmit={onFormSubmit} oninput={markTouched} onchange={markTouched} onkeydown={onFormKeydown}>
      <!-- shared file picker for both Import-list buttons (target set at click time) -->
      <input
        bind:this={rangesFileInput}
        class="hidden"
        type="file"
        accept=".txt,.csv,.list,.text,text/plain"
        onchange={importRangesFile}
      />
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h3 class="flex items-center gap-2 text-sm font-semibold">
          <Gauge class="size-4" style="color: var(--accent)" /> {t("pro.section.scanConfig")}
        </h3>
        <div class="flex items-center gap-2">
          {#if xray}
            <span
              class="pill"
              title={xray.found ? (xray.path ?? t("pro.xray.foundFallback")) : t("pro.xray.missingUnder", { dir: xray.data_dir ?? "" })}
              style={xray.found
                ? "background: oklch(30% .06 155); color: var(--good)"
                : "background: oklch(30% .09 25); color: var(--bad)"}
            >
              xray {xray.found ? xray.version : t("pro.xray.missing")}
            </span>
            {#if !xray.found}
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                onclick={downloadXray}
                disabled={xrayBusy}
                data-state={xrayBusy ? "loading" : undefined}
                title={t("pro.xray.downloadTitle", { dir: xray.data_dir ?? "" })}
              >
                <Download class="size-3.5" /> {t("pro.xray.download")}
              </button>
            {/if}
          {/if}
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            onclick={loadRangeInfo}
            title={t("pro.range.infoTitle")}
          >
            <Info class="size-3.5" /> {t("pro.range.button")}
          </button>
        </div>
      </div>

      {#if xrayError}
        <p class="fade-in mt-2 text-xs" role="alert" style="color: var(--bad)">
          {t("pro.xray.error", { msg: xrayError })}
        </p>
      {/if}

      {#if rangesInfo}
        <p class="mono fade-in mt-2 text-[11px]" style="color: var(--ink-muted)">
          {t("pro.range.info", { count: rangesInfo.host_count.toLocaleString("en-US"), date: rangesInfo.last_updated ?? t("pro.range.bundled") })}
        </p>
      {/if}

      {#if validationErrors.length > 0}
        <div class="fade-in mt-3 text-xs" role="alert" style="color: var(--bad)">
          <p class="font-semibold">{t("pro.validation.fixBefore")}</p>
          <ul class="mt-1 list-inside list-disc space-y-0.5">
            {#each validationErrors as msg (msg)}
              <li>{msg}</li>
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
              class="flex flex-wrap items-center gap-1 rounded-full p-1"
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

      <details class="mt-4">
        <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
          {t("pro.section.customCidrs")}
        </summary>
        <div class="mt-3 grid gap-4 grid-form">
          <label class="text-xs" style="color: var(--ink-muted)">
            {t("pro.field.customCidrs")}
            <textarea
              class="field mono mt-1"
              rows="3"
              name="customCidrs"
              aria-invalid={fieldErrors.customCidrs ? "true" : undefined}
              aria-describedby={fieldErrors.customCidrs ? "err-customCidrs" : undefined}
              bind:value={form.customCidrs}
              onchange={() => normalizeField("customCidrs")}></textarea>
            {@render fieldError("customCidrs")}
          </label>
          <label class="text-xs" style="color: var(--ink-muted)">
            {t("pro.field.exclude")}
            <textarea
              class="field mono mt-1"
              rows="3"
              name="exclude"
              aria-invalid={fieldErrors.exclude ? "true" : undefined}
              aria-describedby={fieldErrors.exclude ? "err-exclude" : undefined}
              bind:value={form.exclude}
              onchange={() => normalizeField("exclude")}></textarea>
            {@render fieldError("exclude")}
          </label>
        </div>
        <div class="mt-2 flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            class="pill cursor-pointer"
            style="background: var(--paper-3); color: var(--ink)"
            title={t("pro.field.excludeWarpTitle")}
            onclick={excludeWarpIngress}
          >{t("pro.field.excludeWarp")}</button>
          {#if form.mode === "Cdn"}
            <button
              type="button"
              class="pill cursor-pointer"
              style="background: var(--paper-3); color: var(--ink)"
              title={t("pro.field.importListTitle")}
              onclick={() => { rangesTarget = "customCidrs"; rangesFileInput?.click(); }}
            >{t("pro.field.importList")}</button>
          {/if}
          <button
            type="button"
            class="pill cursor-pointer"
            style="color: var(--ink-muted)"
            title={t("pro.field.clearTitle")}
            onclick={clearExclusions}
          >{t("pro.field.clear")}</button>
          {#if rangesNote}
            <span
              class="fade-in mono text-[10px]"
              role="status"
              style={rangesNote.ok ? "color: var(--good)" : "color: var(--bad)"}
            >
              {rangesNote.text}
            </span>
          {/if}
        </div>
      </details>

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
                  onclick={() => { rangesTarget = "warpEndpoints"; rangesFileInput?.click(); }}
                >{t("pro.field.importList")}</button>
                {#if rangesNote}
                  <span
                    class="fade-in mono text-[10px]"
                    role="status"
                    style={rangesNote.ok ? "color: var(--good)" : "color: var(--bad)"}
                  >
                    {rangesNote.text}
                  </span>
                {/if}
              </div>
            </div>
          </details>

          <div class="mt-3 grid gap-4 grid-form">
          <div class="text-xs span-all" style="color: var(--ink-muted)">
            <label class="block">
              {t("pro.warp.wgconfLabel")}
              <textarea
                class="field mono mt-1"
                rows="3"
                name="wgconf"
                aria-invalid={fieldErrors.wgconf ? "true" : undefined}
                aria-describedby={fieldErrors.wgconf ? "err-wgconf" : undefined}
                bind:value={form.wgconf}
                onchange={() => {
                  // Mirror the file-load behavior: a pasted config implies
                  // intent to verify — flip the checkbox on automatically.
                  if (form.wgconf.trim()) {
                    form.verifyWarp = true;
                    touched.verifyWarp = true;
                  }
                }}
              ></textarea>
            </label>
            {@render fieldError("wgconf")}
            <div class="mt-1.5 flex flex-wrap items-center gap-2">
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                title={t("pro.warp.wgconfLoadTitle")}
                onclick={() => wgconfFileInput?.click()}
              >
                <FolderOpen class="size-3.5" /> {t("pro.warp.wgconfLoad")}
              </button>
              {#if wgconfFileName}
                <span
                  class="fade-in mono max-w-48 truncate text-[11px]"
                  style="color: var(--ink-muted)"
                  title={wgconfFileName}>{wgconfFileName}</span
                >
              {/if}
            </div>
            {#if wgconfFileError}
              <p class="fade-in mt-1 text-[11px]" role="alert" style="color: var(--bad)">
                {wgconfFileError}
              </p>
            {/if}
            <div class="mt-2">
              <WgNoiseEditor
                text={form.wgconf}
                onchange={(next) => {
                  form.wgconf = next;
                  touched.wgconf = true;
                  delete serverFieldErrors.wgconf;
                }}
              />
            </div>
            <input
              bind:this={wgconfFileInput}
              class="hidden"
              type="file"
              accept=".conf,.txt"
              onchange={loadWgconfFile}
            />
          </div>
          <label class="flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
            <input type="checkbox" name="verifyWarp" bind:checked={form.verifyWarp} disabled={!form.wgconf} class="accent-[var(--accent)]" />
            {t("pro.warp.verify")}
          </label>
          <p class="mt-1 text-[11px] span-all" style="color: var(--ink-muted)">{t("pro.warp.verifyHint")}</p>

          <!-- WARP registration -->
          <div
            class="fade-in rounded-md border px-3 py-3 span-all"
            style="border-color: oklch(100% 0 0 / 8%)"
          >
            <div class="flex flex-wrap items-end gap-2">
              <label class="text-xs" style="color: var(--ink-muted)">
                {t("pro.warp.licenseLabel")}
                <input
                  class="field mono mt-1 !w-56"
                  bind:value={licenseInput}
                  maxlength="256"
                  placeholder={t("pro.warp.licensePlaceholder")}
                />
              </label>
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                onclick={() => registerWarp(false)}
                disabled={registering}
                data-state={registering ? "loading" : undefined}
                title={t("pro.warp.registerTitle")}
              >
                <KeyRound class="size-3.5" />
                {registering ? t("pro.warp.registering") : t("pro.warp.register")}
              </button>
            </div>

            {#if registerError}
              <div class="fade-in mt-2 flex flex-wrap items-center gap-2 text-xs">
                <span role="alert" style="color: var(--bad)">{registerError}</span>
                {#if offerOverwrite && !registering}
                  <button
                    type="button"
                    class="btn btn-secondary btn-sm"
                    onclick={() => registerWarp(true)}
                    title={t("pro.warp.overwriteTitle")}
                  >
                    {t("pro.warp.overwrite")}
                  </button>
                {/if}
              </div>
            {/if}

            {#if registeredConf}
              <div class="fade-in mt-3">
                <p class="text-xs font-semibold" style="color: var(--good)">
                  {t("pro.warp.registeredHeading")}
                </p>
                <textarea
                  class="field mono mt-1 w-full"
                  rows="5"
                  readonly
                  value={registeredConf}
                ></textarea>
                <div class="mt-2 flex flex-wrap gap-2">
                  <button type="button" class="btn btn-secondary btn-sm" onclick={copyConf}>
                    {#if confCopied}
                      <Check class="size-3.5" style="color: var(--good)" /> {t("pro.warp.copied")}
                    {:else}
                      <Copy class="size-3.5" /> {t("pro.warp.copy")}
                    {/if}
                  </button>
                  <button
                    type="button"
                    class="btn btn-primary btn-sm"
                    onclick={useRegisteredConf}
                    title={t("pro.warp.useInVerifyTitle")}
                  >
                    {t("pro.warp.useInVerify")}
                  </button>
                </div>
              </div>
            {/if}
            </div>
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
          <!-- Tunnel-test card: configs stay visible; expert knobs collapse
               into a details whose summary lists non-default choices. -->
          <div
            class="fade-in mt-4 rounded-md border px-4 py-4"
            style="border-color: oklch(100% 0 0 / 8%)"
          >
            <span class="eyebrow mb-3">{t("table.tunnel.col")}</span>
            <label class="text-xs" style="color: var(--ink-muted)">
              {t("pro.phase2.configsLabel")}
              <textarea
                class="field mono mt-1"
                rows="3"
                name="configsText"
                aria-invalid={fieldErrors.configsText ? "true" : undefined}
                aria-describedby={fieldErrors.configsText ? "err-configsText" : undefined}
                bind:value={form.configsText}
                onchange={() => normalizeField("configsText")}></textarea>
              {@render fieldError("configsText")}
            </label>
            <details class="mt-3" bind:open={tunnelAdvancedOpen}>
              <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
                {t("pro.section.tunnelAdvanced")}
                {#if tunnelAdvancedSummary}
                  <span class="mono font-normal" style="color: var(--accent)">
                    · {tunnelAdvancedSummary}
                  </span>
                {/if}
              </summary>
              <div class="mt-3 grid gap-4 grid-form">
                <label class="text-xs" style="color: var(--ink-muted)">
                  {t("pro.phase2.fragment")}
                  <select class="field mt-1" name="fragment" bind:value={form.fragment}>
                    <option>off</option><option>light</option><option>medium</option><option>heavy</option>
                  </select>
                  {@render fieldError("fragment")}
                </label>
                <label class="text-xs span-all" style="color: var(--ink-muted)">
                  {t("pro.phase2.sniLabel")}
                  <input
                    class="field mono mt-1"
                    name="snis"
                    placeholder={t("pro.phase2.sniPlaceholder")}
                    aria-invalid={fieldErrors.snis ? "true" : undefined}
                    aria-describedby={fieldErrors.snis ? "err-snis" : undefined}
                    bind:value={form.snis}
                  />
                  {@render fieldError("snis")}
                </label>
                <label class="text-xs span-all" style="color: var(--ink-muted)">
                  {t("pro.phase2.probeLabel")}
                  <input
                    class="field mono mt-1"
                    name="probeUrl"
                    aria-invalid={fieldErrors.probeUrl ? "true" : undefined}
                    aria-describedby={fieldErrors.probeUrl ? "err-probeUrl" : undefined}
                    bind:value={form.probeUrl}
                  />
                  {@render fieldError("probeUrl")}
                </label>
              </div>
            </details>
          </div>
        {/if}
      {/if}

      <!-- sticky actions: one canonical Start/Stop pair, visible even with
           phase-2/WARP textareas expanded -->
      <div
        class="sticky bottom-0 z-10 -mx-6 sm:-mx-8 -mb-8 sm:-mb-10 mt-5 rounded-b-2xl px-6 sm:px-8 pt-3 backdrop-blur-md"
        style="background: color-mix(in oklab, var(--paper-2) 88%, transparent); box-shadow: 0 -12px 24px oklch(0% 0 0 / 25%); padding-bottom: max(1rem, env(safe-area-inset-bottom));"
      >
        <div class="flex flex-wrap items-center justify-end gap-2">
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
                title={form.phase2On && configsListed.length > 0
                  ? t("pro.action.skipTitle")
                  : t("pro.phase2.configsLabel")}
                onclick={verifyBanked}
              >
                <ShieldCheck class="size-3.5" />
                {t("pro.action.verifyBanked", { n: app.results.length })}
              </button>
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
          <p class="fade-in mt-2 text-[11px]" role="note" style="color: oklch(80% 0.13 85)">
            {t("pro.hint.noCap")}
          </p>
        {/if}
      </div>
    </form>
    </div>
  </section>

  {#if app.phase2}
    <p class="mono fade-in px-1 text-xs" style="color: var(--accent)" role="status">
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
