<script lang="ts">
  import { onMount } from "svelte";
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
  import { errorText, startScan, stopScan, ui } from "../store.svelte";
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
      wgconfFileError = `"${file.name}" is ${Math.ceil(file.size / 1024)} KB — wgconf files must be 64 KB or smaller`;
      return;
    }
    try {
      form.wgconf = await file.text();
      form.verifyWarp = true;
      wgconfFileName = file.name;
      delete serverFieldErrors.wgconf;
    } catch {
      wgconfFileError = `Could not read "${file.name}"`;
    }
  }

  const allIssues = $derived.by(() => {
    try {
      buildConfig(form);
      return [] as FieldIssue[];
    } catch (e) {
      return e instanceof FormValidationError ? e.issues : [];
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
    [/\bsnis?\b/i, "snis"],
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
  // stale cross-family ports can't linger silently.
  $effect(() => {
    void form.mode;
    if (hydrated) {
      form.selectedPorts = defaultSelectedPorts(form.mode);
      form.customPortsText = "";
    }
  });

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
    form = formStateFromConfig(p.config);
    touched = {};
    serverFieldErrors = {};
    validationErrors = [];
  }

  async function saveProfile() {
    const name = profileNameInput.trim();
    if (!name) {
      profileStatus = { ok: false, text: "Enter a name to save this configuration." };
      return;
    }
    profileBusy = true;
    try {
      await assertOk(await api.saveProfile(name, buildConfig(form)));
      profileStatus = { ok: true, text: `Saved "${name}."` };
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
    if (!selectedProfile || !confirm(`Delete profile "${selectedProfile}"?`))
      return;
    profileBusy = true;
    const deleted = selectedProfile;
    try {
      await assertOk(await api.deleteProfile(deleted));
      profileStatus = { ok: true, text: `Deleted "${deleted}."` };
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
      if (!res.success) xrayError = res.error ?? "download failed";
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
      class="fade-in mt-1 block text-[11px] leading-snug"
      style="color: var(--bad)"
      role="alert">{fieldErrors[name]}</span
    >
  {/if}
{/snippet}

<div class="fade-in flex flex-col gap-6">
  <!-- scan form -->
  <section class="card px-6 py-6">
    <!-- profiles bar: outside the <form> so Enter here never starts a scan -->
    <div
      class="mb-4 flex flex-wrap items-center gap-2 border-b pb-4"
      style="border-color: oklch(100% 0 0 / 6%)"
    >
      <span
        class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider"
        style="color: var(--ink-muted)"
      >
        <FolderOpen class="size-3.5" style="color: var(--accent)" /> Profiles
      </span>
      <select
        class="field !w-auto text-xs"
        bind:value={selectedProfile}
        onchange={loadSelectedProfile}
        disabled={profiles.length === 0}
        title="Load a saved profile into the form"
      >
        <option value="">
          {profiles.length === 0 ? "no saved profiles yet" : "load a profile…"}
        </option>
        {#each profiles as p (p.name)}
          <option value={p.name}>{p.name}</option>
        {/each}
      </select>
      <input
        class="field mono !w-44 text-xs"
        placeholder="name to save as"
        maxlength="64"
        bind:value={profileNameInput}
      />
      <button
        class="btn btn-secondary btn-sm"
        onclick={saveProfile}
        disabled={profileBusy}
        title="Save the current form values under this name"
      >
        <Save class="size-3.5" /> Save
      </button>
      <button
        class="btn btn-secondary btn-sm"
        onclick={deleteSelectedProfile}
        disabled={!selectedProfile || profileBusy}
        title="Delete the selected profile"
      >
        <Trash2 class="size-3.5" /> Delete
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
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h3 class="flex items-center gap-2 text-sm font-semibold">
          <Gauge class="size-4" style="color: var(--accent)" /> Scan configuration
        </h3>
        <div class="flex items-center gap-2">
          {#if xray}
            <span
              class="pill"
              title={xray.found
                ? (xray.path ?? "xray binary found")
                : `not found — expected under ${xray.data_dir}`}
              style={xray.found
                ? "background: oklch(30% .06 155); color: var(--good)"
                : "background: oklch(30% .09 25); color: var(--bad)"}
            >
              xray {xray.found ? xray.version : "missing"}
            </span>
            {#if !xray.found}
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                onclick={downloadXray}
                disabled={xrayBusy}
                data-state={xrayBusy ? "loading" : undefined}
                title={`Download the pinned xray release into the data dir (${xray.data_dir})`}
              >
                <Download class="size-3.5" /> Download
              </button>
            {/if}
          {/if}
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            onclick={loadRangeInfo}
            title="Show how many candidate IPs are loaded and when they were last refreshed"
          >
            <Info class="size-3.5" /> Range info
          </button>
        </div>
      </div>

      {#if xrayError}
        <p class="fade-in mt-2 text-xs" role="alert" style="color: var(--bad)">
          xray: {xrayError}
        </p>
      {/if}

      {#if rangesInfo}
        <p class="mono fade-in mt-2 text-[11px]" style="color: var(--ink-muted)">
          {rangesInfo.host_count.toLocaleString("en-US")} hosts · updated
          {rangesInfo.last_updated ?? "bundled"}
        </p>
      {/if}

      {#if validationErrors.length > 0}
        <div class="fade-in mt-3 text-xs" role="alert" style="color: var(--bad)">
          <p class="font-semibold">Fix these before starting:</p>
          <ul class="mt-1 list-inside list-disc space-y-0.5">
            {#each validationErrors as msg (msg)}
              <li>{msg}</li>
            {/each}
          </ul>
        </div>
      {/if}

      <div class="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <label class="text-xs" style="color: var(--ink-muted)">
          Mode
          <select class="field mt-1" name="mode" bind:value={form.mode}>
            <option value="Cdn">CDN / proxy</option>
            <option value="Warp">WARP</option>
          </select>
        </label>

        {#if form.mode === "Cdn"}
          <div>
            <label class="block text-xs" style="color: var(--ink-muted)">
              Target
              <select class="field mt-1" name="preset" bind:value={form.preset} disabled={form.useCount}>
                <option>Quick</option><option>Normal</option><option>Full</option>
              </select>
            </label>
            <p class="mt-1 text-[11px]" style="color: var(--ink-muted)">
              Quick ≈ 4K probes · Normal ≈ 12K · Full = every known CF IP
              (~1.5M, hours)
            </p>
          </div>
          <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
            <input type="checkbox" name="useCount" bind:checked={form.useCount} class="accent-[var(--accent)]" />
            custom count instead
          </label>
        {/if}

        <label class="text-xs" style="color: var(--ink-muted)">
          Candidates to test
          <input
            class="field mono mt-1"
            type="number"
            min="1"
            max="100000"
            name="count"
            aria-invalid={fieldErrors.count ? "true" : undefined}
            bind:value={form.count}
          />
          {@render fieldError("count")}
        </label>

        <div class="text-xs sm:col-span-2 lg:col-span-3">
          <div class="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
            <span style="color: var(--ink-muted)">
              Cloudflare ports
              {#if form.mode === "Warp"}
                <span class="mono text-[10px]">(WireGuard UDP · official)</span>
              {:else}
                <span class="mono text-[10px]">(TLS · per Cloudflare network-ports docs)</span>
              {/if}
            </span>
            <span class="flex items-center gap-1">
              <button
                type="button"
                class="pill cursor-pointer"
                style="background: var(--paper-3); color: var(--ink-muted)"
                title="Select every catalog port for this mode (including extended)"
                onclick={selectAllPorts}
              >
                all
              </button>
              <button
                type="button"
                class="pill cursor-pointer"
                style="background: var(--paper-3); color: var(--ink-muted)"
                title="Clear the port selection"
                onclick={clearPorts}
              >
                none
              </button>
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
          </div>
          {#if form.mode === "Warp" && portCatalog(form.mode).extended.length > 0}
            <details class="mt-2">
              <summary class="cursor-pointer" style="color: var(--ink-muted)">
                extended community ports ({portCatalog(form.mode).extended.length})
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

        <label class="text-xs" style="color: var(--ink-muted)">
          Custom port(s) — comma-separated
          <input
            class="field mono mt-1"
            name="customPortsText"
            placeholder="8443"
            aria-invalid={fieldErrors.customPortsText ? "true" : undefined}
            bind:value={form.customPortsText}
          />
          {@render fieldError("customPortsText")}
        </label>

        <label class="text-xs" style="color: var(--ink-muted)">
          Concurrency
          <input
            class="field mono mt-1"
            type="number"
            min="1"
            max="1000"
            name="concurrency"
            aria-invalid={fieldErrors.concurrency ? "true" : undefined}
            bind:value={form.concurrency}
          />
          {@render fieldError("concurrency")}
        </label>

        <label class="text-xs" style="color: var(--ink-muted)">
          Timeout (ms)
          <input
            class="field mono mt-1"
            type="number"
            min="100"
            max="30000"
            name="timeoutMs"
            aria-invalid={fieldErrors.timeoutMs ? "true" : undefined}
            bind:value={form.timeoutMs}
          />
          {@render fieldError("timeoutMs")}
        </label>

        <label class="text-xs" style="color: var(--ink-muted)">
          Stop after N working found
          <input
            class="field mono mt-1"
            type="number"
            min="1"
            name="stopFound"
            aria-invalid={fieldErrors.stopFound ? "true" : undefined}
            bind:value={form.stopFound}
          />
          {@render fieldError("stopFound")}
        </label>

        <label class="text-xs" style="color: var(--ink-muted)">
          Hard cap on probes (blank = unlimited)
          <input
            class="field mono mt-1"
            type="text"
            inputmode="numeric"
            placeholder="none"
            name="capText"
            aria-invalid={fieldErrors.capText ? "true" : undefined}
            bind:value={form.capText}
          />
          {@render fieldError("capText")}
        </label>

        {#if form.mode === "Cdn"}
          <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
            <input type="checkbox" name="includeV6" bind:checked={form.includeV6} class="accent-[var(--accent)]" />
            include IPv6 ranges
          </label>
        {/if}
      </div>

      <details class="mt-4">
        <summary class="cursor-pointer text-xs font-semibold" style="color: var(--ink-muted)">
          Custom CIDRs &amp; exclusions
        </summary>
        <div class="mt-3 grid gap-4 sm:grid-cols-2">
          <label class="text-xs" style="color: var(--ink-muted)">
            Custom CIDRs (one per line)
            <textarea
              class="field mono mt-1"
              rows="3"
              name="customCidrs"
              aria-invalid={fieldErrors.customCidrs ? "true" : undefined}
              bind:value={form.customCidrs}></textarea>
            {@render fieldError("customCidrs")}
          </label>
          <label class="text-xs" style="color: var(--ink-muted)">
            Exclude (one CIDR per line)
            <textarea
              class="field mono mt-1"
              rows="3"
              name="exclude"
              aria-invalid={fieldErrors.exclude ? "true" : undefined}
              bind:value={form.exclude}></textarea>
            {@render fieldError("exclude")}
          </label>
        </div>
        <div class="mt-2 flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            class="pill cursor-pointer"
            style="background: var(--paper-3); color: var(--ink)"
            title="Append Cloudflare's WARP ingress ranges to the exclusion list (deduped)"
            onclick={excludeWarpIngress}
          >
            Exclude WARP ingress
          </button>
          <button
            type="button"
            class="pill cursor-pointer"
            style="color: var(--ink-muted)"
            title="Empty the exclusion list"
            onclick={clearExclusions}
          >
            clear
          </button>
          <span class="mono text-[10px]" style="color: var(--ink-muted)">
            adds 162.159.192.0/24 + 162.159.193.0/24 — Cloudflare One docs list
            these as WARP ingress; probing them in CDN mode wastes candidates
          </span>
        </div>
      </details>

      {#if form.mode === "Warp"}
        <div class="mt-4 grid gap-4 sm:grid-cols-2">
          <label class="text-xs" style="color: var(--ink-muted)">
            Handshake probes per endpoint (higher = stricter zero-loss bar)
            <input
              class="field mono mt-1"
              type="number"
              min="1"
              max="10"
              name="warpProbes"
              aria-invalid={fieldErrors.warpProbes ? "true" : undefined}
              bind:value={form.warpProbes}
            />
            {@render fieldError("warpProbes")}
          </label>
          <label class="text-xs" style="color: var(--ink-muted)">
            Custom endpoints (ip or ip:port, one per line)
            <textarea
              class="field mono mt-1"
              rows="2"
              name="warpEndpoints"
              aria-invalid={fieldErrors.warpEndpoints ? "true" : undefined}
              bind:value={form.warpEndpoints}></textarea>
            {@render fieldError("warpEndpoints")}
          </label>
          <div class="text-xs sm:col-span-2" style="color: var(--ink-muted)">
            <label class="block">
              wgconf (paste your wg:// URI, wg-quick INI, or Amnezia config — enables real-keypair verification)
              <textarea
                class="field mono mt-1"
                rows="3"
                name="wgconf"
                aria-invalid={fieldErrors.wgconf ? "true" : undefined}
                bind:value={form.wgconf}></textarea>
            </label>
            {@render fieldError("wgconf")}
            <div class="mt-1.5 flex flex-wrap items-center gap-2">
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                title="Read a WireGuard .conf file into the field above (verification is enabled automatically)"
                onclick={() => wgconfFileInput?.click()}
              >
                <FolderOpen class="size-3.5" /> Load .conf file
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
            verify with this identity's real keypair
          </label>

          <!-- WARP registration -->
          <div
            class="fade-in rounded-md border px-3 py-3 sm:col-span-2"
            style="border-color: oklch(100% 0 0 / 8%)"
          >
            <div class="flex flex-wrap items-end gap-2">
              <label class="text-xs" style="color: var(--ink-muted)">
                WARP+ license (optional — blank = free account)
                <input
                  class="field mono mt-1 !w-56"
                  bind:value={licenseInput}
                  maxlength="256"
                  placeholder="license key"
                />
              </label>
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                onclick={() => registerWarp(false)}
                disabled={registering}
                data-state={registering ? "loading" : undefined}
                title="Register a fresh WARP identity with Cloudflare (~45 s)"
              >
                <KeyRound class="size-3.5" />
                {registering ? "Registering…" : "Register identity"}
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
                    title="Replace the previously registered identity with a new one"
                  >
                    Overwrite existing identity?
                  </button>
                {/if}
              </div>
            {/if}

            {#if registeredConf}
              <div class="fade-in mt-3">
                <p class="text-xs font-semibold" style="color: var(--good)">
                  Identity registered — wgconf:
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
                      <Check class="size-3.5" style="color: var(--good)" /> Copied
                    {:else}
                      <Copy class="size-3.5" /> Copy
                    {/if}
                  </button>
                  <button
                    type="button"
                    class="btn btn-primary btn-sm"
                    onclick={useRegisteredConf}
                    title="Paste into the wgconf field above and enable real-keypair verification"
                  >
                    Use in verify
                  </button>
                </div>
              </div>
            {/if}
          </div>
        </div>
      {:else}
        <!-- phase-2 toggle sits above the section it reveals -->
        <label class="mt-4 flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" name="phase2On" bind:checked={form.phase2On} class="accent-[var(--accent)]" />
          <ShieldCheck class="size-3.5" style="color: var(--accent)" />
          verify candidates through xray (phase 2)
        </label>
        {#if xray && !xray.found}
          <p class="mt-1 pl-6 text-[11px]" style="color: var(--ink-muted)">
            requires the xray binary — download it with the button above
          </p>
        {/if}

        {#if form.phase2On}
          <div class="fade-in mt-4 grid gap-4">
            <label class="text-xs" style="color: var(--ink-muted)">
              Configs to verify through the tunnel (vless/trojan/vmess/ss URIs or subscription URLs, one per line)
              <textarea
                class="field mono mt-1"
                rows="3"
                name="configsText"
                aria-invalid={fieldErrors.configsText ? "true" : undefined}
                bind:value={form.configsText}></textarea>
              {@render fieldError("configsText")}
            </label>
            <div class="grid gap-4 sm:grid-cols-3">
              <label class="text-xs" style="color: var(--ink-muted)">
                DPI fragmentation
                <select class="field mt-1" name="fragment" bind:value={form.fragment}>
                  <option>off</option><option>light</option><option>medium</option><option>heavy</option>
                  <option>custom</option>
                </select>
              </label>
              <label class="text-xs sm:col-span-2" style="color: var(--ink-muted)">
                SNI variants (comma-separated, empty = each config's own)
                <input
                  class="field mono mt-1"
                  name="snis"
                  placeholder="front.example.com"
                  aria-invalid={fieldErrors.snis ? "true" : undefined}
                  bind:value={form.snis}
                />
                {@render fieldError("snis")}
              </label>
            </div>
            <label class="text-xs" style="color: var(--ink-muted)">
              Probe URL fetched through each tunnel
              <input
                class="field mono mt-1"
                name="probeUrl"
                aria-invalid={fieldErrors.probeUrl ? "true" : undefined}
                bind:value={form.probeUrl}
              />
              {@render fieldError("probeUrl")}
            </label>
          </div>
        {/if}
      {/if}

      <!-- sticky actions: one canonical Start/Stop pair, visible even with
           phase-2/WARP textareas expanded -->
      <div
        class="sticky bottom-0 z-10 -mx-6 -mb-6 mt-5 rounded-b-2xl px-6 pb-4 pt-3 backdrop-blur-md"
        style="background: color-mix(in oklab, var(--paper-2) 88%, transparent); box-shadow: 0 -12px 24px oklch(0% 0 0 / 25%);"
      >
        <div class="flex flex-wrap items-center justify-end gap-2">
          {#if app.running}
            <button type="button" class="btn btn-secondary" onclick={stopScan}>
              <Square class="size-3.5" /> Stop
            </button>
          {:else}
            <button
              type="submit"
              class="btn btn-primary"
              disabled={starting}
              data-state={starting ? "loading" : undefined}
            >
              <Play class="size-3.5" /> Start scan
            </button>
          {/if}
        </div>
        {#if !form.capText.trim() && form.concurrency >= 512}
          <p class="fade-in mt-2 text-[11px]" role="note" style="color: oklch(80% 0.13 85)">
            no cap at high concurrency can run very long
          </p>
        {/if}
      </div>
    </form>
  </section>

  {#if app.phase2}
    <p class="mono fade-in px-1 text-xs" style="color: var(--accent)" role="status">
      phase 2: {app.phase2.done}/{app.phase2.total} verified…
    </p>
  {/if}

  {#if app.results.length > 0}
    <ResultsTable results={app.results} />
  {/if}
</div>
