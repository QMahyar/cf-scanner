<script lang="ts">
  import { onMount } from "svelte";
  import {
    Boxes,
    Check,
    Copy,
    Download,
    FolderOpen,
    Gauge,
    Globe,
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
    formStateFromConfig,
    FormValidationError,
  } from "../formState";
  import type { FormState } from "../formState";
  import ResultsTable from "./ResultsTable.svelte";

  const app = ui();
  let starting = $state(false);
  let validationErrors = $state<string[]>([]);
  let form = $state<FormState>(defaultFormState());
  let rangesInfo = $state<RangesPayload | null>(null);

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

  async function start() {
    starting = true;
    try {
      const cfg = buildConfig(form);
      validationErrors = [];
      await startScan(cfg);
    } catch (e) {
      if (e instanceof FormValidationError) validationErrors = e.errors;
      else app.error = errorText(e);
    }
    starting = false;
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

  onMount(() => {
    void refreshProfiles().catch((e) => {
      profileStatus = { ok: false, text: errorText(e) };
    });
    void loadXray();
  });
</script>

<div class="fade-in flex flex-col gap-6">
  <!-- scan form -->
  <section class="card px-5 py-5">
    <!-- profiles bar -->
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
        class="btn btn-secondary !py-1.5"
        onclick={saveProfile}
        disabled={profileBusy}
        title="Save the current form values under this name"
      >
        <Save class="size-3.5" /> Save
      </button>
      <button
        class="btn btn-secondary !py-1.5"
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
              class="btn btn-secondary !py-1.5"
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
          class="btn btn-secondary !py-1.5"
          onclick={loadRangeInfo}
          title="Show how many candidate IPs are loaded and when they were last refreshed"
        >
          <Info class="size-3.5" /> Range info
        </button>
        {#if app.running}
          <button class="btn btn-secondary !py-1.5" onclick={stopScan}>
            <Square class="size-3.5" /> Stop
          </button>
        {:else}
          <button
            class="btn btn-primary !py-1.5"
            onclick={start}
            disabled={starting}
            data-state={starting ? "loading" : undefined}
          >
            <Play class="size-3.5" /> Start scan
          </button>
        {/if}
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

    <div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <label class="text-xs" style="color: var(--ink-muted)">
        Mode
        <select class="field mt-1" bind:value={form.mode}>
          <option value="Cdn">CDN / proxy</option>
          <option value="Warp">WARP</option>
        </select>
      </label>

      {#if form.mode === "Cdn"}
        <div>
          <label class="block text-xs" style="color: var(--ink-muted)">
            Target
            <select class="field mt-1" bind:value={form.preset} disabled={form.useCount}>
              <option>Quick</option><option>Normal</option><option>Full</option>
            </select>
          </label>
          <p class="mt-1 text-[11px]" style="color: var(--ink-muted)">
            Quick ≈ 4K probes · Normal ≈ 12K · Full = every known CF IP
            (~1.5M, hours)
          </p>
        </div>
        <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" bind:checked={form.useCount} class="accent-[var(--accent)]" />
          custom count instead
        </label>
      {/if}

      <label class="text-xs" style="color: var(--ink-muted)">
        Candidates to test
        <input class="field mono mt-1" type="number" min="1" max="100000" bind:value={form.count} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Ports (comma-separated)
        <input class="field mono mt-1" bind:value={form.portsText} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Concurrency
        <input class="field mono mt-1" type="number" min="1" max="1000" bind:value={form.concurrency} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Timeout (ms)
        <input class="field mono mt-1" type="number" min="100" max="30000" bind:value={form.timeoutMs} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Stop after N working found
        <input class="field mono mt-1" type="number" min="1" bind:value={form.stopFound} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Hard cap on probes (blank = unlimited)
        <input
          class="field mono mt-1"
          type="text"
          inputmode="numeric"
          placeholder="none"
          bind:value={form.capText}
        />
      </label>

      {#if form.mode === "Cdn"}
        <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" bind:checked={form.includeV6} class="accent-[var(--accent)]" />
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
          <textarea class="field mono mt-1" rows="3" bind:value={form.customCidrs}></textarea>
        </label>
        <label class="text-xs" style="color: var(--ink-muted)">
          Exclude (one CIDR per line)
          <textarea class="field mono mt-1" rows="3" bind:value={form.exclude}></textarea>
        </label>
      </div>
    </details>

    {#if form.mode === "Warp"}
      <div class="mt-4 grid gap-4 sm:grid-cols-2">
        <label class="text-xs" style="color: var(--ink-muted)">
          Handshake probes per endpoint (higher = stricter zero-loss bar)
          <input class="field mono mt-1" type="number" min="1" max="10" bind:value={form.warpProbes} />
        </label>
        <label class="text-xs" style="color: var(--ink-muted)">
          Custom endpoints (ip or ip:port, one per line)
          <textarea class="field mono mt-1" rows="2" bind:value={form.warpEndpoints}></textarea>
        </label>
        <label class="text-xs sm:col-span-2" style="color: var(--ink-muted)">
          wgconf (paste your wg:// URI, wg-quick INI, or Amnezia config — enables real-keypair verification)
          <textarea class="field mono mt-1" rows="3" bind:value={form.wgconf}></textarea>
        </label>
        <label class="flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" bind:checked={form.verifyWarp} disabled={!form.wgconf} class="accent-[var(--accent)]" />
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
              class="btn btn-secondary !py-1.5"
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
                  class="btn btn-secondary !py-1"
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
                <button class="btn btn-secondary !py-1.5" onclick={copyConf}>
                  {#if confCopied}
                    <Check class="size-3.5" style="color: var(--good)" /> Copied
                  {:else}
                    <Copy class="size-3.5" /> Copy
                  {/if}
                </button>
                <button
                  class="btn btn-primary !py-1.5"
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
    {:else if form.phase2On}
      <div class="mt-4 grid gap-4">
        <label class="text-xs" style="color: var(--ink-muted)">
          Configs to verify through the tunnel (vless/trojan/vmess/ss URIs or subscription URLs, one per line)
          <textarea class="field mono mt-1" rows="3" bind:value={form.configsText}></textarea>
        </label>
        <div class="grid gap-4 sm:grid-cols-3">
          <label class="text-xs" style="color: var(--ink-muted)">
            DPI fragmentation
            <select class="field mt-1" bind:value={form.fragment}>
              <option>off</option><option>light</option><option>medium</option><option>heavy</option>
              <option>custom</option>
            </select>
          </label>
          <label class="text-xs sm:col-span-2" style="color: var(--ink-muted)">
            SNI variants (comma-separated, empty = each config's own)
            <input class="field mono mt-1" bind:value={form.snis} placeholder="front.example.com" />
          </label>
        </div>
        <label class="text-xs" style="color: var(--ink-muted)">
          Probe URL fetched through each tunnel
          <input class="field mono mt-1" bind:value={form.probeUrl} />
        </label>
      </div>
    {/if}

    {#if form.mode === "Cdn"}
      <label class="mt-4 flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
        <input type="checkbox" bind:checked={form.phase2On} class="accent-[var(--accent)]" />
        <ShieldCheck class="size-3.5" style="color: var(--accent)" />
        verify candidates through xray (phase 2)
      </label>
      {#if xray && !xray.found}
        <p class="mt-1 pl-6 text-[11px]" style="color: var(--ink-muted)">
          requires the xray binary — download it with the button above
        </p>
      {/if}
    {/if}
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
