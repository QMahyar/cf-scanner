<script lang="ts">
  import {
    Boxes,
    Download,
    Gauge,
    Globe,
    Info,
    KeyRound,
    Play,
    Save,
    ShieldCheck,
    Square,
  } from "@lucide/svelte";
  import { api, type RangesPayload } from "../api";
  import { errorText, startScan, stopScan, ui } from "../store.svelte";
  import {
    buildConfig,
    defaultFormState,
    FormValidationError,
  } from "../formState";
  import type { FormState } from "../formState";
  import ResultsTable from "./ResultsTable.svelte";

  const app = ui();
  let starting = $state(false);
  let validationErrors = $state<string[]>([]);
  let form = $state<FormState>(defaultFormState());
  let rangesInfo = $state<RangesPayload | null>(null);

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
</script>

<div class="fade-in flex flex-col gap-6">
  <!-- scan form -->
  <section class="card px-5 py-5">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h3 class="flex items-center gap-2 text-sm font-semibold">
        <Gauge class="size-4" style="color: var(--accent)" /> Scan configuration
      </h3>
      <div class="flex items-center gap-2">
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
        <label class="text-xs" style="color: var(--ink-muted)">
          Target
          <select class="field mt-1" bind:value={form.preset} disabled={form.useCount}>
            <option>Quick</option><option>Normal</option><option>Full</option>
          </select>
        </label>
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
