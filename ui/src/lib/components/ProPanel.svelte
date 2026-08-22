<script lang="ts">
  import {
    Boxes,
    Download,
    Gauge,
    Globe,
    KeyRound,
    Play,
    RefreshCw,
    Save,
    ShieldCheck,
    Square,
  } from "@lucide/svelte";
  import { api } from "../api";
  import { resetResults, ui } from "../store.svelte";
  import type { CdnPreset, FragmentPreset, ScanConfig, WarpConfig } from "../types";
  import ResultsTable from "./ResultsTable.svelte";

  const app = ui();
  let starting = $state(false);

  // --- form state (best defaults; every control is a Pro control) ---
  let mode = $state<"Cdn" | "Warp">("Cdn");
  let preset = $state<CdnPreset>("Quick");
  let count = $state(350);
  let useCount = $state(false);
  let ports = $state("443");
  let concurrency = $state(128);
  let timeoutMs = $state(2000);
  let includeV6 = $state(false);
  let stopFound = $state(20);
  let cap = $state<number | null>(null);
  let customCidrs = $state("");
  let exclude = $state("");

  let phase2On = $state(false);
  let configsText = $state("");
  let fragment = $state<FragmentPreset>("off");
  let snis = $state("");
  let probeUrl = $state("https://www.cloudflare.com/cdn-cgi/trace");

  let warpProbes = $state(3);
  let warpEndpoints = $state("");
  let wgconf = $state("");
  let verifyWarp = $state(false);

  function buildConfig(): ScanConfig {
    const cfg: ScanConfig = {
      mode,
      target: mode === "Cdn"
        ? useCount ? { Count: count } : { Preset: preset }
        : { Count: count },
      ports: ports.split(",").map((p) => parseInt(p.trim(), 10)).filter(Boolean),
      stop: { found: stopFound, cap },
      exclude: exclude.split("\n").map((s) => s.trim()).filter(Boolean),
      custom_cidrs: customCidrs.split("\n").map((s) => s.trim()).filter(Boolean),
      include_v6: includeV6,
      concurrency,
      timeout_ms: timeoutMs,
      phase2: null,
      warp: null,
    };
    if (mode === "Warp") {
      const warp: WarpConfig = {
        custom_endpoints: warpEndpoints.split("\n").map((s) => s.trim()).filter(Boolean),
        probes_per_endpoint: warpProbes,
        wgconf: wgconf || null,
        verify_with_wgconf: verifyWarp && !!wgconf,
      };
      cfg.warp = warp;
    }
    if (phase2On && mode === "Cdn") {
      cfg.phase2 = {
        configs: configsText.split("\n").map((s) => s.trim()).filter(Boolean),
        fragment,
        snis: snis.split(",").map((s) => s.trim()).filter(Boolean),
        probe_url: probeUrl,
        probe_urls: [],
        concurrency: 3,
      };
    }
    return cfg;
  }

  async function start() {
    starting = true;
    app.error = null;
    resetResults();
    try {
      await api.scan(buildConfig());
      app.running = true;
    } catch (e) {
      app.error = String(e);
    }
    starting = false;
  }

  async function stop() {
    await api.cancel();
  }

  async function refreshRanges() {
    try {
      await api.rangesRefresh();
      app.error = null;
    } catch (e) {
      app.error = String(e);
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
          onclick={refreshRanges}
          title="Re-fetch official Cloudflare ranges into the data dir"
        >
          <RefreshCw class="size-3.5" /> Refresh ranges
        </button>
        {#if app.running}
          <button class="btn btn-secondary !py-1.5" onclick={stop}>
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

    <div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <label class="text-xs" style="color: var(--ink-muted)">
        Mode
        <select class="field mt-1" bind:value={mode}>
          <option value="Cdn">CDN / proxy</option>
          <option value="Warp">WARP</option>
        </select>
      </label>

      {#if mode === "Cdn"}
        <label class="text-xs" style="color: var(--ink-muted)">
          Target
          <select class="field mt-1" bind:value={preset} disabled={useCount}>
            <option>Quick</option><option>Normal</option><option>Full</option>
          </select>
        </label>
        <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" bind:checked={useCount} class="accent-[var(--accent)]" />
          custom count instead
        </label>
      {/if}

      <label class="text-xs" style="color: var(--ink-muted)">
        {mode === "Cdn" && !useCount ? "Stop after N working" : "Candidates"}
        <input class="field mono mt-1" type="number" min="1" max="100000" bind:value={count} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Ports (comma-separated)
        <input class="field mono mt-1" bind:value={ports} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Concurrency
        <input class="field mono mt-1" type="number" min="1" max="1000" bind:value={concurrency} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Timeout (ms)
        <input class="field mono mt-1" type="number" min="100" max="30000" bind:value={timeoutMs} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Stop after N working
        <input class="field mono mt-1" type="number" min="1" bind:value={stopFound} />
      </label>

      <label class="text-xs" style="color: var(--ink-muted)">
        Hard cap on probes (empty = none)
        <input class="field mono mt-1" type="number" min="1" bind:value={cap} />
      </label>

      {#if mode === "Cdn"}
        <label class="flex items-end gap-2 pb-1 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" bind:checked={includeV6} class="accent-[var(--accent)]" />
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
          <textarea class="field mono mt-1" rows="3" bind:value={customCidrs}></textarea>
        </label>
        <label class="text-xs" style="color: var(--ink-muted)">
          Exclude (one CIDR per line)
          <textarea class="field mono mt-1" rows="3" bind:value={exclude}></textarea>
        </label>
      </div>
    </details>

    {#if mode === "Warp"}
      <div class="mt-4 grid gap-4 sm:grid-cols-2">
        <label class="text-xs" style="color: var(--ink-muted)">
          Handshake probes per endpoint (higher = stricter zero-loss bar)
          <input class="field mono mt-1" type="number" min="1" max="10" bind:value={warpProbes} />
        </label>
        <label class="text-xs" style="color: var(--ink-muted)">
          Custom endpoints (ip or ip:port, one per line)
          <textarea class="field mono mt-1" rows="2" bind:value={warpEndpoints}></textarea>
        </label>
        <label class="text-xs sm:col-span-2" style="color: var(--ink-muted)">
          wgconf (paste your wg:// URI, wg-quick INI, or Amnezia config — enables real-keypair verification)
          <textarea class="field mono mt-1" rows="3" bind:value={wgconf}></textarea>
        </label>
        <label class="flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
          <input type="checkbox" bind:checked={verifyWarp} disabled={!wgconf} class="accent-[var(--accent)]" />
          verify with this identity's real keypair
        </label>
      </div>
    {:else if phase2On}
      <div class="mt-4 grid gap-4">
        <label class="text-xs" style="color: var(--ink-muted)">
          Configs to verify through the tunnel (vless/trojan/vmess/ss URIs or subscription URLs, one per line)
          <textarea class="field mono mt-1" rows="3" bind:value={configsText}></textarea>
        </label>
        <div class="grid gap-4 sm:grid-cols-3">
          <label class="text-xs" style="color: var(--ink-muted)">
            DPI fragmentation
            <select class="field mt-1" bind:value={fragment}>
              <option>off</option><option>light</option><option>medium</option><option>heavy</option>
              <option>custom</option>
            </select>
          </label>
          <label class="text-xs sm:col-span-2" style="color: var(--ink-muted)">
            SNI variants (comma-separated, empty = each config's own)
            <input class="field mono mt-1" bind:value={snis} placeholder="front.example.com" />
          </label>
        </div>
        <label class="text-xs" style="color: var(--ink-muted)">
          Probe URL fetched through each tunnel
          <input class="field mono mt-1" bind:value={probeUrl} />
        </label>
      </div>
    {/if}

    {#if mode === "Cdn"}
      <label class="mt-4 flex items-center gap-2 text-xs" style="color: var(--ink-muted)">
        <input type="checkbox" bind:checked={phase2On} class="accent-[var(--accent)]" />
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
