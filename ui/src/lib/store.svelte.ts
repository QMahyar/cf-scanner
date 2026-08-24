import { ApiError, api } from "./api";
import type { Mode, ScanConfig, ScanSummary, Verdict } from "./types";

export interface UiState {
  running: boolean;
  startedAt: number | null;
  progress: { scanned: number; found: number; total: number | null };
  phase2: { done: number; total: number } | null;
  results: Verdict[];
  summary: ScanSummary | null;
  error: string | null;
  proMode: boolean;
  /** Original phase-2 config URIs from the last started scan, indexed by
   * Verdict.config_index; lets result rows export importable URIs. */
  lastScanConfigs: string[];
  /** True when the last WARP scan probed under the user's real keypair
   * (verify_with_wgconf) — results are then labeled as verified. */
  lastScanVerified: boolean;
}

const app = $state<UiState>({
  running: false,
  startedAt: null,
  progress: { scanned: 0, found: 0, total: null },
  phase2: null,
  results: [],
  summary: null,
  error: null,
  proMode: localStorage.getItem("cf-pro-mode") === "1",
  lastScanConfigs: [],
  lastScanVerified: false,
});

export function ui(): UiState {
  return app;
}

export function setProMode(on: boolean) {
  app.proMode = on;
  localStorage.setItem("cf-pro-mode", on ? "1" : "0");
}

export function applyResult(verdict: Verdict) {
  const key = `${verdict.ip}:${verdict.port}`;
  const idx = app.results.findIndex((r) => `${r.ip}:${r.port}` === key);
  if (idx >= 0) app.results[idx] = verdict;
  else app.results.push(verdict);
}

export function resetResults() {
  app.results = [];
  app.summary = null;
  app.progress = { scanned: 0, found: 0, total: null };
  app.phase2 = null;
  app.error = null;
  app.startedAt = null;
  app.lastScanConfigs = [];
  app.lastScanVerified = false;
  resetTicks();
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** The one place a scan starts: resets last-scan results, POSTs the config,
 * flips the running flag, and surfaces failures — callers never duplicate
 * that sequence. Never throws; check ui().error, and use the returned
 * rejection to route 400/422 messages into per-field errors. */
export interface StartOutcome {
  ok: boolean;
  /** Set when the POST was rejected with a status the UI can map to fields. */
  rejected: { status: number; detail: string } | null;
}

export async function startScan(cfg: ScanConfig): Promise<StartOutcome> {
  resetResults();
  app.lastScanConfigs = cfg.phase2?.configs ?? [];
  app.lastScanVerified = cfg.mode === "Warp" && cfg.warp?.verify_with_wgconf === true;
  try {
    await api.scan(cfg);
    app.running = true;
    app.startedAt = Date.now();
    return { ok: true, rejected: null };
  } catch (e) {
    app.error = errorText(e);
    const rejected =
      e instanceof ApiError && (e.status === 400 || e.status === 422)
        ? { status: e.status, detail: e.detail || e.message }
        : null;
    return { ok: false, rejected };
  }
}

export async function stopScan() {
  try {
    await api.cancel();
  } catch (e) {
    app.error = errorText(e);
  }
}

/** Rolling window over phase-1 progress ticks, kept long enough to span
 * ~500 probes — the evidence base for the skip-to-phase-2 suggestion
 * (research §9: survivors ≥ threshold AND sliding success rate < floor). */
const tickWindow: { scanned: number; found: number }[] = [];

export function recordTick(p: { scanned: number; found: number }): void {
  const last = tickWindow[tickWindow.length - 1];
  // Progress ticks can repeat/reset between runs; only monotonic growth is
  // meaningful evidence.
  if (last && p.scanned < last.scanned) tickWindow.length = 0;
  tickWindow.push({ scanned: p.scanned, found: p.found });
  while (tickWindow.length > 2 && last.scanned - tickWindow[0].scanned > 500)
    tickWindow.shift();
}

export function resetTicks(): void {
  tickWindow.length = 0;
}

/** True when the recent window shows diminishing returns worth escaping:
 * enough survivors banked (≥ minFound) and a hit rate below `floor` over
 * ≥100 probes of evidence. Null = not enough data to judge. */
export function lowYieldWindow(minFound = 12, floor = 0.03): boolean | null {
  if (tickWindow.length < 2) return null;
  const first = tickWindow[0];
  const lastTick = tickWindow[tickWindow.length - 1];
  const dScanned = lastTick.scanned - first.scanned;
  if (dScanned < 100) return null;
  const dFound = lastTick.found - first.found;
  return lastTick.found >= minFound && dFound / dScanned < floor;
}

/** Default simple-mode configs: best defaults for a first-run user, per the
 * 2026-08-23 research synthesis (docs/research/2026-08-23-ui-v2-research.md):
 * CDN probes a random sample of `testCount` candidates on 443 (400–800 band
 * avoids tripping ISP/CF scan limits while surfacing hits fast); WARP sweeps
 * the official WireGuard ports over a small bounded candidate count. Stop
 * target default 20 follows the dominant competitor precedent (N=10 family,
 * midpoint of common asks). */
export function simpleConfig(
  found = 20,
  mode: Mode = "Cdn",
  testCount = 800,
): ScanConfig {
  if (mode === "Warp") {
    return {
      mode: "Warp",
      target: { Count: Math.min(testCount, 5000) },
      ports: [2408, 500, 1701, 4500],
      stop: { found, cap: null },
      exclude: [],
      custom_cidrs: [],
      concurrency: 128,
      timeout_ms: 2000,
      phase2: null,
      warp: {
        custom_endpoints: [],
        probes_per_endpoint: 3,
        wgconf: null,
        verify_with_wgconf: false,
      },
    };
  }
  return {
    mode: "Cdn",
    target: { Count: testCount },
    ports: [443],
    stop: { found, cap: null },
    exclude: [],
    custom_cidrs: [],
    concurrency: 128,
    timeout_ms: 2000,
    phase2: null,
    warp: null,
  };
}

/** Export chain from research §7: clipboard first (localhost is a secure
 * context), then the mobile share sheet when present, then an unconditional
 * Blob .txt download as the final fallback. Returns how it resolved so the
 * caller can show honest feedback. */

/** Shared result filter used by ResultsTable and SimpleStart so Copy-all
 * respects the same active latency filter. Filter lives here, not inside a
 * single view, so both UIs stay in sync without prop drilling. */
const sharedFilter = $state<{ maxLatency: number | null }>({ maxLatency: null });
export function resultFilter(): { maxLatency: number | null } {
  return sharedFilter;
}

export function filteredEndpoints(results: Verdict[], maxLatency: number | null): string {
  return results
    .filter((r) => maxLatency === null || (r.latency_ms ?? 9e9) <= maxLatency)
    .map((r) => `${r.ip}:${r.port}`)
    .join("\n");
}
export type ExportHow = "clipboard" | "share" | "download";

export async function exportText(text: string, filename: string): Promise<ExportHow> {
  try {
    await navigator.clipboard.writeText(text);
    return "clipboard";
  } catch {
    /* fall through to share/download */
  }
  const file = new File([text], filename, { type: "text/plain" });
  if (navigator.canShare?.({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: filename });
      return "share";
    } catch (e) {
      // User-cancelled shares must not silently degrade into a download.
      if (e instanceof DOMException && e.name === "AbortError") return "share";
    }
  }
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
  return "download";
}
