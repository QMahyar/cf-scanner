import { ApiError, api } from "./api";
import type { ScanConfig, ScanSummary, Verdict } from "./types";

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
  await api.cancel();
}

/** Default simple-mode config: best defaults for a first-run user. */
export function simpleConfig(found = 10): ScanConfig {
  return {
    mode: "Cdn",
    target: { Preset: "Quick" },
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
