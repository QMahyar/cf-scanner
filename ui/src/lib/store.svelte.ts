import type { ScanConfig, ScanSummary, Verdict } from "./types";

export interface UiState {
  running: boolean;
  progress: { scanned: number; found: number; total: number | null };
  phase2: { done: number; total: number } | null;
  results: Verdict[];
  summary: (ScanSummary & { is_running?: boolean }) | null;
  error: string | null;
  proMode: boolean;
}

const app = $state<UiState>({
  running: false,
  progress: { scanned: 0, found: 0, total: null },
  phase2: null,
  results: [],
  summary: null,
  error: null,
  proMode: localStorage.getItem("cf-pro-mode") === "1",
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
}

/** Default simple-mode config: best defaults for a first-run user. */
export function simpleConfig(): ScanConfig {
  return {
    mode: "Cdn",
    target: { Preset: "Quick" },
    ports: [443],
    stop: { found: 10, cap: null },
    exclude: [],
    custom_cidrs: [],
    concurrency: 128,
    timeout_ms: 2000,
    phase2: null,
    warp: null,
  };
}
