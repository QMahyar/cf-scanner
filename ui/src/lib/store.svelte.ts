import { ApiError, api } from "./api";
import { t } from "./i18n.svelte";
import { markDirty, phase2Only } from "./resultsView.svelte";
import type { Mode, ScanConfig, ScanSummary, Verdict } from "./types";
import { WARP_SWEEP_CAP } from "./validators";

export interface UiState {
  running: boolean;
  startedAt: number | null;
  progress: { scanned: number; found: number; total: number | null };
  phase2: { done: number; total: number } | null;
  results: Verdict[];
  summary: ScanSummary | null;
  error: string | null;
  proMode: boolean;
  lastScanConfigs: string[];
  lastScanVerified: boolean;
  frozenPhase1: Verdict[] | null;
  statusHasCandidates: boolean;
}

function readProMode(): boolean {
  try {
    return localStorage.getItem("cf-pro-mode") === "1";
  } catch {
    return false;
  }
}

function initialState(): UiState {
  return {
    running: false,
    startedAt: null,
    progress: { scanned: 0, found: 0, total: null },
    phase2: null,
    results: [],
    summary: null,
    error: null,
    proMode: readProMode(),
    lastScanConfigs: [],
    lastScanVerified: false,
    frozenPhase1: null,
    statusHasCandidates: false,
  };
}

export class UiStore {
  state = $state<UiState>(initialState());
  #index = new Map<string, number>();
  #tickWindow: { scanned: number; found: number }[] = [];

  ui(): UiState {
    return this.state;
  }

  setProMode(on: boolean): void {
    this.state.proMode = on;
    try {
      localStorage.setItem("cf-pro-mode", on ? "1" : "0");
    } catch {
    }
  }

  applyResult(verdict: Verdict): void {
    const key = `${verdict.ip}:${verdict.port}`;
    const idx = this.#index.get(key);
    if (idx !== undefined) {
      this.state.results[idx] = verdict;
    } else {
      this.#index.set(key, this.state.results.length);
      this.state.results.push(verdict);
    }
    markDirty();
  }

  setResults(rows: Verdict[]): void {
    this.#index.clear();
    for (let i = 0; i < rows.length; i++) this.#index.set(`${rows[i].ip}:${rows[i].port}`, i);
    this.state.results = rows;
    markDirty();
  }

  resetResults(): void {
    this.#index.clear();
    this.state.results = [];
    this.state.summary = null;
    this.state.progress = { scanned: 0, found: 0, total: null };
    this.state.phase2 = null;
    this.state.error = null;
    this.state.startedAt = null;
    this.state.lastScanConfigs = [];
    this.state.lastScanVerified = false;
    this.state.frozenPhase1 = null;
    this.resetTicks();
    markDirty();
  }

  recordTick(p: { scanned: number; found: number }): void {
    const last = this.#tickWindow[this.#tickWindow.length - 1];
    if (last && p.scanned < last.scanned) this.#tickWindow.length = 0;
    this.#tickWindow.push({ scanned: p.scanned, found: p.found });
    while (this.#tickWindow.length > 2 && p.scanned - this.#tickWindow[0].scanned > 500)
      this.#tickWindow.shift();
  }

  resetTicks(): void {
    this.#tickWindow.length = 0;
  }

  lowYieldWindow(minFound = 12, floor = 0.03): boolean | null {
    if (this.#tickWindow.length < 2) return null;
    const first = this.#tickWindow[0];
    const lastTick = this.#tickWindow[this.#tickWindow.length - 1];
    const dScanned = lastTick.scanned - first.scanned;
    if (dScanned < 100) return null;
    const dFound = lastTick.found - first.found;
    return lastTick.found >= minFound && dFound / dScanned < floor;
  }

  allCandidates(): readonly Verdict[] {
    return this.state.results;
  }

  verifiedOnly(): Verdict[] {
    return this.state.results.filter(phase2Only);
  }

  hasCandidates(): boolean {
    return this.state.results.length > 0 || this.state.statusHasCandidates;
  }

  async startScan(cfg: ScanConfig, opts?: { preserveResults?: boolean }): Promise<StartOutcome> {
    const preserve = opts?.preserveResults === true && cfg.phase2_only === true;
    if (preserve) this.state.frozenPhase1 = this.state.results.slice();
    try {
      await api.scan(cfg);
      if (!preserve) this.resetResults();
      this.state.lastScanConfigs = cfg.phase2?.configs ?? [];
      this.state.lastScanVerified = cfg.mode === "Warp" && cfg.warp?.verify_with_wgconf === true;
      this.state.running = true;
      this.state.startedAt = Date.now();
      return { ok: true, rejected: null };
    } catch (e) {
      this.state.error = errorText(e);
      const rejected =
        e instanceof ApiError && (e.status === 400 || e.status === 422)
          ? { status: e.status, detail: e.detail || e.message }
          : null;
      return { ok: false, rejected };
    }
  }

  async stopScan(): Promise<void> {
    try {
      await api.cancel();
    } catch (e) {
      this.state.error = errorText(e);
    }
  }
}

const _store = new UiStore();

export function ui(): UiState {
  return _store.ui();
}

export function setProMode(on: boolean): void {
  return _store.setProMode(on);
}

export function applyResult(verdict: Verdict): void {
  return _store.applyResult(verdict);
}

export function setResults(rows: Verdict[]): void {
  return _store.setResults(rows);
}

export function resetResults(): void {
  return _store.resetResults();
}

export function recordTick(p: { scanned: number; found: number }): void {
  return _store.recordTick(p);
}

export function resetTicks(): void {
  return _store.resetTicks();
}

export function lowYieldWindow(minFound = 12, floor = 0.03): boolean | null {
  return _store.lowYieldWindow(minFound, floor);
}

export function allCandidates(): readonly Verdict[] {
  return _store.allCandidates();
}

export function verifiedOnly(): Verdict[] {
  return _store.verifiedOnly();
}

export function hasCandidates(): boolean {
  return _store.hasCandidates();
}

export function errorText(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/failed to fetch|networkerror|load failed|fetch failed/i.test(msg)) {
    return `${msg} — ${t("error.networkHint")}`;
  }
  return msg;
}

export interface StartOutcome {
  ok: boolean;
  rejected: { status: number; detail: string } | null;
}

export async function startScan(
  cfg: ScanConfig,
  opts?: { preserveResults?: boolean },
): Promise<StartOutcome> {
  return _store.startScan(cfg, opts);
}

export async function stopScan(): Promise<void> {
  return _store.stopScan();
}

export function simpleConfig(
  found = 20,
  mode: Mode = "Cdn",
  testCount = 800,
): ScanConfig {
  if (mode === "Warp") {
    return {
      mode: "Warp",
      target: { Count: Math.min(testCount, WARP_SWEEP_CAP) },
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
  }
  const file = new File([text], filename, { type: "text/plain" });
  if (navigator.canShare?.({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: filename });
      return "share";
    } catch (e) {
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

export function downloadFile(text: string, filename: string, mime = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
}
