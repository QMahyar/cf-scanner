import type { Verdict } from "./types";

export type Phase = "candidates" | "verified";
export type SortCol = "latency" | "ip" | "country";

export function keyOf(r: Verdict): string {
  return `${r.ip}:${r.port}`;
}

export const phase2Only = (r: Verdict) => r.phase2 != null;

const DEFAULT_RENDER_CAP = 500;

export interface ResultsViewOptions {
  renderCap?: number;
}

const PHASE_PREDICATE: Record<Phase, (r: Verdict) => boolean> = {
  candidates: () => true,
  verified: phase2Only,
};

function compareLatency(a: number | null, b: number | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a - b;
}

function compareIp(a: string, b: string): number {
  const ao = a.split(".").map(Number);
  const bo = b.split(".").map(Number);
  if (ao.length !== bo.length) return a.localeCompare(b);
  for (let i = 0; i < ao.length; i++) {
    const d = ao[i] - bo[i];
    if (d !== 0) return d;
  }
  return 0;
}

export class ResultsView {
  sortCol = $state<SortCol | null>("latency");
  sortDir = $state<"asc" | "desc">("asc");
  maxLatency = $state<number | null>(null);
  selected = $state(new Set<string>());
  renderLimit = $state(DEFAULT_RENDER_CAP);
  #version = $state(0);

  readonly #source: () => readonly Verdict[];
  readonly #predicate: (r: Verdict) => boolean;
  readonly #renderCap: number;
  #matchedCache: Verdict[] = [];
  #rowsCache: Verdict[] = [];
  #visibleCache: Verdict[] = [];
  #cappedCache = false;
  #cachedVersion = -1;

  constructor(
    source: () => readonly Verdict[],
    phase: Phase,
    opts?: ResultsViewOptions,
  ) {
    this.#source = source;
    this.#predicate = PHASE_PREDICATE[phase];
    this.#renderCap = opts?.renderCap ?? DEFAULT_RENDER_CAP;
    this.renderLimit = this.#renderCap;
    _instances.add(this);
  }

  markDirty(): void {
    this.#version++;
  }

  destroy(): void {
    _instances.delete(this);
  }

  get renderCap(): number {
    return this.#renderCap;
  }

  total = $derived.by(() => this.#source().length);


  get matched(): Verdict[] {
    void this.#version;
    if (this.#cachedVersion !== this.#version) {
      this.#matchedCache = this.#source().filter(
        (r) =>
          this.#predicate(r) &&
          (this.maxLatency === null || (r.latency_ms ?? 9e9) <= this.maxLatency),
      );
      this.#rowsCache =
        this.sortCol === null
          ? [...this.#matchedCache]
          : [...this.#matchedCache].sort((a, b) => this.#compare(a, b));
      this.#visibleCache = this.#rowsCache.slice(0, this.renderLimit);
      this.#cappedCache = this.#rowsCache.length > this.renderLimit;
      this.#cachedVersion = this.#version;
    }
    return this.#matchedCache;
  }

  get rows(): Verdict[] {
    void this.matched;
    return this.#rowsCache;
  }

  get visible(): Verdict[] {
    void this.matched;
    return this.#visibleCache;
  }

  get capped(): boolean {
    void this.matched;
    return this.#cappedCache;
  }

  get picked(): Verdict[] {
    return this.matched.filter((r) => this.selected.has(keyOf(r)));
  }

  get allPicked(): boolean {
    return this.matched.length > 0 && this.picked.length === this.matched.length;
  }

  #compare(a: Verdict, b: Verdict): number {
    const dir = this.sortDir === "asc" ? 1 : -1;
    if (this.sortCol === "ip") return dir * compareIp(a.ip, b.ip);
    if (this.sortCol === "country") {
      const ac = a.country ?? "\uffff";
      const bc = b.country ?? "\uffff";
      return dir * (ac.localeCompare(bc) || (a.colo ?? "").localeCompare(b.colo ?? ""));
    }
    const cmp = compareLatency(a.latency_ms, b.latency_ms);
    return a.latency_ms === null || b.latency_ms === null ? cmp : dir * cmp;
  }

  cycleSort(col: SortCol): void {
    if (this.sortCol !== col) {
      this.sortCol = col;
      this.sortDir = "asc";
    } else if (this.sortDir === "asc") {
      this.sortDir = "desc";
    } else {
      this.sortCol = null;
    }
    this.markDirty();
  }

  setMaxLatency(n: number | null): void {
    this.maxLatency = n;
    this.markDirty();
  }

  toggleRow(r: Verdict, on: boolean): void {
    const next = new Set(this.selected);
    if (on) next.add(keyOf(r));
    else next.delete(keyOf(r));
    this.selected = next;
  }

  setAll(on: boolean): void {
    this.selected = on ? new Set(this.matched.map(keyOf)) : new Set();
  }

  resetSelection(): void {
    this.selected = new Set();
  }
}

const _instances = new Set<ResultsView>();

export function markDirty(): void {
  for (const v of _instances) v.markDirty();
}
