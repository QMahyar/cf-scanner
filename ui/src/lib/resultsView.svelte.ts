import type { Verdict } from "./types";

export type Phase = "candidates" | "verified";
export type SortCol = "latency" | "ip";

export function keyOf(r: Verdict): string {
  return `${r.ip}:${r.port}`;
}

export const phase2Only = (r: Verdict) => r.phase2 != null;

const DEFAULT_RENDER_CAP = 500;

export interface ResultsViewOptions {
  /** Overrides the default render cap; ResultsTable keeps owning its
   * RENDER_CAP constant and passes it in. */
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

/** Octet-wise numeric IP order (10.0.0.2 < 10.0.0.10); localeCompare would
 * put 10.0.0.10 before 10.0.0.2. */
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

/** One column's view over app.results: phase predicate + latency cap +
 * tri-state sort + row selection + render cap, all runes-based so instances
 * stay reactive wherever they're read. Selection mutations replace the Set
 * whole — $state does not track in-place Set mutation. */
export class ResultsView {
  /** Active sort column; null = engine order (tri-state). */
  sortCol = $state<SortCol | null>("latency");
  sortDir = $state<"asc" | "desc">("asc");
  maxLatency = $state<number | null>(null);
  selected = $state(new Set<string>());
  renderLimit = $state(DEFAULT_RENDER_CAP);
  #dirty = $state(true);

  readonly #source: () => readonly Verdict[];
  readonly #predicate: (r: Verdict) => boolean;
  readonly #renderCap: number;
  #matchedCache: Verdict[] = [];
  #rowsCache: Verdict[] = [];
  #visibleCache: Verdict[] = [];
  #cappedCache = false;

  constructor(
    source: () => readonly Verdict[],
    phase: Phase,
    opts?: ResultsViewOptions,
  ) {
    this.#source = source;
    this.#predicate = PHASE_PREDICATE[phase];
    this.#renderCap = opts?.renderCap ?? DEFAULT_RENDER_CAP;
    this.renderLimit = this.#renderCap;
    // Eagerly populate caches so the instance is valid before the first
    // dirty cycle — avoids stale reads when the module-level flag is
    // already false (e.g. a second ResultsView in the same test suite).
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
    this.#dirty = false;
    _instances.add(this);
  }

  markDirty(): void {
    this.#dirty = true;
  }

  get renderCap(): number {
    return this.#renderCap;
  }

  // total is cheap and drives component skeleton/empty-state switching —
  // keep it $derived so the component re-renders when items arrive.
  total = $derived.by(() => this.#source().length);

  // Lazy cached fields: recomputed only when #dirty is set. Avoids O(n)
  // filter+sort on every applyResult tick during live scans.

  get matched(): Verdict[] {
    if (this.#dirty) {
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
      this.#dirty = false;
    }
    return this.#matchedCache;
  }

  get rows(): Verdict[] {
    // Recomputed together with matched above.
    if (this.#dirty) void this.matched;
    return this.#rowsCache;
  }

  get visible(): Verdict[] {
    if (this.#dirty) void this.matched;
    return this.#visibleCache;
  }

  get capped(): boolean {
    if (this.#dirty) void this.matched;
    return this.#cappedCache;
  }

  // picked/allPicked depend on selection ($state), not on data mutations,
  // so they recompute on every read — cheap Set lookup over matched.
  get picked(): Verdict[] {
    return this.matched.filter((r) => this.selected.has(keyOf(r)));
  }

  get allPicked(): boolean {
    return this.matched.length > 0 && this.picked.length === this.matched.length;
  }

  #compare(a: Verdict, b: Verdict): number {
    const dir = this.sortDir === "asc" ? 1 : -1;
    if (this.sortCol === "ip") return dir * compareIp(a.ip, b.ip);
    const cmp = compareLatency(a.latency_ms, b.latency_ms);
    // Missing latency sinks to the bottom whichever way the sort runs.
    return a.latency_ms === null || b.latency_ms === null ? cmp : dir * cmp;
  }

  /** Tri-state per research §7: asc → desc → scan order. */
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
