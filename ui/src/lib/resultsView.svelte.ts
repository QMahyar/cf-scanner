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

  readonly #source: () => readonly Verdict[];
  readonly #predicate: (r: Verdict) => boolean;
  readonly #renderCap: number;

  constructor(
    source: () => readonly Verdict[],
    phase: Phase,
    opts?: ResultsViewOptions,
  ) {
    this.#source = source;
    this.#predicate = PHASE_PREDICATE[phase];
    this.#renderCap = opts?.renderCap ?? DEFAULT_RENDER_CAP;
    this.renderLimit = this.#renderCap;
  }

  get renderCap(): number {
    return this.#renderCap;
  }

  // WHY .by with a thunk: a direct `this.#source()` call in a field
  // initializer trips TS2729 ("used before initialization") under plain-TS
  // checking of .svelte.ts modules; deferring through the arrow is the same
  // derivation, just lazy.
  total = $derived.by(() => this.#source().length);

  matched = $derived.by(() =>
    this.#source().filter(
      (r) =>
        this.#predicate(r) &&
        (this.maxLatency === null || (r.latency_ms ?? 9e9) <= this.maxLatency),
    ),
  );

  rows = $derived.by(() => {
    if (this.sortCol === null) return [...this.matched];
    return [...this.matched].sort((a, b) => this.#compare(a, b));
  });

  visible = $derived(this.rows.slice(0, this.renderLimit));

  capped = $derived(this.rows.length > this.renderLimit);

  picked = $derived(this.matched.filter((r) => this.selected.has(keyOf(r))));

  allPicked = $derived(
    this.matched.length > 0 && this.picked.length === this.matched.length,
  );

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
  }

  setMaxLatency(n: number | null): void {
    this.maxLatency = n;
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
