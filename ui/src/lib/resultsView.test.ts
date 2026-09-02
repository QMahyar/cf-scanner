import { beforeEach, describe, expect, it } from "vitest";
import { ResultsView } from "./resultsView.svelte";
import type { Verdict } from "./types";

function row(ip: string, port: number, latencyMs: number | null, phase2 = false): Verdict {
  return {
    ip,
    port,
    latency_ms: latencyMs,
    country: null,
    colo: null,
    phase2: phase2
      ? {
          passed: true,
          fragment: "off",
          sni: "",
          latency_ms: 12,
          error: null,
          config_index: 0,
          verifier: "inline",
        }
      : null,
  };
}

const FIXTURE: Verdict[] = [
  row("1.1.1.1", 443, 30),
  row("1.1.1.2", 443, 10),
  row("1.1.1.3", 8443, 10),
  row("1.1.1.4", 443, null),
  row("9.9.9.9", 443, 500, true),
  row("9.9.9.10", 443, 5, true),
];

describe("ResultsView semantics (characterization)", () => {
  let view: ResultsView;
  beforeEach(() => {
    view = new ResultsView(() => FIXTURE, "candidates");
  });

  it("totals the unfiltered source", () => {
    expect(view.total).toBe(6);
  });

  it("matched honors the latency cap with the row exactly at the cap kept", () => {
    view.setMaxLatency(10);
    expect(view.matched.map((r) => r.ip).sort()).toEqual(["1.1.1.2", "1.1.1.3", "9.9.9.10"]);
  });

  it("default sort is latency asc with missing latency sunk to the bottom", () => {
    expect(view.rows.map((r) => r.ip)).toEqual([
      "9.9.9.10",
      "1.1.1.2",
      "1.1.1.3",
      "1.1.1.1",
      "9.9.9.9",
      "1.1.1.4",
    ]);
  });

  it("latency sort desc keeps missing latency at the bottom", () => {
    view.cycleSort("latency"); // asc → desc
    expect(view.rows[view.rows.length - 1].ip).toBe("1.1.1.4");
    expect(view.rows[0].ip).toBe("9.9.9.9");
  });

  it("ip sort is octet-wise numeric, not lexical", () => {
    view.cycleSort("ip");
    expect(view.rows.map((r) => r.ip)).toEqual([
      "1.1.1.1",
      "1.1.1.2",
      "1.1.1.3",
      "1.1.1.4",
      "9.9.9.9",
      "9.9.9.10",
    ]);
  });

  it("tri-state cycle returns to engine order", () => {
    view.cycleSort("latency"); // desc
    view.cycleSort("latency"); // null (engine order)
    expect(view.sortCol).toBe(null);
    expect(view.rows.map((r) => r.ip)).toEqual(FIXTURE.map((r) => r.ip));
  });

  it("verified phase filters to phase2 rows only", () => {
    const verified = new ResultsView(() => FIXTURE, "verified");
    // total is the raw source length by design; matched applies the predicate.
    expect(verified.total).toBe(FIXTURE.length);
    expect(verified.matched.length).toBe(2);
    expect(verified.matched.every((r) => r.phase2 != null)).toBe(true);
  });

  it("selection round-trips by ip:port key", () => {
    view.toggleRow(FIXTURE[0], true);
    view.toggleRow(FIXTURE[1], true);
    expect(view.picked.map((r) => r.ip)).toEqual(["1.1.1.1", "1.1.1.2"]);
    expect(view.allPicked).toBe(false);
    view.setAll(true);
    expect(view.allPicked).toBe(true);
    view.resetSelection();
    expect(view.picked).toEqual([]);
  });

  it("visible respects the render cap and reports capping", () => {
    const many: Verdict[] = Array.from({ length: 1200 }, (_, i) =>
      row(`10.0.${Math.floor(i / 256)}.${i % 256}`, 443, i),
    );
    const capped = new ResultsView(() => many, "candidates");
    expect(capped.visible.length).toBe(500);
    expect(capped.capped).toBe(true);
    expect(capped.renderCap).toBe(500);
  });

  it("show-more (renderLimit bump + markDirty) reveals fresh rows", () => {
    const many: Verdict[] = Array.from({ length: 1200 }, (_, i) =>
      row(`10.0.${Math.floor(i / 256)}.${i % 256}`, 443, i),
    );
    const capped = new ResultsView(() => many, "candidates");
    expect(capped.visible.length).toBe(500);
    capped.renderLimit += capped.renderCap;
    capped.markDirty();
    expect(capped.visible.length).toBe(1000);
    expect(capped.visible.at(-1)).toBe(many[999]);
    expect(capped.capped).toBe(true);
    capped.renderLimit += capped.renderCap;
    capped.markDirty();
    expect(capped.visible.length).toBe(1200);
    expect(capped.capped).toBe(false);
  });
});
