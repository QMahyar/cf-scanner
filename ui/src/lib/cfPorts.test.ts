import { describe, expect, it } from "vitest";
import {
  CDN_HTTPS_PORTS,
  WARP_EXTENDED_PORTS,
  WARP_PRIMARY_PORTS,
} from "./cfPorts";

describe("CDN_HTTPS_PORTS", () => {
  it("matches the curated Cloudflare HTTPS-proxied list", () => {
    expect(CDN_HTTPS_PORTS).toEqual([443, 2053, 2083, 2087, 2096, 8443]);
  });

  it("holds valid port numbers", () => {
    for (const p of CDN_HTTPS_PORTS) {
      expect(p).toBeGreaterThan(0);
      expect(p).toBeLessThanOrEqual(65535);
    }
  });
});

describe("WARP_PRIMARY_PORTS", () => {
  it("matches the WireGuard default + fallbacks", () => {
    expect(WARP_PRIMARY_PORTS).toEqual([2408, 500, 1701, 4500]);
  });
});

describe("WARP_EXTENDED_PORTS", () => {
  it("is sorted ascending and duplicate-free", () => {
    const sorted = [...WARP_EXTENDED_PORTS].sort((a, b) => a - b);
    expect(WARP_EXTENDED_PORTS).toEqual(sorted);
    expect(new Set(WARP_EXTENDED_PORTS).size).toBe(WARP_EXTENDED_PORTS.length);
  });

  it("never overlaps the primary list", () => {
    const primary = new Set(WARP_PRIMARY_PORTS);
    for (const p of WARP_EXTENDED_PORTS) {
      expect(primary.has(p)).toBe(false);
    }
  });

  it("holds valid port numbers", () => {
    for (const p of WARP_EXTENDED_PORTS) {
      expect(p).toBeGreaterThan(0);
      expect(p).toBeLessThanOrEqual(65535);
    }
  });
});
