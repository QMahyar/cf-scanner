import { describe, expect, it } from "vitest";
import { gen } from "./qr";

describe("qr encoder invariants", () => {
  it("encodes a short URI at the smallest version with a square module grid", () => {
    const q = gen("vless://id@example.com:443");
    expect(q).not.toBeNull();
    expect(q!.size).toBeGreaterThanOrEqual(21);
    expect(q!.size).toBeLessThanOrEqual(29);
    expect(q!.modules.length).toBe(q!.size);
    for (const row of q!.modules) expect(row.length).toBe(q!.size);
  });

  it("encodes an empty string without crashing", () => {
    expect(gen("")).not.toBeNull();
  });

  it("scales the version with payload size (larger input, larger or equal grid)", () => {
    const small = gen("a".repeat(10))!;
    const big = gen("a".repeat(500))!;
    expect(big.size).toBeGreaterThan(small.size);
  });

  it("returns null for payloads beyond v25 byte capacity", () => {
    expect(gen("a".repeat(5000))).toBeNull();
  });

  it("is deterministic for the same input", () => {
    const a = gen("vless://x@1.2.3.4:443");
    const b = gen("vless://x@1.2.3.4:443");
    expect(a).toEqual(b);
  });
});
