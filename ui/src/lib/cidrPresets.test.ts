import { describe, expect, it } from "vitest";
import { EXCLUDE_WARP_INGRESS } from "./cidrPresets";
import { parseCidr } from "./validators";

describe("EXCLUDE_WARP_INGRESS", () => {
  it("contains only CIDRs that pass the shared grammar", () => {
    for (const cidr of EXCLUDE_WARP_INGRESS) {
      expect(parseCidr(cidr)).toMatchObject({ ok: true, value: cidr });
    }
  });

  it("is duplicate-free", () => {
    expect(new Set(EXCLUDE_WARP_INGRESS).size).toBe(EXCLUDE_WARP_INGRESS.length);
  });
});
