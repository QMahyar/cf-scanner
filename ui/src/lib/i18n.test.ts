import { describe, expect, it } from "vitest";
import { dictionaries } from "./i18n.svelte";

describe("i18n en/fa parity", () => {
  it("fa carries exactly the en keys (no dead keys, no gaps)", () => {
    const { en, fa } = dictionaries();
    expect(Object.keys(fa).sort()).toEqual(Object.keys(en).sort());
  });

  it("every interpolation slot in an en template exists in its fa twin", () => {
    const { en, fa } = dictionaries();
    for (const [key, template] of Object.entries(en)) {
      const slots = [...template.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
      const faSlots = [...fa[key].matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
      expect(faSlots, `key ${key} must have identical slots in fa`).toEqual(slots);
    }
  });

  it("no template carries mangled placeholder syntax", () => {
    const { en } = dictionaries();
    for (const [key, template] of Object.entries(en)) {
      expect(template.includes("{{"), `${key} has '{{'`).toBe(false);
      expect(template.includes("}{"), `${key} has '}{ '`).toBe(false);
    }
  });
});
