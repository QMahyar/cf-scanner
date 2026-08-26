import { describe, expect, it } from "vitest";
import grammarCases from "../../../tests/fixtures/grammar-cases.json";
import { parseCidr, parseEndpoint, validateSni } from "./validators";

type Kind = (typeof grammarCases)[number]["kind"];
type Case = { kind: Kind; input: string; expect: "ok" | "err" };

const RUNNERS: Record<Kind, (s: string) => { ok: boolean }> = {
  cidr: (s) => parseCidr(s),
  endpoint: (s) => parseEndpoint(s),
  sni: (s) => validateSni(s),
};

describe("grammar parity with tests/fixtures/grammar-cases.json", () => {
  // The fixture is the shared contract between the Rust validators
  // (src/api/types.rs, src/ranges.rs) and this TS mirror. Every case must
  // land the same way on both sides.
  for (const c of grammarCases as Case[]) {
    it(`${c.kind}: ${JSON.stringify(c.input)} → ${c.expect}`, () => {
      const runner = RUNNERS[c.kind];
      expect(runner, `no runner for kind ${c.kind}`).toBeDefined();
      expect(runner(c.input).ok).toBe(c.expect === "ok");
    });
  }

  it("fixture covers every kind this mirror implements", () => {
    const kinds = new Set((grammarCases as Case[]).map((c) => c.kind));
    for (const kind of Object.keys(RUNNERS) as Kind[]) {
      expect(kinds.has(kind), `fixture missing cases for kind ${kind}`).toBe(true);
    }
  });
});
