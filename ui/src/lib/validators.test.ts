import { describe, expect, it } from "vitest";
import {
  MAX_CIDRS,
  MAX_PORTS,
  MAX_SNI_BYTES,
  isIpv4,
  isIpv6,
  isRoutableIpv4,
  normalizeLines,
  parseCidr,
  parseEndpoint,
  humanizeSeconds,
  validateProbeUrl,
  validateSni,
} from "./validators";

describe("MAX_* mirrors of src/api/types.rs", () => {
  it("keeps the bounds the server enforces", () => {
    // Keep in sync with api/types.rs MAX_*; the grammar fixture pins the
    // grammar, this pins the bounds.
    expect(MAX_PORTS).toBe(64);
    expect(MAX_CIDRS).toBe(64);
    expect(MAX_SNI_BYTES).toBe(256);
  });
});

describe("isIpv4", () => {
  const ok = ["1.2.3.4", "0.0.0.0", "255.255.255.255", "10.0.0.1"];
  const bad = ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "010.1.1.1", "a.b.c.d", "1..2.3"];
  for (const s of ok) it(`accepts ${s}`, () => expect(isIpv4(s)).toBe(true));
  for (const s of bad) it(`rejects ${s || "(empty)"}`, () => expect(isIpv4(s)).toBe(false));
});

describe("isIpv6", () => {
  const ok = ["::1", "2606:4700::", "2001:db8::1", "fe80::1", "1:2:3:4:5:6:7:8"];
  const bad = ["", "1.2.3.4", "::::", "1:2:3:4:5:6:7:8:9", "g::1", "1:2:3:4:5:6:7"];
  for (const s of ok) it(`accepts ${s}`, () => expect(isIpv6(s)).toBe(true));
  for (const s of bad) it(`rejects ${s || "(empty)"}`, () => expect(isIpv6(s)).toBe(false));
});

describe("parseEndpoint (mirror of api/types.rs parse_endpoint)", () => {
  const cases: Array<[string, boolean]> = [
    ["1.2.3.4", true],
    ["1.2.3.4:2408", true],
    ["255.255.255.255:1", true],
    ["1.2.3.4:65535", true],
    [" 1.2.3.4:443 ", true],
    ["1.2.3.4:0", false],
    ["1.2.3.4:65536", false],
    ["1.2.3.4:99999", false],
    ["1.2.3.4:abc", false],
    ["1.2.3.4:-1", false],
    ["1.2.3.4:", false],
    ["::1", false],
    ["bad", false],
    ["010.1.1.1", false],
    ["256.1.1.1", false],
    ["", false],
  ];
  for (const [input, wantOk] of cases) {
    it(`${JSON.stringify(input)} → ${wantOk ? "ok" : "err"}`, () => {
      expect(parseEndpoint(input).ok).toBe(wantOk);
    });
  }
});

describe("parseCidr (mirror of ranges.rs parse_cidr)", () => {
  const cases: Array<[string, boolean]> = [
    ["10.0.0.0/8", true],
    ["1.2.3.4/32", true],
    ["0.0.0.0/0", true],
    ["2606:4700::/32", true],
    ["::1/128", true],
    ["999.1.1.1/24", false],
    ["010.1.1.1/24", false],
    ["1.2.3.4/33", false],
    ["2606:4700::/129", false],
    ["::/0", false],
    ["1.2.3.4", false],
    ["1.2.3.4/abc", false],
    ["1.2.3.4/", false],
    ["1.2.3.4/-1", false],
    ["", false],
  ];
  for (const [input, wantOk] of cases) {
    it(`${JSON.stringify(input)} → ${wantOk ? "ok" : "err"}`, () => {
      expect(parseCidr(input).ok).toBe(wantOk);
    });
  }

  it("returns the canonical trimmed input on success", () => {
    expect(parseCidr(" 1.2.3.0/24 ")).toEqual({ ok: true, value: "1.2.3.0/24" });
  });
});

describe("validateSni (mirror of api/types.rs validate_sni)", () => {
  const cases: Array<[string, boolean]> = [
    ["www.cloudflare.com", true],
    ["a", true],
    ["a-b.c-d.e", true],
    ["1.2.3.4", true],
    ["2606:4700::1111", true],
    ["bad_sni", false],
    ["-lead.example", false],
    ["trailing-.example", false],
    ["a..b", false],
    ["", false],
    ["a.-b.example", false],
  ];
  for (const [input, wantOk] of cases) {
    it(`${JSON.stringify(input)} → ${wantOk ? "ok" : "err"}`, () => {
      expect(validateSni(input).ok).toBe(wantOk);
    });
  }
});

describe("validateProbeUrl", () => {
  it("accepts http and https", () => {
    expect(validateProbeUrl("http://example.com/cdn-cgi/trace").ok).toBe(true);
    expect(validateProbeUrl("https://example.com/cdn-cgi/trace").ok).toBe(true);
  });

  it("rejects non-http schemes and empty input", () => {
    expect(validateProbeUrl("ftp://example.com").ok).toBe(false);
    expect(validateProbeUrl("").ok).toBe(false);
    expect(validateProbeUrl("example.com/trace").ok).toBe(false);
  });
});

describe("isRoutableIpv4 (mirror of the server non-routable guard)", () => {
  const unroutable = [
    "0.1.2.3",
    "10.0.0.1",
    "127.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.1.1",
  ];
  const routable = ["1.1.1.1", "8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1"];
  for (const ip of unroutable) it(`flags ${ip} unroutable`, () => expect(isRoutableIpv4(ip)).toBe(false));
  for (const ip of routable) it(`flags ${ip} routable`, () => expect(isRoutableIpv4(ip)).toBe(true));
});

describe("normalizeLines", () => {
  it("trims, drops blanks, dedupes preserving order", () => {
    expect(normalizeLines("  a \n\nb\na\n b\n")).toBe("a\nb");
  });
  it("handles CRLF input", () => {
    expect(normalizeLines("x\r\ny\r\n")).toBe("x\ny");
  });
});

describe("humanizeSeconds", () => {
  it("keeps sub-minute raw", () => {
    expect(humanizeSeconds(59)).toBe("59s");
  });
  it("formats minutes and hours", () => {
    expect(humanizeSeconds(80)).toBe("1m 20s");
    expect(humanizeSeconds(3900)).toBe("1h 05m");
  });
});
