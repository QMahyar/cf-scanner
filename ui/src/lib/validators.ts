/** Line-by-line TypeScript mirror of the server's validation grammar
 * (src/api/types.rs + src/ranges.rs). Single source of truth for the form:
 * buildConfig, the live inline errors and the ranges-import classifier all
 * consume these, so invalid data is caught at entry instead of as a server
 * 400 round-trip — and profile save gates on exactly the same rules as scan
 * start. Bounds mirror the MAX_* constants in api/types.rs. */

export const MAX_SCAN_COUNT = 100_000;
export const MAX_PORTS = 64;
export const MAX_CIDRS = 64;
export const MAX_PHASE2_ENTRIES = 8;
export const MAX_STOP_VALUE = 100_000_000;
export const MAX_CONFIG_ENTRY_BYTES = 8 * 1024;
export const MAX_SNI_BYTES = 256;
export const MAX_PROBE_URL_BYTES = 2 * 1024;
export const MAX_WGCONF_BYTES = 64 * 1024;
export const MAX_ENDPOINTS = 2048;
// WARP sweep cap: the engine silently caps testCount to this (store.svelte.ts
// simpleConfig). Mirrors the server-side sweep bound; surface it in the UI.
export const WARP_SWEEP_CAP = 5000;

export type Verdict<T> = { ok: true; value: T } | { ok: false; message: string };

const IPV4_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const DECIMAL = /^\d+$/;

/** Strict dotted-quad IPv4: four octets 0–255, leading zeros rejected
 * (mirrors Rust's std Ipv4Addr parse). */
export function isIpv4(s: string): boolean {
  const parts = s.split(".");
  return (
    parts.length === 4 &&
    parts.every((p) => p.length > 0 && p.length <= 3 && IPV4_OCTET.test(p))
  );
}

/** Structural IPv6 check (groups of 1–4 hex digits, one `::` compression
 * allowed). The server re-parses strictly; this catches the obvious garbage
 * without reimplementing the full RFC grammar. */
export function isIpv6(s: string): boolean {
  if (!s || !s.includes(":") || /[^0-9a-f:.]/i.test(s)) return false;
  const double = s.match(/::/g);
  if (double && double.length > 1) return false;
  const halves = s.split("::");
  const groups = (part: string) =>
    part === "" ? [] : part.split(":").filter(Boolean);
  const left = groups(halves[0]);
  const right = halves.length > 1 ? groups(halves[1] ?? "") : groups(halves[0]);
  if (halves.length === 1 && left.length !== 8) return false;
  if (halves.length > 1 && left.length + right.length > 7) return false;
  return [...left, ...right].every((g) => /^[0-9a-f]{1,4}$/.test(g));
}

function isIp(s: string): boolean {
  return isIpv4(s) || isIpv6(s);
}

/** Mirror of `parse_endpoint` (api/types.rs): `ip` or `ip:port`, IPv4 only
 * by design, port 1–65535 when present. */
export function parseEndpoint(line: string): Verdict<string> {
  const s = line.trim();
  const colon = s.lastIndexOf(":");
  const host = colon === -1 ? s : s.slice(0, colon);
  const portStr = colon === -1 ? null : s.slice(colon + 1);
  if (host.includes(":")) {
    return { ok: false, message: `${line}: IPv6 is not supported (WARP dials raw IPv4)` };
  }
  if (!isIpv4(host)) {
    return { ok: false, message: `${line}: not an IPv4 address` };
  }
  if (portStr !== null) {
    // Empty port ("1.2.3.4:") must mirror the server's rejection — the
    // fixture pins it as err.
    if (!DECIMAL.test(portStr)) {
      return { ok: false, message: `${line}: port is not a number` };
    }
    const port = Number(portStr);
    if (port < 1 || port > 65535) {
      return { ok: false, message: `${line}: port must be 1–65535` };
    }
  }
  return { ok: true, value: s };
}

/** Mirror of `parse_cidr` (ranges.rs): `addr/prefix`, strict v4 or
 * structural v6, prefix within family bits, v6 /0 rejected (host count
 * exceeds u128 server-side). Returns the canonical `addr/prefix`. */
export function parseCidr(line: string): Verdict<string> {
  const s = line.trim();
  const slash = s.lastIndexOf("/");
  if (slash === -1) {
    return { ok: false, message: `${line}: needs a /prefix (e.g. 1.2.3.0/24)` };
  }
  const addr = s.slice(0, slash);
  const prefixStr = s.slice(slash + 1);
  const v6 = addr.includes(":");
  if (v6 ? !isIpv6(addr) : !isIpv4(addr)) {
    return { ok: false, message: `${line}: invalid address` };
  }
  if (!DECIMAL.test(prefixStr)) {
    return { ok: false, message: `${line}: prefix must be a number` };
  }
  const prefix = Number(prefixStr);
  const bits = v6 ? 128 : 32;
  if (prefix > bits) {
    return { ok: false, message: `${line}: prefix must be ≤${bits}` };
  }
  if (v6 && prefix === 0) {
    return { ok: false, message: `${line}: IPv6 /0 is not supported` };
  }
  return { ok: true, value: s };
}

/** Mirror of `validate_sni` (api/types.rs): a raw IP or an RFC 1035-style
 * hostname (per-label ≤63, total ≤253, alnum + hyphen, no edge hyphens). */
export function validateSni(s: string): Verdict<string> {
  const v = s.trim();
  if (isIp(v)) return { ok: true, value: v };
  if (v.length > 253) return { ok: false, message: `${s}: hostname exceeds 253 characters` };
  const ok =
    v.length > 0 &&
    v.split(".").every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        !label.startsWith("-") &&
        !label.endsWith("-") &&
        /^[a-zA-Z0-9-]+$/.test(label),
    );
  return ok
    ? { ok: true, value: v }
    : { ok: false, message: `${s}: must be a hostname (a-z 0-9 -) or an IP` };
}

/** Mirror of the phase-2 probe-URL rule: non-empty http(s), ≤2048 bytes. */
export function validateProbeUrl(url: string): Verdict<string> {
  const v = url.trim();
  if (!/^https?:\/\//.test(v)) {
    return { ok: false, message: `${url || "(empty)"}: must be an http(s) URL` };
  }
  if (new TextEncoder().encode(v).length > MAX_PROBE_URL_BYTES) {
    return { ok: false, message: `probe URL exceeds ${MAX_PROBE_URL_BYTES} bytes` };
  }
  return { ok: true, value: v };
}

/** Mirror of the server's non-routable guard: loopback, RFC 1918, link-local
 * and unspecified v4 space can never be scan targets. Conservative on
 * purpose — anything borderline is left for the server to decide. */
export function isRoutableIpv4(ip: string): boolean {
  if (!isIpv4(ip)) return true; // v6/other shapes: defer to server rules
  const o = ip.split(".").map(Number);
  const [a, b] = [o[0], o[1]];
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  return true;
}

/** Trim → drop blank lines → dedupe (order preserved). Applied on blur so a
 * pasted bulk list can never leave ghost empty lines behind. */
export function normalizeLines(text: string): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out.join("\n");
}

/** Humanize seconds for ETAs: 59s stays raw, past that 1m 20s / 1h 05m. */
export function humanizeSeconds(total: number): string {
  if (total < 60) return `${total}s`;
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = Math.floor(total % 60);
  return h > 0
    ? `${h}h ${String(m).padStart(2, "0")}m`
    : `${m}m ${String(s).padStart(2, "0")}s`;
}
