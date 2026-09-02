
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
export const WARP_SWEEP_CAP = 5000;

export type Verdict<T> = { ok: true; value: T } | { ok: false; message: string };

const IPV4_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const DECIMAL = /^\+?\d+$/;

export function isIpv4(s: string): boolean {
  const parts = s.split(".");
  return (
    parts.length === 4 &&
    parts.every((p) => p.length > 0 && p.length <= 3 && IPV4_OCTET.test(p))
  );
}

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

export function parseEndpoint(line: string): Verdict<string> {
  const s = line.trim();
  const colon = s.lastIndexOf(":");
  const host = (colon === -1 ? s : s.slice(0, colon)).trim();
  const portStr = colon === -1 ? null : s.slice(colon + 1).trim();
  if (host.includes(":")) {
    return { ok: false, message: `${line}: IPv6 is not supported (WARP dials raw IPv4)` };
  }
  if (!isIpv4(host)) {
    return { ok: false, message: `${line}: not an IPv4 address` };
  }
  if (portStr !== null) {
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

export function parseCidr(line: string): Verdict<string> {
  const s = line.trim();
  const slash = s.lastIndexOf("/");
  if (slash === -1) {
    return { ok: false, message: `${line}: needs a /prefix (e.g. 1.2.3.0/24)` };
  }
  const addr = s.slice(0, slash).trim();
  const prefixStr = s.slice(slash + 1).trim();
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

export function validateSni(s: string): Verdict<string> {
  if (isIp(s)) return { ok: true, value: s };
  if (s.length > 253) return { ok: false, message: `${s}: hostname exceeds 253 characters` };
  const ok =
    s.length > 0 &&
    s.split(".").every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        !label.startsWith("-") &&
        !label.endsWith("-") &&
        /^[a-zA-Z0-9-]+$/.test(label),
    );
  return ok
    ? { ok: true, value: s }
    : { ok: false, message: `${s}: must be a hostname (a-z 0-9 -) or an IP` };
}

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

export function isRoutableIpv4(ip: string): boolean {
  if (!isIpv4(ip)) return true;
  const o = ip.split(".").map(Number);
  const [a, b] = [o[0], o[1]];
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  return true;
}

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

export function humanizeSeconds(total: number): string {
  if (total < 60) return `${total}s`;
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = Math.floor(total % 60);
  return h > 0
    ? `${h}h ${String(m).padStart(2, "0")}m`
    : `${m}m ${String(s).padStart(2, "0")}s`;
}
