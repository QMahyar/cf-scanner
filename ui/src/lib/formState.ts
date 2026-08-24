import type { CdnPreset, FragmentPreset, FragmentWire, Mode, ScanConfig } from "./types";

/** PascalCase wire value → lowercase form value; unknown/legacy values fall
 * back to the form default so a profile saved by any version still loads. */
function fragmentFromWire(wire: string | undefined): FragmentPreset {
  const lower = (wire ?? "").toLowerCase();
  return ["off", "light", "medium", "heavy", "custom"].includes(lower)
    ? (lower as FragmentPreset)
    : "off";
}

import {
  CDN_HTTPS_PORTS,
  WARP_EXTENDED_PORTS,
  WARP_PRIMARY_PORTS,
} from "./cfPorts";
import {
  MAX_CIDRS,
  MAX_CONFIG_ENTRY_BYTES,
  MAX_PHASE2_ENTRIES,
  MAX_PORTS,
  MAX_SNI_BYTES,
  MAX_SCAN_COUNT,
  MAX_STOP_VALUE,
  MAX_WGCONF_BYTES,
  isRoutableIpv4,
  parseCidr,
  parseEndpoint,
  validateProbeUrl,
  validateSni,
} from "./validators";

/** Everything the Pro panel can set, exactly as the user typed it.
 * Ports are a checkbox selection from the curated Cloudflare catalogs plus a
 * free-text custom field; buildConfig merges and validates both at start
 * time. Text fields stay text so "cleared" is representable (e.g. capText ""
 * = no hard cap). */
export interface FormState {
  mode: Mode;
  preset: CdnPreset;
  count: number;
  useCount: boolean;
  selectedPorts: number[];
  customPortsText: string;
  concurrency: number;
  timeoutMs: number;
  includeV6: boolean;
  stopFound: number;
  capText: string;
  customCidrs: string;
  exclude: string;
  phase2On: boolean;
  configsText: string;
  fragment: FragmentPreset;
  snis: string;
  probeUrl: string;
  warpProbes: number;
  warpEndpoints: string;
  wgconf: string;
  verifyWarp: boolean;
}

/** Ports offered as chips for a mode: the official catalog first, then the
 * community-verified extended WARP list behind a disclosure. */
export function portCatalog(mode: Mode): { primary: number[]; extended: number[] } {
  return mode === "Warp"
    ? { primary: WARP_PRIMARY_PORTS, extended: WARP_EXTENDED_PORTS }
    : { primary: CDN_HTTPS_PORTS, extended: [] };
}

/** Mode's default checked chips; exported so the panel can re-default the
 * selection when the user flips CDN ↔ WARP mid-form. WARP defaults to the
 * whole catalog (primary + extended) — WireGuard answers on any of them, so
 * a first WARP scan should sweep everything known; CDN stays conservative
 * on 443 only. */
export function defaultSelectedPorts(mode: Mode): number[] {
  return mode === "Warp"
    ? [...WARP_PRIMARY_PORTS, ...WARP_EXTENDED_PORTS]
    : [443];
}

/** Pro panel defaults; simple mode keeps its own in simpleConfig(). */
export function defaultFormState(): FormState {
  return {
    mode: "Cdn",
    preset: "Quick",
    count: 350,
    useCount: false,
    selectedPorts: defaultSelectedPorts("Cdn"),
    customPortsText: "",
    concurrency: 128,
    timeoutMs: 2000,
    includeV6: false,
    stopFound: 20,
    capText: "",
    customCidrs: "",
    exclude: "",
    phase2On: false,
    configsText: "",
    fragment: "off",
    snis: "",
    probeUrl: "https://www.cloudflare.com/cdn-cgi/trace",
    warpProbes: 3,
    warpEndpoints: "",
    wgconf: "",
    verifyWarp: false,
  };
}

/** Pure ScanConfig → FormState: inverse of buildConfig for every field it
 * owns, so loading a profile reproduces the exact inputs that built it
 * (ports/cidrs rejoin lines or commas, cap "" = none, Count target flips
 * useCount). Server-unmappable extras (probe_urls, custom_fragment,
 * phase-2 concurrency) fall back to defaults since the form cannot edit
 * them. */
export function formStateFromConfig(cfg: ScanConfig): FormState {
  const d = defaultFormState();
  const catalog = portCatalog(cfg.mode);
  const known = new Set([...catalog.primary, ...catalog.extended]);
  const selected = cfg.ports.filter((p) => known.has(p));
  const custom = cfg.ports.filter((p) => !known.has(p));
  return {
    mode: cfg.mode,
    preset: !("Count" in cfg.target) ? cfg.target.Preset : d.preset,
    count: "Count" in cfg.target ? cfg.target.Count : d.count,
    useCount: "Count" in cfg.target,
    // A profile whose ports are all unknown to the current catalog keeps at
    // least the mode default checked, so the form never renders zero chips.
    selectedPorts: selected.length > 0 ? selected : d.selectedPorts,
    customPortsText: custom.join(", "),
    concurrency: cfg.concurrency,
    timeoutMs: cfg.timeout_ms,
    includeV6: cfg.include_v6 ?? false,
    stopFound: cfg.stop.found,
    capText: cfg.stop.cap === null ? "" : String(cfg.stop.cap),
    customCidrs: cfg.custom_cidrs.join("\n"),
    exclude: cfg.exclude.join("\n"),
    phase2On: cfg.mode === "Cdn" && !!cfg.phase2,
    configsText: cfg.phase2?.configs.join("\n") ?? "",
    fragment: fragmentFromWire(cfg.phase2?.fragment),
    snis: cfg.phase2?.snis.join(", ") ?? "",
    probeUrl: cfg.phase2?.probe_url || d.probeUrl,
    warpProbes: cfg.warp?.probes_per_endpoint ?? d.warpProbes,
    warpEndpoints: cfg.warp?.custom_endpoints.join("\n") ?? "",
    wgconf: cfg.warp?.wgconf ?? "",
    verifyWarp: cfg.warp?.verify_with_wgconf ?? false,
  };
}

export type FormField = keyof FormState;

/** One validation problem: which FormState key failed (null = form-wide) and
 * what to tell the user. The field key lets the UI light up the exact input. */
export interface FieldIssue {
  field: FormField | null;
  message: string;
}

export class FormValidationError extends Error {
  readonly issues: FieldIssue[];

  constructor(issues: FieldIssue[]) {
    super(issues.map((i) => i.message).join(" · "));
    this.name = "FormValidationError";
    this.issues = issues;
  }

  /** Flat messages for click-time summary lists. */
  get errors(): string[] {
    return this.issues.map((i) => i.message);
  }
}

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function csv(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function wholeNumber(
  value: unknown,
  label: string,
  min: number,
  max: number,
  field: FormField,
  issues: FieldIssue[],
): number {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n < min) {
    issues.push({ field, message: `${label}: enter a whole number ≥ ${min}` });
    return min;
  }
  if (n > max) {
    issues.push({ field, message: `${label}: maximum is ${max.toLocaleString("en-US")}` });
    return max;
  }
  return n;
}

/** Per-line syntax checks for the free-text list fields, mirroring the
 * server grammar via validators.ts. Runs inside buildConfig so live inline
 * errors, scan start and profile save all share one verdict. */
function checkLines(
  text: string,
  field: FormField,
  label: string,
  parse: (line: string) => { ok: true; value: string } | { ok: false; message: string },
  routable: boolean,
  maxLines: number | null,
  issues: FieldIssue[],
): void {
  const list = lines(text);
  if (maxLines !== null && list.length > maxLines) {
    issues.push({
      field,
      message: `${label}: at most ${maxLines} lines (got ${list.length})`,
    });
    return;
  }
  for (const line of list) {
    const v = parse(line);
    // `=== false`, not truthiness: without tsconfig strictNullChecks the
    // truthy form does not narrow this discriminated union.
    if (v.ok === false) {
      issues.push({ field, message: `${label}: ${v.message}` });
      continue;
    }
    if (routable) {
      const ip = v.value.split("/")[0];
      if (!isRoutableIpv4(ip)) {
        issues.push({
          field,
          message: `${label}: ${ip} is a reserved/local range — the server refuses it`,
        });
      }
    }
  }
}

function parseCustomPorts(text: string, issues: FieldIssue[]): number[] {
  if (!text.trim()) return [];
  const ports: number[] = [];
  for (const raw of text.split(",")) {
    const token = raw.trim();
    if (!token) {
      issues.push({
        field: "customPortsText",
        message: "Custom ports: empty entry between commas",
      });
      continue;
    }
    const port = Number(token);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      issues.push({
        field: "customPortsText",
        message: `Custom ports: "${token}" is not a valid port (whole number 1–65535)`,
      });
      continue;
    }
    ports.push(port);
  }
  return ports;
}

function parseCap(text: string, issues: FieldIssue[]): number | null {
  const token = text.trim();
  if (!token) return null;
  const cap = Number(token);
  if (!Number.isInteger(cap) || cap < 1) {
    issues.push({
      field: "capText",
      message: `Hard cap: "${token}" is not a positive integer (clear the field for no cap)`,
    });
    return null;
  }
  return cap;
}

/** Pure FormState → ScanConfig. Throws FormValidationError listing every
 * problem it found instead of silently mangling input into NaN/0. */
export function buildConfig(f: FormState): ScanConfig {
  const issues: FieldIssue[] = [];

  // Chips + custom merge into one deduped, ascending port list. The WARP
  // default-port guard stays even though no WARP chip is 443: a user can
  // still type 443 as a custom port.
  const customPorts = parseCustomPorts(f.customPortsText, issues);
  const ports = [...new Set([...f.selectedPorts, ...customPorts])].sort((a, b) => a - b);
  if (ports.length === 0) {
    issues.push({
      field: "selectedPorts",
      message: "Ports: check at least one port or enter a custom one",
    });
  }
  if (ports.length > MAX_PORTS) {
    issues.push({
      field: "customPortsText",
      message: `Ports: at most ${MAX_PORTS} unique ports (got ${ports.length})`,
    });
  }
  if (f.mode === "Warp" && ports.includes(443)) {
    issues.push({
      field: "customPortsText",
      message:
        "WARP speaks WireGuard, not MASQUE — UDP 443 only serves the MASQUE protocol (try 2408, 500, 1701 or 4500)",
    });
  }
  const cap = parseCap(f.capText, issues);
  if (cap !== null && cap > MAX_STOP_VALUE) {
    issues.push({ field: "capText", message: `Hard cap: maximum is ${MAX_STOP_VALUE.toLocaleString("en-US")}` });
  }
  const count = wholeNumber(f.count, "Candidate count", 1, MAX_SCAN_COUNT, "count", issues);
  const stopFound = wholeNumber(
    f.stopFound,
    "Stop after N working",
    1,
    MAX_STOP_VALUE,
    "stopFound",
    issues,
  );
  const concurrency = wholeNumber(
    f.concurrency,
    "Concurrency",
    1,
    1000,
    "concurrency",
    issues,
  );
  const timeoutMs = wholeNumber(f.timeoutMs, "Timeout", 100, 30_000, "timeoutMs", issues);
  const warpProbes = wholeNumber(
    f.warpProbes,
    "Handshake probes per endpoint",
    1,
    10,
    "warpProbes",
    issues,
  );

  // Free-text lists: same grammar the server enforces, checked at entry so
  // inline errors and profile-save gating match scan-time 400s exactly.
  checkLines(f.customCidrs, "customCidrs", "Custom CIDRs", parseCidr, true, MAX_CIDRS, issues);
  checkLines(f.exclude, "exclude", "Exclude", parseCidr, false, MAX_CIDRS, issues);
  if (f.mode === "Warp") {
    checkLines(
      f.warpEndpoints,
      "warpEndpoints",
      "Custom endpoints",
      parseEndpoint,
      true,
      null,
      issues,
    );
  }
  if (f.wgconf.trim().length > MAX_WGCONF_BYTES) {
    issues.push({
      field: "wgconf",
      message: `wgconf exceeds ${Math.floor(MAX_WGCONF_BYTES / 1024)} KB`,
    });
  }

  const phase2Wanted = f.mode === "Cdn" && f.phase2On;
  const phase2Configs = phase2Wanted ? lines(f.configsText) : [];
  if (phase2Wanted) {
    if (phase2Configs.length === 0) {
      issues.push({
        field: "configsText",
        message: "Phase 2: add at least one config URI to verify",
      });
    }
    if (phase2Configs.length > MAX_PHASE2_ENTRIES) {
      issues.push({
        field: "configsText",
        message: `Phase 2: at most ${MAX_PHASE2_ENTRIES} configs (got ${phase2Configs.length})`,
      });
    }
    for (const c of phase2Configs) {
      if (c.length > MAX_CONFIG_ENTRY_BYTES) {
        issues.push({
          field: "configsText",
          message: `Phase 2: one config exceeds ${Math.floor(MAX_CONFIG_ENTRY_BYTES / 1024)} KB`,
        });
        break;
      }
      // Server-side API rule: share URIs and subscription URLs carry a
      // scheme; local xray JSON paths are CLI-only.
      if (!c.includes("://")) {
        issues.push({
          field: "configsText",
          message: `Phase 2: "${c.slice(0, 32)}${c.length > 32 ? "…" : ""}" has no scheme — paste a vless:// trojan:// vmess:// ss:// link or a subscription URL`,
        });
      }
    }
    const sniList = csv(f.snis);
    if (sniList.length > MAX_PHASE2_ENTRIES) {
      issues.push({
        field: "snis",
        message: `SNI variants: at most ${MAX_PHASE2_ENTRIES} (got ${sniList.length})`,
      });
    }
    for (const s of sniList) {
      const v = validateSni(s);
      if (v.ok === false) {
        issues.push({ field: "snis", message: `SNI: ${v.message}` });
      } else if (v.value.length > MAX_SNI_BYTES) {
        issues.push({ field: "snis", message: `SNI exceeds ${MAX_SNI_BYTES} bytes` });
      }
    }
    const pv = validateProbeUrl(f.probeUrl);
    if (pv.ok === false) issues.push({ field: "probeUrl", message: `Probe URL: ${pv.message}` });
  }

  if (issues.length > 0) throw new FormValidationError(issues);

  const cfg: ScanConfig = {
    mode: f.mode,
    target:
      f.mode === "Cdn" && !f.useCount ? { Preset: f.preset } : { Count: count },
    ports,
    stop: { found: stopFound, cap },
    exclude: lines(f.exclude),
    custom_cidrs: lines(f.customCidrs),
    include_v6: f.includeV6,
    concurrency,
    timeout_ms: timeoutMs,
    phase2: null,
    warp: null,
  };

  if (f.mode === "Warp") {
    cfg.warp = {
      custom_endpoints: lines(f.warpEndpoints),
      probes_per_endpoint: warpProbes,
      wgconf: f.wgconf.trim() ? f.wgconf : null,
      verify_with_wgconf: f.verifyWarp && !!f.wgconf.trim(),
    };
  }

  if (phase2Wanted) {
    cfg.phase2 = {
      configs: phase2Configs,
      // Wire contract is PascalCase (serde default for FragmentPreset); the
      // form stores lowercase for friendlier selects/persistence.
      fragment: (f.fragment.charAt(0).toUpperCase() +
        f.fragment.slice(1)) as FragmentWire,
      snis: csv(f.snis),
      probe_url: f.probeUrl,
      probe_urls: [],
      concurrency: 3,
    };
  }

  return cfg;
}

/** localStorage key for the persisted Pro-panel form. Bump to reset users'
 * saved forms when FormState changes shape (restore merges over defaults,
 * so additive keys never need a bump). */
export const FORM_PERSIST_KEY = "cf-form-v1";

/** FormState → JSON for localStorage. wgconf is deliberately dropped: it
 * carries a WireGuard private key and must not sit on disk in plaintext;
 * verifyWarp without it is meaningless so it is reset too. */
export function persistedFormState(f: FormState): string {
  const copy: FormState = { ...f };
  copy.wgconf = "";
  copy.verifyWarp = false;
  return JSON.stringify(copy);
}

/** Inverse of persistedFormState: parse + merge known keys over defaults so
 * older/newer shapes stay forward-compatible. Returns null when unparseable
 * or not an object; mistyped values fall back to their defaults. */
export function formStateFromPersisted(raw: string): FormState | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;

  const saved = parsed as Record<string, unknown>;
  const d = defaultFormState();
  const out: FormState = { ...d };
  const sink = out as unknown as Record<string, unknown>;
  for (const key of Object.keys(d) as FormField[]) {
    if (key in saved && typeof saved[key] === typeof d[key])
      sink[key] = saved[key];
  }

  if (!["Cdn", "Warp"].includes(out.mode)) out.mode = d.mode;
  // Sanitize the port selection: integers 1-65535 only, and at least the
  // mode default so a corrupted blob can't produce a zero-port form.
  out.selectedPorts = out.selectedPorts.filter(
    (p) => Number.isInteger(p) && p >= 1 && p <= 65535,
  );
  if (out.selectedPorts.length === 0) out.selectedPorts = defaultSelectedPorts(out.mode);
  if (!["Quick", "Normal", "Full"].includes(out.preset)) out.preset = d.preset;
  if (!["off", "light", "medium", "heavy", "custom"].includes(out.fragment))
    out.fragment = d.fragment;
  return out;
}
