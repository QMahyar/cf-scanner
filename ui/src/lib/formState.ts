import type { CdnPreset, FragmentPreset, Mode, ScanConfig } from "./types";
import {
  CDN_HTTPS_PORTS,
  WARP_EXTENDED_PORTS,
  WARP_PRIMARY_PORTS,
} from "./cfPorts";

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
    fragment: cfg.phase2?.fragment ?? d.fragment,
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
  field: FormField,
  issues: FieldIssue[],
): number {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n < min) {
    issues.push({ field, message: `${label}: enter a whole number ≥ ${min}` });
    return min;
  }
  return n;
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
  if (f.mode === "Warp" && ports.includes(443)) {
    issues.push({
      field: "customPortsText",
      message:
        "WARP speaks WireGuard, not MASQUE — UDP 443 only serves the MASQUE protocol (try 2408, 500, 1701 or 4500)",
    });
  }
  const cap = parseCap(f.capText, issues);
  const count = wholeNumber(f.count, "Candidate count", 1, "count", issues);
  const stopFound = wholeNumber(
    f.stopFound,
    "Stop after N working",
    1,
    "stopFound",
    issues,
  );
  const concurrency = wholeNumber(
    f.concurrency,
    "Concurrency",
    1,
    "concurrency",
    issues,
  );
  const timeoutMs = wholeNumber(f.timeoutMs, "Timeout", 1, "timeoutMs", issues);
  const warpProbes = wholeNumber(
    f.warpProbes,
    "Handshake probes per endpoint",
    1,
    "warpProbes",
    issues,
  );

  const phase2Wanted = f.mode === "Cdn" && f.phase2On;
  const phase2Configs = phase2Wanted ? lines(f.configsText) : [];
  if (phase2Wanted && phase2Configs.length === 0) {
    issues.push({
      field: "configsText",
      message: "Phase 2: add at least one config URI to verify",
    });
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
      fragment: f.fragment,
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
