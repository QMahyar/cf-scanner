import type { CdnPreset, FragmentPreset, Mode, ScanConfig } from "./types";

/** Everything the Pro panel can set, exactly as the user typed it.
 * Text fields stay text so "cleared" is representable (e.g. capText "" = no
 * hard cap); buildConfig does the strict parse at start time. */
export interface FormState {
  mode: Mode;
  preset: CdnPreset;
  count: number;
  useCount: boolean;
  portsText: string;
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

/** Pro panel defaults; simple mode keeps its own in simpleConfig(). */
export function defaultFormState(): FormState {
  return {
    mode: "Cdn",
    preset: "Quick",
    count: 350,
    useCount: false,
    portsText: "443",
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
  return {
    mode: cfg.mode,
    preset: !("Count" in cfg.target) ? cfg.target.Preset : d.preset,
    count: "Count" in cfg.target ? cfg.target.Count : d.count,
    useCount: "Count" in cfg.target,
    portsText: cfg.ports.join(", "),
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

export class FormValidationError extends Error {
  readonly errors: string[];

  constructor(errors: string[]) {
    super(errors.join(" · "));
    this.name = "FormValidationError";
    this.errors = errors;
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

function wholeNumber(value: unknown, label: string, min: number, issues: string[]): number {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n < min) {
    issues.push(`${label}: enter a whole number ≥ ${min}`);
    return min;
  }
  return n;
}

function parsePorts(text: string, issues: string[]): number[] {
  if (!text.trim()) {
    issues.push("Ports: at least one port is required");
    return [];
  }
  const ports: number[] = [];
  for (const raw of text.split(",")) {
    const token = raw.trim();
    if (!token) {
      issues.push("Ports: empty entry between commas");
      continue;
    }
    const port = Number(token);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      issues.push(`Ports: "${token}" is not a valid port (whole number 1–65535)`);
      continue;
    }
    ports.push(port);
  }
  return ports;
}

function parseCap(text: string, issues: string[]): number | null {
  const token = text.trim();
  if (!token) return null;
  const cap = Number(token);
  if (!Number.isInteger(cap) || cap < 1) {
    issues.push(`Hard cap: "${token}" is not a positive integer (clear the field for no cap)`);
    return null;
  }
  return cap;
}

/** Pure FormState → ScanConfig. Throws FormValidationError listing every
 * problem it found instead of silently mangling input into NaN/0. */
export function buildConfig(f: FormState): ScanConfig {
  const issues: string[] = [];

  const ports = parsePorts(f.portsText, issues);
  const cap = parseCap(f.capText, issues);
  const count = wholeNumber(f.count, "Candidate count", 1, issues);
  const stopFound = wholeNumber(f.stopFound, "Stop after N working", 1, issues);
  const concurrency = wholeNumber(f.concurrency, "Concurrency", 1, issues);
  const timeoutMs = wholeNumber(f.timeoutMs, "Timeout", 1, issues);
  const warpProbes = wholeNumber(f.warpProbes, "Handshake probes per endpoint", 1, issues);

  const phase2Wanted = f.mode === "Cdn" && f.phase2On;
  const phase2Configs = phase2Wanted ? lines(f.configsText) : [];
  if (phase2Wanted && phase2Configs.length === 0) {
    issues.push("Phase 2: add at least one config URI to verify");
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
