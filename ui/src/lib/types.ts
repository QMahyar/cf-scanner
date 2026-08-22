export type Mode = "Cdn" | "Warp";
export type CdnPreset = "Quick" | "Normal" | "Full";
export type FragmentPreset = "off" | "light" | "medium" | "heavy" | "custom";

export interface Phase2Config {
  configs: string[];
  fragment: FragmentPreset;
  custom_fragment?: { packets: string; length: string; interval: string } | null;
  snis: string[];
  probe_url: string;
  probe_urls: string[];
  concurrency: number;
}

export interface WarpConfig {
  custom_endpoints: string[];
  probes_per_endpoint: number;
  wgconf?: string | null;
  verify_with_wgconf: boolean;
}

export interface ScanConfig {
  mode: Mode;
  target: { Preset: CdnPreset } | { Count: number };
  ports: number[];
  stop: { found: number; cap: number | null };
  exclude: string[];
  custom_cidrs: string[];
  include_v6?: boolean;
  concurrency: number;
  timeout_ms: number;
  phase2?: Phase2Config | null;
  warp?: WarpConfig | null;
}

export interface Phase2Verdict {
  passed: boolean;
  fragment: string;
  sni: string;
  latency_ms: number | null;
  error: string | null;
  config_index: number;
  verifier: string;
}

export interface Verdict {
  ip: string;
  port: number;
  latency_ms: number | null;
  country: string | null;
  colo: string | null;
  phase2?: Phase2Verdict | null;
}

export interface ScanProgress {
  scanned: number;
  found: number;
  total: number | null;
}

export interface Phase2Progress {
  done: number;
  total: number;
}

export interface ScanSummary {
  scanned: number;
  found: number;
  duration_ms: number;
  cancelled: boolean;
}

export interface ResultsPayload {
  results: Verdict[];
  summary: ScanSummary | null;
}

export interface StatusPayload {
  version: string;
  is_running: boolean;
}
