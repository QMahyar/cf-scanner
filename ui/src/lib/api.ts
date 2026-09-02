import type {
  Phase2Progress,
  ResultsPayload,
  ScanConfig,
  ScanProgress,
  ScanSummary,
  StatusPayload,
  Verdict,
} from "./types";

export interface XrayStatusPayload {
  found: boolean;
  path: string | null;
  data_dir: string;
  version: string;
}

export interface RangesPayload {
  host_count: number;
  last_updated: string | null;
}

export type LiveStatus = "connecting" | "live" | "offline";

/** Failure from a non-2xx API response. Carries the HTTP status and the
 * server envelope's detail so callers can route messages to form fields
 * (400/422) instead of only showing a global banner. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, summary: string, detail: string) {
    super(detail ? `${summary}: ${detail}` : summary || String(status));
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function apiErrorFrom(res: Response): Promise<ApiError> {
  let summary = `${res.status}`;
  let detail = "";
  try {
    const body = await res.json();
    if (body?.error) summary = body.error;
    if (body?.message) detail = body.message;
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, summary, detail);
}

/** 202 (scan accepted) and 204 carry no body but still use the ApiError
 * envelope on failure — pass their Response through this to get
 * unwrap()-style thrown Errors. */
export async function assertOk(res: Response): Promise<Response> {
  if (!res.ok) throw await apiErrorFrom(res);
  return res;
}

async function unwrap<T>(res: Response): Promise<T> {
  if (!res.ok) throw await apiErrorFrom(res);
  // 202 (scan accepted) and 204 carry no body: parsing them as JSON throws
  // "Unexpected end of JSON input" even though the request succeeded.
  if (res.status === 202 || res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** State-changing requests carry this marker: browsers never attach custom
 * headers to cross-site form posts, so the server's guard treats its
 * presence as proof the request came from this app's JS, not a hostile page
 * (covers legacy browsers that send neither Origin nor Sec-Fetch-Site). */
const CSRF_MARKERS = { "X-Requested-With": "cf-scanner" };

export const api = {
  status: () =>
    fetch("/api/status", { cache: "no-store", signal: AbortSignal.timeout(8000) }).then(
      unwrap<StatusPayload>,
    ),
  results: () =>
    fetch("/api/results", { cache: "no-store", signal: AbortSignal.timeout(8000) }).then(
      unwrap<ResultsPayload>,
    ),
  scan: (cfg: ScanConfig) =>
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...CSRF_MARKERS },
      body: JSON.stringify(cfg),
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    }).then(unwrap<unknown>),
  cancel: () =>
    fetch("/api/cancel", {
      method: "POST",
      headers: CSRF_MARKERS,
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    }).then(assertOk),
  reset: () =>
    fetch("/api/reset", {
      method: "POST",
      headers: CSRF_MARKERS,
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    }).then(assertOk),
  exportUri: (config: string, ip: string, port: number) =>
    fetch("/api/config/export", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...CSRF_MARKERS },
      body: JSON.stringify({ config, ip, port }),
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    }).then(unwrap<{ uri: string }>),
  /** Subscription bundle from the last scan's verified set. */
  bundle: (format: "base64" | "raw" | "singbox" | "clash" = "base64") =>
    fetch(`/api/bundle?format=${format}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    })
      .then(assertOk)
      .then((res) => res.text()),
  /** Metadata dump (json/csv) of the current results. */
  resultsExport: (format: "json" | "csv" = "csv") =>
    fetch(`/api/results/export?format=${format}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    })
      .then(assertOk)
      .then((res) => res.text()),
  xrayStatus: () =>
    fetch("/api/xray/status", { cache: "no-store", signal: AbortSignal.timeout(8000) }).then(
      unwrap<XrayStatusPayload>,
    ),
  xrayDownload: () =>
    fetch("/api/xray/download", {
      method: "POST",
      headers: CSRF_MARKERS,
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    }).then(unwrap<{ success: boolean; path?: string | null; error?: string | null }>),
  ranges: () =>
    fetch("/api/ranges", { cache: "no-store", signal: AbortSignal.timeout(8000) }).then(
      unwrap<RangesPayload>,
    ),
  warpRegister: (license: string | null, overwrite: boolean) =>
    fetch("/api/warp/register", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...CSRF_MARKERS },
      body: JSON.stringify({ license: license || null, overwrite }),
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    }).then(unwrap<{ wgconf: string }>),
};

/** Live event stream. The server keeps idle connections open (a replayed
 * terminal is context, not an end-of-stream), so one EventSource lasts the
 * whole session; browsers reconnect transparently on drop. onStatus tracks
 * the real connection: live on open, connecting while the browser
 * auto-reconnects, offline only when navigator says the network is gone. */
export function subscribe(handlers: {
  onProgress?: (p: ScanProgress) => void;
  onResult?: (v: Verdict) => void;
  onFinished?: (s: ScanSummary) => void;
  onPhase2?: (p: Phase2Progress) => void;
  onFailed?: (msg: string) => void;
  onStatus?: (s: LiveStatus) => void;
  onReconnect?: () => void;
}): EventSource {
  const es = new EventSource("/api/events");
  let firstOpen = true;
  if (handlers.onStatus || handlers.onReconnect) {
    es.onopen = () => {
      handlers.onStatus?.("live");
      if (!firstOpen) handlers.onReconnect?.();
      firstOpen = false;
    };
    es.onerror = () =>
      handlers.onStatus?.(navigator.onLine ? "connecting" : "offline");
  } else if (handlers.onReconnect) {
    es.onopen = () => {
      if (!firstOpen) handlers.onReconnect?.();
      firstOpen = false;
    };
  } else {
    es.onopen = () => {
      firstOpen = false;
    };
  }
  const listen = <T>(
    event: string,
    cb: ((value: T) => void) | undefined,
  ): void => {
    if (!cb) return;
    es.addEventListener(event, (ev: MessageEvent) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(ev.data as string);
      } catch (err) {
        console.debug("dropping malformed SSE frame", event, err);
        return;
      }
      cb(parsed as T);
    });
  };
  listen("progress", handlers.onProgress);
  listen("result", handlers.onResult);
  listen("finished", handlers.onFinished);
  listen("phase2-progress", handlers.onPhase2);
  listen("failed", handlers.onFailed);
  return es;
}
