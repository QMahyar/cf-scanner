import type {
  Phase2Progress,
  ResultsPayload,
  ScanConfig,
  ScanProgress,
  ScanSummary,
  StatusPayload,
  Verdict,
} from "./types";

export interface ProfilePayload {
  name: string;
  config: ScanConfig;
}

export interface XrayStatusPayload {
  found: boolean;
  path: string | null;
  data_dir: string;
  version: string;
}

async function unwrap<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let message = `${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
      if (body?.message) message += `: ${body.message}`;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

export const api = {
  status: () => fetch("/api/status").then(unwrap<StatusPayload>),
  results: () => fetch("/api/results").then(unwrap<ResultsPayload>),
  scan: (cfg: ScanConfig) =>
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cfg),
    }).then(unwrap<unknown>),
  cancel: () => fetch("/api/cancel", { method: "POST" }),
  reset: () => fetch("/api/reset", { method: "POST" }),
  profiles: () => fetch("/api/profiles").then(unwrap<ProfilePayload[]>),
  saveProfile: (name: string, cfg: unknown) =>
    fetch(`/api/profiles/${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cfg),
    }),
  deleteProfile: (name: string) =>
    fetch(`/api/profiles/${encodeURIComponent(name)}`, { method: "DELETE" }),
  exportUri: (config: string, ip: string, port: number) =>
    fetch("/api/config/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config, ip, port }),
    }).then(unwrap<{ uri: string }>),
  xrayStatus: () => fetch("/api/xray/status").then(unwrap<XrayStatusPayload>),
  xrayDownload: () =>
    fetch("/api/xray/download", { method: "POST" }).then(
      unwrap<{ success: boolean; path?: string | null; error?: string | null }>,
    ),
  rangesRefresh: () =>
    fetch("/api/ranges/refresh", { method: "POST" }).then(unwrap<unknown>),
  warpRegister: (license: string | null, overwrite: boolean) =>
    fetch("/api/warp/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ license: license || null, overwrite }),
    }).then(unwrap<{ wgconf: string }>),
};

/** Live event stream. The server keeps idle connections open (a replayed
 * terminal is context, not an end-of-stream), so one EventSource lasts the
 * whole session; browsers reconnect transparently on drop. */
export function subscribe(handlers: {
  onProgress?: (p: ScanProgress) => void;
  onResult?: (v: Verdict) => void;
  onFinished?: (s: ScanSummary) => void;
  onPhase2?: (p: Phase2Progress) => void;
  onFailed?: (msg: string) => void;
}): EventSource {
  const es = new EventSource("/api/events");
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
