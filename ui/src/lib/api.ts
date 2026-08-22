import type { ResultsPayload, ScanConfig, StatusPayload } from "./types";

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
  profiles: () => fetch("/api/profiles").then(unwrap<{ profiles: Record<string, unknown> }>),
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
  xrayStatus: () =>
    fetch("/api/xray/status").then(
      unwrap<{ available: boolean; path?: string | null }>,
    ),
  xrayDownload: () =>
    fetch("/api/xray/download", { method: "POST" }).then(unwrap<unknown>),
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
export function subscribe(
  handlers: {
    onProgress?: (p: { scanned: number; found: number; total: number | null }) => void;
    onResult?: (v: unknown) => void;
    onFinished?: (s: unknown) => void;
    onPhase2?: (p: { done: number; total: number }) => void;
    onFailed?: (msg: string) => void;
  },
): EventSource {
  const es = new EventSource("/api/events");
  const data = (ev: MessageEvent) => JSON.parse(ev.data);
  if (handlers.onProgress)
    es.addEventListener("progress", (e) => handlers.onProgress!(data(e)));
  if (handlers.onResult)
    es.addEventListener("result", (e) => handlers.onResult!(data(e)));
  if (handlers.onFinished)
    es.addEventListener("finished", (e) => handlers.onFinished!(data(e)));
  if (handlers.onPhase2)
    es.addEventListener("phase2-progress", (e) => handlers.onPhase2!(data(e)));
  if (handlers.onFailed)
    es.addEventListener("failed", (e) => handlers.onFailed!(data(e)));
  return es;
}
