import type { RunSummary, ScanDetail, ScansPage, Stats } from "./types";

const BASE = "/api";

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = (await res.json()) as { detail?: string; message?: string };
      detail = body.detail || body.message || detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return (await res.json()) as T;
}

export interface ScanQuery {
  limit?: number;
  offset?: number;
  verdict?: string;
  risk_level?: string;
  language?: string;
  dast_attempted?: boolean;
  run_id?: string;
  q?: string;
  sort?: string;
  order?: string;
}

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

export const api = {
  stats: () => getJSON<Stats>("/stats"),
  scans: (query: ScanQuery = {}) => getJSON<ScansPage>(`/scans${qs(query as Record<string, unknown>)}`),
  scan: (id: number | string) => getJSON<ScanDetail>(`/scans/${id}`),
  runs: () => getJSON<RunSummary[]>("/runs"),
};
