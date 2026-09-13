import type { Asset, Finding, FindingDetail, Scan, SourceStatus } from "./types";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const TOKEN_KEY = "cerberus.apiKey";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getToken()}`,
        ...init.headers,
      },
    });
  } catch {
    throw new ApiError(0, "network_error", `Cannot reach the API at ${BASE_URL}. Is it running?`);
  }

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const error = body?.error;
    throw new ApiError(
      response.status,
      error?.code ?? "unknown",
      error?.message ?? `Request failed with status ${response.status}`,
    );
  }
  return response.json() as Promise<T>;
}

export function listFindings(params: {
  kevOnly: boolean;
  minRiskScore: string;
  limit?: number;
}): Promise<{ total: number; findings: Finding[] }> {
  const query = new URLSearchParams({ limit: String(params.limit ?? 50) });
  if (params.kevOnly) query.set("kev_only", "true");
  if (params.minRiskScore) query.set("min_risk_score", params.minRiskScore);
  return request(`/api/v1/findings?${query}`);
}

export function getFinding(id: string): Promise<FindingDetail> {
  return request(`/api/v1/findings/${id}`);
}

export function updateFindingStatus(id: string, status: string): Promise<FindingDetail> {
  return request(`/api/v1/findings/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

export function listAssets(): Promise<{ total: number; assets: Asset[] }> {
  return request(`/api/v1/assets?limit=100`);
}

export function enrichmentStatus(): Promise<{ sources: SourceStatus[] }> {
  return request(`/api/v1/enrichment/status`);
}

export function startScan(targetDomain: string): Promise<{ scan_id: string; status: string }> {
  return request(`/api/v1/scans`, {
    method: "POST",
    body: JSON.stringify({ target_domain: targetDomain, authorized: true }),
  });
}

export function getScan(scanId: string): Promise<Scan> {
  return request(`/api/v1/scans/${scanId}`);
}
