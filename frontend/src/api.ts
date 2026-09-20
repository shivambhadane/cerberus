import {
  auth,
  fbSignOut,
  getCurrentIdToken,
  onAuthStateChanged,
} from "./lib/firebase";
import type {
  Asset,
  AuthResult,
  Connection,
  Criticality,
  Domain,
  Finding,
  FindingDetail,
  FindingQuery,
  Observation,
  Overview,
  Page,
  ProjectList,
  ProviderInfo,
  Scan,
  SourceStatus,
  TestbedTarget,
  User,
  VerifyResult,
} from "./types";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export const PAGE_SIZE = 25;

/** Scan statuses that mean work is still in flight (the API reports these; polling keys off them). */
export const ACTIVE_SCAN_STATUSES = ["pending", "discovering", "enriching", "scoring"];

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/* ---- Session -----------------------------------------------------------------------------
 * Firebase Auth manages ID tokens and refreshes automatically in memory/IndexedDB.
 * For legacy / fallback API access, the access token is retained in memory.
 */

let accessToken = "";

/* A non-secret note that this browser has signed in. It only decides whether to *try* resuming a
 * session on load: without it, every first-time visitor would fire a refresh request that is bound
 * to fail, and the browser logs failed requests as errors. It grants nothing. */
const SESSION_HINT = "cerberus.hadSession";
function hintSession(present: boolean): void {
  try {
    if (present) localStorage.setItem(SESSION_HINT, "1");
    else localStorage.removeItem(SESSION_HINT);
  } catch {
    /* storage unavailable: a reload then asks for a sign-in, which is safe */
  }
}
function hasSessionHint(): boolean {
  try {
    return localStorage.getItem(SESSION_HINT) === "1";
  } catch {
    return false;
  }
}

let refreshInFlight: Promise<AuthResult | null> | null = null;
const signedOutListeners = new Set<() => void>();

/** Called when a session cannot be continued (refresh refused): the app should show sign-in. */
export function onSessionEnded(listener: () => void): () => void {
  signedOutListeners.add(listener);
  return () => signedOutListeners.delete(listener);
}

async function fetchWithSession(path: string, init: RequestInit): Promise<Response> {
  let token: string | null = null;
  try {
    token = await getCurrentIdToken();
  } catch {
    // Firebase not yet initialized or unauthenticated
  }
  if (!token && accessToken) {
    token = accessToken;
  }
  return fetch(`${BASE_URL}${path}`, {
    ...init,
    credentials: "include", // sends the refresh cookie to /auth/*, and accepts the one it sets
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  });
}

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const error = body?.error;
    throw new ApiError(
      response.status,
      error?.code ?? "unknown",
      error?.message ?? `The API returned status ${response.status}.`,
    );
  }
  return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
}

async function send(path: string, init: RequestInit): Promise<Response> {
  try {
    return await fetchWithSession(path, init);
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError(0, "network_error", `Cannot reach the API at ${BASE_URL}. Check that it is running.`);
  }
}

/**
 * Get a new access token from the refresh cookie. Concurrent callers share one request: the
 * refresh token is single-use, so two simultaneous refreshes would look like a replay.
 */
export function refreshSession(): Promise<AuthResult | null> {
  refreshInFlight ??= (async () => {
    try {
      const result = await parse<AuthResult>(await send("/api/v1/auth/refresh", { method: "POST" }));
      accessToken = result.access_token;
      hintSession(true);
      return result;
    } catch {
      accessToken = "";
      hintSession(false);
      return null;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response = await send(path, init);
  if (response.status === 401 && !path.startsWith("/api/v1/auth/")) {
    let refreshed = false;
    try {
      const refreshedToken = await getCurrentIdToken(true);
      if (refreshedToken) {
        refreshed = true;
      }
    } catch {
      // not a firebase session
    }

    if (!refreshed && (await refreshSession())) {
      refreshed = true;
    }

    if (refreshed) {
      response = await send(path, init);
    } else {
      signedOutListeners.forEach((listener) => listener());
    }
  }
  return parse<T>(response);
}

function query(params: Record<string, string | number | boolean | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "" || value === false) continue;
    q.set(key, String(value));
  }
  const text = q.toString();
  return text ? `?${text}` : "";
}

const offsetFor = (page = 1, size = PAGE_SIZE) => (Math.max(1, page) - 1) * size;

/* ---- Accounts ---------------------------------------------------------------------------- */

export const getMe = () => request<User>("/api/v1/auth/me");

async function authenticate(path: string, body: unknown): Promise<AuthResult> {
  const result = await parse<AuthResult>(await send(path, { method: "POST", body: JSON.stringify(body) }));
  accessToken = result.access_token;
  hintSession(true);
  return result;
}

export const register = (email: string, password: string, name: string) =>
  authenticate("/api/v1/auth/register", { email, password, name });

export const login = (email: string, password: string) => authenticate("/api/v1/auth/login", { email, password });

/** Resume a session from Firebase Auth or the refresh cookie (page load). Null when there is none. */
export function restoreSession(): Promise<User | null> {
  return new Promise((resolve) => {
    let settled = false;
    const unsubscribe = onAuthStateChanged(auth, async (fbUser) => {
      unsubscribe();
      if (settled) return;
      settled = true;
      if (fbUser) {
        try {
          const me = await getMe();
          resolve(me);
          return;
        } catch {
          // Firebase authenticated but backend failed or disabled
        }
      }
      if (hasSessionHint()) {
        const legacy = await refreshSession();
        resolve(legacy ? legacy.user : null);
      } else {
        resolve(null);
      }
    });
  });
}

export async function logout(): Promise<void> {
  try {
    await fbSignOut(auth).catch(() => undefined);
    await parse<void>(await send("/api/v1/auth/logout", { method: "POST" })).catch(() => undefined);
  } finally {
    accessToken = ""; // whatever the server said, this browser is signed out
    hintSession(false);
  }
}

/* ---- Domains ----------------------------------------------------------------------------- */

export async function listDomains(signal?: AbortSignal): Promise<Domain[]> {
  const data = await request<{ total: number; domains: Domain[] }>("/api/v1/domains", { signal });
  return data.domains;
}

export const addDomain = (domain: string) =>
  request<Domain>("/api/v1/domains", { method: "POST", body: JSON.stringify({ domain }) });

export const verifyDomain = (id: string) =>
  request<VerifyResult>(`/api/v1/domains/${id}/verify`, { method: "POST" });

export async function listTestbeds(signal?: AbortSignal): Promise<TestbedTarget[]> {
  const data = await request<{ total: number; testbeds: TestbedTarget[] }>("/api/v1/domains/testbeds", { signal });
  return data.testbeds;
}

export const addTestbed = (targetId: string) =>
  request<Domain>(`/api/v1/domains/testbeds/${targetId}`, { method: "POST" });

/* ---- Deployment providers (Vercel, Netlify, Cloudflare Pages) -----------------------------
 * The browser never sees a provider token or client secret. `connectProvider` returns only the
 * provider's own authorisation URL; the provider then redirects to the API, which completes the
 * connection server-side and sends the browser back to the Targets page with a short outcome code.
 */

export const listProviders = async (signal?: AbortSignal): Promise<ProviderInfo[]> =>
  (await request<{ providers: ProviderInfo[] }>("/api/v1/providers", { signal })).providers;

export const connectProvider = (provider: string) =>
  request<{ authorization_url: string }>(`/api/v1/providers/${provider}/connect`, { method: "POST" });

/**
 * Connect with an access token the person made on the platform. The token goes to the server once, is proved
 * by using it, and is stored encrypted; it is never returned, so nothing here can read it back.
 */
export const connectWithToken = (provider: string, token: string, teamId?: string) =>
  request<Connection>(`/api/v1/providers/${provider}/token`, {
    method: "POST",
    body: JSON.stringify({ token, team_id: teamId?.trim() || null }),
  });

export const listConnectionProjects = (connectionId: string, signal?: AbortSignal) =>
  request<ProjectList>(`/api/v1/connections/${connectionId}/projects`, { signal });

export const disconnectConnection = (connectionId: string) =>
  request<{ disconnected: boolean; targets_reset: number }>(`/api/v1/connections/${connectionId}/disconnect`, {
    method: "POST",
  });

export const listConnections = (signal?: AbortSignal) => request<Connection[]>("/api/v1/connections", { signal });

/** Add a deployment as a verified target. The server decides ownership; these three are only a request. */
export const addPlatformTarget = (connectionId: string, projectId: string, hostname: string) =>
  request<Domain>("/api/v1/domains/provider", {
    method: "POST",
    body: JSON.stringify({ connection_id: connectionId, project_id: projectId, hostname }),
  });

/** Verify an existing target again through a connected account (e.g. after reconnecting it). */
export const verifyPlatformTarget = (domainId: string, connectionId: string, projectId: string) =>
  request<Domain>(`/api/v1/domains/${domainId}/verify/provider`, {
    method: "POST",
    body: JSON.stringify({ connection_id: connectionId, project_id: projectId }),
  });

/* ---- Findings, assets, evidence ---------------------------------------------------------- */

export async function listFindings(f: FindingQuery, signal?: AbortSignal): Promise<Page<Finding>> {
  const size = f.pageSize ?? PAGE_SIZE;
  const data = await request<{ total: number; findings: Finding[] }>(
    `/api/v1/findings${query({
      q: f.q,
      status: f.status,
      detection_method: f.detection,
      asset_id: f.assetId,
      kev_only: f.kevOnly,
      min_risk_score: f.minRisk,
      sort: f.sort,
      order: f.order,
      limit: size,
      offset: offsetFor(f.page, size),
    })}`,
    { signal },
  );
  return { total: data.total, items: data.findings };
}

export const getFinding = (id: string, signal?: AbortSignal) =>
  request<FindingDetail>(`/api/v1/findings/${id}`, { signal });

export const updateFindingStatus = (id: string, status: string) =>
  request<FindingDetail>(`/api/v1/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });

export async function listAssets(page = 1, signal?: AbortSignal): Promise<Page<Asset>> {
  const data = await request<{ total: number; assets: Asset[] }>(
    `/api/v1/assets${query({ limit: PAGE_SIZE, offset: offsetFor(page) })}`,
    { signal },
  );
  return { total: data.total, items: data.assets };
}

export const setCriticality = (assetId: string, level: Criticality, reason: string) =>
  request<Asset>(`/api/v1/assets/${assetId}/criticality`, {
    method: "PATCH",
    body: JSON.stringify({ level, reason: reason || undefined }),
  });

export async function listObservations(
  f: { scanId?: string; target?: string; kind?: string; page?: number },
  signal?: AbortSignal,
): Promise<Page<Observation>> {
  const data = await request<{ total: number; observations: Observation[] }>(
    `/api/v1/observations${query({
      scan_id: f.scanId,
      target: f.target,
      kind: f.kind,
      limit: PAGE_SIZE,
      offset: offsetFor(f.page),
    })}`,
    { signal },
  );
  return { total: data.total, items: data.observations };
}

export const enrichmentStatus = (signal?: AbortSignal) =>
  request<{ sources: SourceStatus[] }>("/api/v1/enrichment/status", { signal });

/* ---- Scans ------------------------------------------------------------------------------- */

export async function listScans(page = 1, signal?: AbortSignal, size = PAGE_SIZE): Promise<Page<Scan>> {
  const data = await request<{ total: number; scans: Scan[] }>(
    `/api/v1/scans${query({ limit: size, offset: offsetFor(page, size) })}`,
    { signal },
  );
  return { total: data.total, items: data.scans };
}

/** Scan a domain the person has verified. There is no "authorized" flag: the proof is the domain. */
export const startScan = (domainId: string, profile: string, acceptProfile: boolean) =>
  request<{ scan_id: string; status: string; profile: string }>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify({ domain_id: domainId, profile, accept_profile: acceptProfile }),
  });

export const getOverview = (signal?: AbortSignal) => request<Overview>("/api/v1/overview", { signal });
