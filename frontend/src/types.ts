export interface Finding {
  id: string;
  asset_id: string;
  asset: string;
  cve_id: string;
  cvss_score: number | null;
  kev_listed: boolean;
  epss_score: number | null;
  asset_criticality: string | null;
  risk_score: number | null;
  status: string;
  reasoning: string | null;
  detection_method: string;
  detected_by_tool: string | null;
  detected_at: string;
}

export interface FindingDetail extends Omit<Finding, "asset"> {
  asset: { id: string; hostname: string; port: number };
  asset_criticality_source: "heuristic" | "manual" | null;
  asset_criticality_reason: string | null;
  kev_date_added: string | null;
  has_public_exploit: boolean;
  description: string | null;
  evidence: string | null;
}

export type Criticality = "low" | "medium" | "high" | "critical";

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string | null;
  port: number;
  protocol: string;
  technology: string | null;
  discovered_by_tool: string | null;
  criticality: Criticality | null;
  criticality_reason: string | null;
  criticality_source: "heuristic" | "manual" | null;
  finding_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface SourceStatus {
  name: string;
  last_refreshed_at: string;
  record_count: number;
}

export interface Observation {
  id: string;
  scan_id: string;
  kind: string;
  target: string;
  source_tool: string;
  source_version: string | null;
  data: Record<string, unknown>;
  observed_at: string;
}

export interface Scan {
  scan_id: string;
  target_domain: string;
  profile: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  error: string | null;
  warnings: string[];
  observation_count?: number;
}

export interface Page<T> {
  total: number;
  items: T[];
}

export interface FindingQuery {
  q?: string;
  status?: string;
  detection?: string;
  assetId?: string;
  kevOnly?: boolean;
  minRisk?: string;
  sort?: string;
  order?: string;
  page?: number;
  pageSize?: number;
}

export interface Overview {
  findings: {
    active: number;
    actively_exploited: number;
    confirmed: number;
    by_risk_band: Record<string, number>;
    by_detection: Record<string, number>;
  };
  assets: { total: number; by_criticality: Record<string, number> };
  scans_total: number;
  last_scan: Scan | null;
}

export interface User {
  id: string;
  email: string;
  name: string;
  email_verified: boolean;
  created_at: string;
  last_login_at?: string | null;
  /** From the identity provider's verified token (a Google photo). Untrusted until shown with a fallback. */
  picture_url?: string | null;
  /** How the person signed in: "google.com", "github.com" or "password". */
  auth_provider?: string | null;
}

export interface AuthResult {
  user: User;
  access_token: string;
  token_type: string;
  expires_in: number;
}

export type VerificationStatus = "pending" | "verified" | "failed";

export interface Domain {
  id: string;
  domain: string;
  verification_status: VerificationStatus;
  verification_method: string;
  verified_at: string | null;
  created_at: string;
  /** DNS instructions; null when a platform account (Vercel, Netlify, Cloudflare) proved the target. */
  verification: { method: string; record_type: string; record_name: string; record_value: string } | null;
  provider?: string | null;
  provider_project_id?: string | null;
}

export type ProviderName = "vercel" | "netlify" | "cloudflare";

export interface Connection {
  id: string;
  provider: ProviderName;
  label: string;
  connected_at: string;
  scopes: string[];
  /** How it was connected: the platform's OAuth flow, or an access token the person pasted. */
  method?: "oauth" | "token";
}

export interface ProviderInfo {
  provider: ProviderName;
  label: string;
  /** False until the operator has registered an OAuth app and set its credentials on the server. */
  configured: boolean;
  /** True when an access token can be pasted instead (needs only the server's encryption key). */
  token_paste?: boolean;
  connections: Connection[];
}

export interface PlatformProject {
  id: string;
  name: string;
  /** Platform hostnames (`*.vercel.app` and the like) that can be verified. */
  hostnames: string[];
  verified_hostnames: string[];
}

export interface ProjectList {
  connection: Connection;
  projects: PlatformProject[];
}

export interface VerifyResult {
  verified: boolean;
  reason: "verified" | "record_not_found" | "token_mismatch" | "lookup_failed";
  detail: string;
  domain: Domain;
}

export interface TestbedTarget {
  id: string;
  name: string;
  category: "docker" | "public";
  domain: string;
  url?: string;
  ports?: number[];
  docker_command?: string;
  docker_teardown?: string;
  description: string;
  vulnerabilities: string[];
  tags: string[];
  provider_disclaimer?: string;
  already_added: boolean;
  domain_id?: string | null;
}
