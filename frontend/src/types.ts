export interface Finding {
  id: string;
  asset: string;
  cve_id: string;
  cvss_score: number | null;
  kev_listed: boolean;
  epss_score: number | null;
  asset_criticality: string | null;
  risk_score: number | null;
  status: string;
  reasoning: string | null;
  detected_at: string;
}

export interface FindingDetail extends Omit<Finding, "asset"> {
  asset: { id: string; hostname: string; port: number };
  kev_date_added: string | null;
  has_public_exploit: boolean;
  description: string | null;
}

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string | null;
  port: number;
  protocol: string;
  technology: string | null;
  first_seen_at: string;
  last_seen_at: string;
}

export interface SourceStatus {
  name: string;
  last_refreshed_at: string;
  record_count: number;
}

export interface Scan {
  scan_id: string;
  target_domain: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  error: string | null;
}

export interface FindingFilters {
  kevOnly: boolean;
  minRiskScore: string;
}
