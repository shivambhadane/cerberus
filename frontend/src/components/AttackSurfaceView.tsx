import { useEffect, useState } from "react";
import { ApiError, listAssets, listDomains, listFindings } from "../api";
import { toHash } from "../lib/router";
import type { Asset, Domain, Finding } from "../types";
import { Badge, EmptyState, ErrorBanner, PageHeader, RiskScore, SkeletonRows, StatusBadge } from "./ui";

/** Every asset/finding page, not just the first, up to a sane ceiling. This view's whole point
 * is to show the complete chain from domain to finding, not a paginated slice of it. */
async function fetchAll<T>(
  page: (n: number, signal?: AbortSignal) => Promise<{ total: number; items: T[] }>,
  signal?: AbortSignal,
): Promise<T[]> {
  const items: T[] = [];
  for (let n = 1; n <= 20; n++) {
    const data = await page(n, signal);
    items.push(...data.items);
    if (items.length >= data.total || data.items.length === 0) break;
  }
  return items;
}

/** Which verified domain an asset's hostname belongs to - the same suffix rule core/scope.py
 * uses for authorization, used here only for display grouping. */
function domainFor(hostname: string, domains: Domain[]): Domain | null {
  const host = hostname.toLowerCase();
  return domains.find((d) => host === d.domain || host.endsWith(`.${d.domain}`)) ?? null;
}

const CRIT_TONE: Record<string, "neutral" | "warning" | "danger"> = {
  low: "neutral", medium: "neutral", high: "warning", critical: "danger",
};

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <li>
      <a className="plain-list-link" href={toHash("findings", { finding: finding.id })}>
        <span className="cluster">
          <RiskScore score={finding.risk_score} />
          <span className="mono">{finding.cve_id}</span>
          {finding.kev_listed && <Badge tone="danger">KEV</Badge>}
          <StatusBadge status={finding.status} />
        </span>
        <span className="sr-only">Open {finding.cve_id} on {finding.asset}</span>
      </a>
    </li>
  );
}

function AssetNode({ asset, findings }: { asset: Asset; findings: Finding[] }) {
  return (
    <li className="connection">
      <div className="connection-row">
        <span className="connection-name">
          <strong className="mono">{asset.hostname}:{asset.port}</strong>
          <span className="muted">
            {asset.ip_address ?? "no resolved IP"} · {asset.protocol}
            {asset.technology ? ` · ${asset.technology}` : ""}
          </span>
        </span>
        <span className="cluster">
          {asset.criticality && <Badge tone={CRIT_TONE[asset.criticality] ?? "neutral"}>{asset.criticality}</Badge>}
          <a className="btn btn-ghost btn-sm" href={toHash("evidence", { target: `${asset.hostname}:${asset.port}` })}>
            Evidence
          </a>
        </span>
      </div>
      {findings.length > 0 ? (
        <ul className="plain-list" role="list" aria-label={`Findings on ${asset.hostname}:${asset.port}`}>
          {findings.map((f) => <FindingRow key={f.id} finding={f} />)}
        </ul>
      ) : (
        <p className="field-hint">No findings on this asset.</p>
      )}
    </li>
  );
}

function DomainNode({ domain, assets, findingsByAsset }: {
  domain: Domain; assets: Asset[]; findingsByAsset: Map<string, Finding[]>;
}) {
  return (
    <article className="panel stack" aria-labelledby={`surface-${domain.id}`}>
      <div className="provider-head">
        <div className="provider-title">
          <h2 id={`surface-${domain.id}`} className="mono">{domain.domain}</h2>
          <span className="field-hint">{assets.length} asset{assets.length === 1 ? "" : "s"} discovered</span>
        </div>
      </div>
      {assets.length === 0 ? (
        <p className="field-hint">Nothing discovered yet. Run a scan to populate this domain's surface.</p>
      ) : (
        <ul className="plain-list connection-list" role="list" aria-label={`Assets on ${domain.domain}`}>
          {assets.map((a) => <AssetNode key={a.id} asset={a} findings={findingsByAsset.get(a.id) ?? []} />)}
        </ul>
      )}
    </article>
  );
}

export function AttackSurfaceView() {
  const [domains, setDomains] = useState<Domain[] | null>(null);
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    Promise.all([
      listDomains(controller.signal),
      fetchAll(listAssets, controller.signal),
      fetchAll((n, signal) => listFindings({ pageSize: 100, page: n }, signal), controller.signal),
    ])
      .then(([d, a, f]) => {
        setDomains(d.filter((x) => x.verification_status === "verified"));
        setAssets(a);
        setFindings(f);
      })
      .catch((e: ApiError) => e.name !== "AbortError" && setError(e));
    return () => controller.abort();
  }, []);

  const loading = !domains || !assets || !findings;

  return (
    <div className="stack">
      <PageHeader
        title="Attack Surface"
        description="Every verified target, traced from domain through asset to finding. Each row links back to the scan evidence behind it - nothing here is summarised away from what a scan actually found."
      />
      {error && <ErrorBanner error={error} />}
      {loading && !error && <SkeletonRows rows={6} />}
      {!loading && domains!.length === 0 && (
        <div className="panel">
          <EmptyState title="No verified targets yet" action={<a className="btn btn-primary" href={toHash("domains", {})}>Go to Targets</a>}>
            Verify a domain or a deployment first, then its discovered assets and findings will map out here.
          </EmptyState>
        </div>
      )}
      {!loading && domains!.length > 0 && (
        <div className="stack">
          {domains!.map((domain) => {
            const domainAssets = assets!.filter((a) => domainFor(a.hostname, domains!)?.id === domain.id);
            const byAsset = new Map<string, Finding[]>();
            for (const f of findings!) {
              if (!domainAssets.some((a) => a.id === f.asset_id)) continue;
              byAsset.set(f.asset_id, [...(byAsset.get(f.asset_id) ?? []), f]);
            }
            return <DomainNode key={domain.id} domain={domain} assets={domainAssets} findingsByAsset={byAsset} />;
          })}
        </div>
      )}
    </div>
  );
}
