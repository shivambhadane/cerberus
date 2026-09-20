import { useEffect, useId, useState } from "react";
import { listFindings } from "../api";
import { fixed1, percent } from "../lib/format";
import { toHash, useRoute } from "../lib/router";
import { useApi } from "../lib/useApi";
import { FindingDetail } from "./FindingDetail";
import {
  DetectionBadge,
  EmptyState,
  ErrorBanner,
  ExploitBadge,
  NewScanLink,
  PageHeader,
  Pagination,
  RiskScore,
  SkeletonRows,
  SortHeader,
  StatusBadge,
  TableWrap,
} from "./ui";

const STATUS_OPTIONS = [
  { value: "active", label: "Active (open and acknowledged)" },
  { value: "all", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
];

export function FindingsView() {
  const { params, patch, navigate } = useRoute();
  const ids = { search: useId(), status: useId(), detection: useId(), min: useId() };

  const q = params.get("q") ?? "";
  const status = params.get("status") ?? "active";
  const detection = params.get("detection") ?? "";
  const kevOnly = params.get("kev") === "1";
  const minRisk = params.get("min") ?? "";
  const assetId = params.get("asset") ?? "";
  const sort = params.get("sort") ?? "risk_score";
  const order = params.get("order") ?? "desc";
  const page = Math.max(1, Number(params.get("page") ?? "1") || 1);
  const selected = params.get("finding");

  // The search box is local state so typing stays instant; the URL (and the query) follow it
  // after a short pause. The URL is the source of truth, so the back button restores it.
  const [search, setSearch] = useState(q);
  useEffect(() => setSearch(q), [q]);
  useEffect(() => {
    if (search === q) return;
    const timer = setTimeout(() => patch({ q: search || undefined, page: undefined, finding: undefined }), 300);
    return () => clearTimeout(timer);
  }, [search]); // eslint-disable-line react-hooks/exhaustive-deps

  const { data, error, loading, reload } = useApi(
    (signal) =>
      listFindings(
        { q, status: status === "all" ? undefined : status, detection, assetId, kevOnly, minRisk, sort, order, page },
        signal,
      ),
    [q, status, detection, assetId, kevOnly, minRisk, sort, order, page],
  );

  const filtered = Boolean(q || status !== "active" || detection || kevOnly || minRisk || assetId);
  const items = data?.items ?? [];

  const onSort = (field: string) => {
    const same = sort === field;
    patch({ sort: field, order: same && order === "desc" ? "asc" : "desc", page: undefined });
  };

  const select = (id: string) => patch({ finding: selected === id ? undefined : id });
  const closeDetail = () => {
    const previous = selected;
    patch({ finding: undefined });
    // Return focus to the row the panel was opened from.
    requestAnimationFrame(() => document.getElementById(`open-${previous}`)?.focus());
  };

  const clearFilters = () => navigate("findings", {});

  return (
    <div className="stack">
      <PageHeader
        title="Findings"
        description="Every weakness matched to a known CVE, ranked by how likely attackers are to exploit it."
        actions={<NewScanLink />}
      />
      <form className="panel toolbar" role="search" aria-label="Filter findings" onSubmit={(e) => e.preventDefault()}>
        <div className="field grow">
          <label className="field-label" htmlFor={ids.search}>Search CVE or host</label>
          <input id={ids.search} type="search" className="input" value={search} placeholder="CVE-2021-41773 or api.example.com" onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="field">
          <label className="field-label" htmlFor={ids.status}>Status</label>
          <select id={ids.status} className="select" value={status} onChange={(e) => patch({ status: e.target.value === "active" ? undefined : e.target.value, page: undefined, finding: undefined })}>
            {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor={ids.detection}>Evidence</label>
          <select id={ids.detection} className="select" value={detection} onChange={(e) => patch({ detection: e.target.value || undefined, page: undefined, finding: undefined })}>
            <option value="">Confirmed and inferred</option>
            <option value="active_detection">Confirmed only</option>
            <option value="version_inference">Inferred only</option>
          </select>
        </div>
        <div className="field">
          <label className="field-label" htmlFor={ids.min}>Minimum risk</label>
          <input id={ids.min} type="number" min={0} max={100} className="input" style={{ width: "6.5rem" }} value={minRisk} onChange={(e) => patch({ min: e.target.value || undefined, page: undefined })} />
        </div>
        <label className="check">
          <input type="checkbox" checked={kevOnly} onChange={(e) => patch({ kev: e.target.checked || undefined, page: undefined })} />
          Actively exploited only
        </label>
        {filtered && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={clearFilters}>Clear filters</button>
        )}
      </form>

      {assetId && items[0] && (
        <p className="legend" role="status">
          Showing findings for one asset, <strong className="mono">{items[0].asset}</strong>.{" "}
          <a href={toHash("findings", {})}>Show all assets</a>
        </p>
      )}

      <p className="legend">
        <strong>Confirmed</strong>: a scanner probe matched the host. <strong>Inferred</strong>: the service
        reports a version with a known CVE, but nothing tested it. Both are ranked the same way; they differ
        in how sure we are the weakness exists.
      </p>

      {error && <ErrorBanner error={error} onRetry={reload} />}

      <div className={`split ${selected ? "with-detail" : ""}`}>
        <div className="panel">
          {!data && loading && <SkeletonRows rows={8} />}

          {data && items.length === 0 && (
            filtered ? (
              <EmptyState
                title="No findings match these filters"
                action={<button type="button" className="btn btn-secondary" onClick={clearFilters}>Clear filters</button>}
              >
                Try a broader search, or include resolved findings using the status filter.
              </EmptyState>
            ) : (
              <EmptyState
                title="No findings yet"
                action={<a className="btn btn-primary" href={toHash("scans", {})}>Start a scan</a>}
              >
                Findings appear here once a scan has discovered assets and matched them to known
                vulnerabilities, ranked by how likely attackers are to exploit them.
              </EmptyState>
            )
          )}

          {data && items.length > 0 && (
            <TableWrap label="Findings" busy={loading}>
              <table className="table">
                <caption className="sr-only">Findings, ranked by {sort.replace("_", " ")}</caption>
                <thead>
                  <tr>
                    <SortHeader label="Risk" field="risk_score" sort={sort} order={order} onSort={onSort} numeric />
                    <th scope="col">CVE</th>
                    <th scope="col">Exploited</th>
                    <th scope="col" className="col-evidence">Evidence</th>
                    <SortHeader label="CVSS" field="cvss_score" sort={sort} order={order} onSort={onSort} numeric />
                    <SortHeader label="EPSS" field="epss_score" sort={sort} order={order} onSort={onSort} numeric />
                    <th scope="col">Asset</th>
                    <th scope="col" className="hide-sm col-status">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((f) => (
                    <tr key={f.id} className="clickable" data-selected={selected === f.id} onClick={() => select(f.id)}>
                      <td className="num"><RiskScore score={f.risk_score} /></td>
                      <td>
                        <button
                          type="button"
                          id={`open-${f.id}`}
                          className="row-button"
                          aria-expanded={selected === f.id}
                          aria-controls="finding-detail"
                          onClick={(e) => { e.stopPropagation(); select(f.id); }}
                        >
                          {f.cve_id}
                          <span className="sr-only"> on {f.asset}, show detail</span>
                        </button>
                        {f.reasoning && <p className="clamp">{f.reasoning}</p>}
                      </td>
                      <td><ExploitBadge kev={f.kev_listed} /></td>
                      <td className="col-evidence"><DetectionBadge method={f.detection_method} /></td>
                      <td className="num muted">{fixed1(f.cvss_score)}</td>
                      <td className="num muted">{percent(f.epss_score)}</td>
                      <td className="mono nowrap">{f.asset}</td>
                      <td className="hide-sm col-status"><StatusBadge status={f.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}

          {data && (
            <Pagination page={page} total={data.total} noun="findings" onPage={(p) => patch({ page: p === 1 ? undefined : p, finding: undefined }, false)} />
          )}
        </div>

        {selected && <FindingDetail findingId={selected} onClose={closeDetail} onChanged={reload} />}
      </div>
    </div>
  );
}
