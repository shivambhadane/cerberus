import { Fragment, useId, useState } from "react";
import { listObservations } from "../api";
import { formatDate } from "../lib/format";
import { toHash, useRoute } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { Observation } from "../types";
import { Badge, EmptyState, ErrorBanner, NewScanLink, PageHeader, Pagination, SkeletonRows, TableWrap } from "./ui";

const KINDS = [
  { value: "", label: "All kinds" },
  { value: "subdomain", label: "Subdomains" },
  { value: "open_port", label: "Open ports" },
  { value: "technology", label: "Technologies" },
  { value: "vulnerability", label: "Vulnerability detections" },
];

/** One-line summary of what a tool saw. */
function summarize(o: Observation): string {
  const d = o.data as Record<string, unknown>;
  const text = (v: unknown) => (v === undefined || v === null || v === "" ? null : String(v));

  switch (o.kind) {
    case "vulnerability": {
      // For CVE templates the template id is the CVE id, so don't print it twice.
      const cves = Array.isArray(d.cve_ids) ? (d.cve_ids as string[]).filter((c) => c !== d.template_id).join(", ") : "";
      return [text(d.template_id), text(d.severity), cves].filter(Boolean).join(" · ");
    }
    case "technology":
    case "open_port":
      return [text(d.technology), text(d.service)].filter(Boolean).join(" · ") || "Port open";
    case "subdomain":
      return text(d.ip_address) ?? "";
    default:
      return "";
  }
}

export function ObservationsView() {
  const { params, patch, navigate } = useRoute();
  const kindId = useId();
  const kind = params.get("kind") ?? "";
  const scanId = params.get("scan") ?? "";
  const target = params.get("target") ?? "";
  const page = Math.max(1, Number(params.get("page") ?? "1") || 1);
  const [open, setOpen] = useState<string | null>(null);

  const { data, error, loading, reload } = useApi(
    (signal) => listObservations({ kind, scanId, target, page }, signal),
    [kind, scanId, target, page],
  );
  const items = data?.items ?? [];
  const filtered = Boolean(kind || scanId || target);

  return (
    <div className="stack">
      <PageHeader title="Evidence" description="What each tool actually saw, before Cerberus drew any conclusion." actions={<NewScanLink />} />
      <p className="legend">
        Raw tool output, exactly as recorded <strong>before</strong> Cerberus normalized it. Every asset and
        finding traces back to rows here: an asset says what Cerberus concluded, an observation says what a
        tool actually saw.
      </p>

      <form className="panel toolbar" role="search" aria-label="Filter evidence" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label className="field-label" htmlFor={kindId}>Kind</label>
          <select id={kindId} className="select" value={kind} onChange={(e) => patch({ kind: e.target.value || undefined, page: undefined })}>
            {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
          </select>
        </div>
        {target && <Badge tone="info">Asset {target}</Badge>}
        {scanId && <Badge tone="info">One scan</Badge>}
        {filtered && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => navigate("evidence", {})}>Clear filters</button>
        )}
      </form>

      {error && <ErrorBanner error={error} onRetry={reload} />}

      <div className="panel">
        {!data && loading && <SkeletonRows rows={6} />}

        {data && items.length === 0 && (
          <EmptyState
            title={filtered ? "No evidence matches these filters" : "No evidence recorded yet"}
            action={filtered ? undefined : <a className="btn btn-primary" href={toHash("scans", {})}>Start a scan</a>}
          >
            {filtered
              ? "Try clearing the filters."
              : "Each scan records what every tool saw. Run one and the raw output will be listed here."}
          </EmptyState>
        )}

        {data && items.length > 0 && (
          <TableWrap label="Evidence" busy={loading}>
            <table className="table">
              <caption className="sr-only">Raw tool observations</caption>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Target</th>
                  <th scope="col">Observed</th>
                  <th scope="col">What it saw</th>
                </tr>
              </thead>
              <tbody>
                {items.map((o) => (
                  <Fragment key={o.id}>
                    <tr data-selected={open === o.id}>
                      <td>
                        <button
                          type="button"
                          className="row-button"
                          aria-expanded={open === o.id}
                          aria-controls={`raw-${o.id}`}
                          onClick={() => setOpen(open === o.id ? null : o.id)}
                        >
                          {o.source_tool}
                          <span className="sr-only">, {open === o.id ? "hide" : "show"} raw data</span>
                        </button>
                        {o.source_version && <p className="muted mono">{o.source_version}</p>}
                      </td>
                      <td><Badge tone="neutral">{o.kind.replace("_", " ")}</Badge></td>
                      <td className="mono nowrap">{o.target}</td>
                      <td className="muted nowrap">{formatDate(o.observed_at)}</td>
                      <td className="muted">{summarize(o)}</td>
                    </tr>
                    {open === o.id && (
                      <tr id={`raw-${o.id}`}>
                        <td colSpan={5}>
                          <pre className="mono muted" style={{ margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                            {JSON.stringify(o.data, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}

        {data && <Pagination page={page} total={data.total} noun="observations" onPage={(p) => patch({ page: p === 1 ? undefined : p }, false)} />}
      </div>
    </div>
  );
}
