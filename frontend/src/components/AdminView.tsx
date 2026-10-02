import { useState } from "react";
import { getAdminOverview, listAdminDomains, listAdminScans, listAdminUsers } from "../api";
import { formatDate, relativeTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { Badge, ErrorBanner, PageHeader, Pagination, SkeletonRows } from "./ui";

const STATUS_TONE: Record<string, "success" | "warning" | "danger" | "neutral"> = {
  verified: "success", pending: "warning", failed: "danger",
  completed: "success", running: "warning", failed_scan: "danger",
};

function tone(status: string) {
  if (status === "failed") return "danger";
  return STATUS_TONE[status] ?? "neutral";
}

function Counts({ title, counts }: { title: string; counts: Record<string, number> }) {
  const entries = Object.entries(counts).filter(([, n]) => n > 0);
  return (
    <div className="panel stack">
      <h3>{title}</h3>
      {entries.length === 0 ? (
        <p className="muted">None yet.</p>
      ) : (
        <ul className="plain-list" role="list">
          {entries.map(([key, n]) => (
            <li key={key} className="connection-row">
              <Badge tone={tone(key)}>{key}</Badge>
              <span className="muted mono">{n}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Overview() {
  const { data, error, loading, reload } = useApi((signal) => getAdminOverview(signal), []);
  return (
    <section className="stack">
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <SkeletonRows rows={4} />}
      {data && (
        <div className="kpi-grid">
          <article className="kpi">
            <div className="kpi-head"><h2>Accounts</h2></div>
            <p className="kpi-figure"><span className="kpi-value">{data.user_count}</span></p>
            <p className="kpi-caption">registered users, across every account</p>
          </article>
          <Counts title="Targets, by verification status" counts={data.domain_counts} />
          <Counts title="Scans, by status" counts={data.scan_counts} />
          <Counts title="Open findings, by risk band" counts={data.finding_counts} />
        </div>
      )}
    </section>
  );
}

function Users() {
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useApi((signal) => listAdminUsers(page, signal), [page]);
  return (
    <section className="stack">
      <h2 className="section-title">Accounts</h2>
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <SkeletonRows rows={4} />}
      {data && (
        <>
          <ul className="plain-list" role="list">
            {data.users.map((u) => (
              <li key={u.id} className="connection-row">
                <span className="connection-name">
                  <strong>{u.name || u.email}</strong>
                  <span className="muted">
                    {u.email} · {u.domain_count} target{u.domain_count === 1 ? "" : "s"} ·{" "}
                    {u.scan_count} scan{u.scan_count === 1 ? "" : "s"}
                  </span>
                </span>
                <span className="cluster">
                  {u.is_admin && <Badge tone="neutral">Admin</Badge>}
                  <span className="muted" title={formatDate(u.created_at)}>
                    joined {relativeTime(u.created_at)}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <Pagination page={page} total={data.total} onPage={setPage} noun="accounts" />
        </>
      )}
    </section>
  );
}

function Domains() {
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useApi((signal) => listAdminDomains(page, signal), [page]);
  return (
    <section className="stack">
      <h2 className="section-title">Every account's targets</h2>
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <SkeletonRows rows={4} />}
      {data && (
        <>
          <ul className="plain-list" role="list">
            {data.domains.map((d) => (
              <li key={d.id} className="connection-row">
                <span className="connection-name">
                  <strong className="mono">{d.domain}</strong>
                  <span className="muted">
                    {d.owner_email} · {d.verification_method}
                  </span>
                </span>
                <Badge tone={tone(d.verification_status)}>{d.verification_status}</Badge>
              </li>
            ))}
          </ul>
          <Pagination page={page} total={data.total} onPage={setPage} noun="targets" />
        </>
      )}
    </section>
  );
}

function Scans() {
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useApi((signal) => listAdminScans(page, signal), [page]);
  return (
    <section className="stack">
      <h2 className="section-title">Every account's scans</h2>
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <SkeletonRows rows={4} />}
      {data && (
        <>
          <ul className="plain-list" role="list">
            {data.scans.map((s) => (
              <li key={s.scan_id} className="connection-row">
                <span className="connection-name">
                  <strong className="mono">{s.target_domain}</strong>
                  <span className="muted">
                    {s.owner_email ?? "no owner (predates accounts)"} · {s.profile} ·{" "}
                    {s.finding_count} finding{s.finding_count === 1 ? "" : "s"}
                  </span>
                </span>
                <span className="cluster">
                  <Badge tone={tone(s.status)}>{s.status}</Badge>
                  <span className="muted" title={formatDate(s.started_at)}>
                    {relativeTime(s.started_at)}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <Pagination page={page} total={data.total} onPage={setPage} noun="scans" />
        </>
      )}
    </section>
  );
}

export function AdminView() {
  return (
    <div className="stack">
      <PageHeader
        title="Admin"
        description="Read-only visibility across every account. It grants nothing else: starting a scan still needs a verified target you own yourself, exactly as for anyone."
      />
      <Overview />
      <Users />
      <Domains />
      <Scans />
    </div>
  );
}
