import { useEffect, useId } from "react";
import { ACTIVE_SCAN_STATUSES, getOverview, listFindings, listScans } from "../api";
import { relativeTime } from "../lib/format";
import { toHash } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { Overview, Scan } from "../types";
import { Icon } from "./icons";
import type { IconName } from "./icons";
import {
  Badge,
  DetectionBadge,
  EmptyState,
  ErrorBanner,
  ExploitBadge,
  NewScanLink,
  PageHeader,
  RiskScore,
  SkeletonRows,
  StatusBadge,
  TableWrap,
} from "./ui";

const TOP_RISKS = 6;
const RECENT_SCANS = 5;
const POLL_MS = 4000;

/* ---- KPI card ---------------------------------------------------------------------------- */

type Tone = "danger" | "success" | "info" | "warning";

function Kpi({
  icon,
  tone,
  title,
  value,
  qualifier,
  qualifierTone,
  caption,
  href,
  linkText,
}: {
  icon: IconName;
  tone: Tone;
  title: string;
  value: number;
  qualifier?: string;
  qualifierTone?: Tone;
  caption: string;
  href: string;
  linkText: string;
}) {
  const id = useId();
  return (
    <article className="kpi" aria-labelledby={id}>
      <div className="kpi-head">
        <span className={`kpi-icon kpi-icon-${tone}`}><Icon name={icon} /></span>
        <h2 id={id}>{title}</h2>
      </div>
      <p className="kpi-figure">
        <span className="kpi-value">{value.toLocaleString()}</span>
        {qualifier && <span className={`kpi-qualifier kpi-qualifier-${qualifierTone ?? tone}`}>{qualifier}</span>}
      </p>
      <p className="kpi-caption">
        {caption} <a href={href}>{linkText}<span className="sr-only">: {title.toLowerCase()}</span></a>
      </p>
    </article>
  );
}

/* ---- Bar list ---------------------------------------------------------------------------- */

interface BarRow {
  key: string;
  label: string;
  count: number;
  tone: "critical" | "high" | "medium" | "low" | "neutral" | "accent";
}

/**
 * A horizontal bar chart drawn as a list. Bars start at zero and are scaled to the share of the
 * whole, every bar is labelled with its count and percentage, and the list itself carries all of
 * the data, so nothing depends on seeing colour or the bar.
 */
function BarList({ rows, total }: { rows: BarRow[]; total: number }) {
  return (
    <ul className="bars" role="list">
      {rows.map((row) => {
        const share = total > 0 ? row.count / total : 0;
        return (
          <li key={row.key}>
            <span className="bar-label">{row.label}</span>
            <span className="bar-track" aria-hidden="true">
              <span className={`bar-fill bar-${row.tone}`} style={{ width: row.count > 0 ? `max(2px, ${share * 100}%)` : "0" }} />
            </span>
            <span className="bar-value">
              {row.count.toLocaleString()} <small>{Math.round(share * 100)}%</small>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function RiskBreakdown({ overview }: { overview: Overview }) {
  const { active, confirmed, by_risk_band: band } = overview.findings;
  const inferred = Math.max(0, active - confirmed);
  const severe = (band.critical ?? 0) + (band.high ?? 0);

  const bands: BarRow[] = [
    { key: "critical", label: "Critical", count: band.critical ?? 0, tone: "critical" },
    { key: "high", label: "High", count: band.high ?? 0, tone: "high" },
    { key: "medium", label: "Medium", count: band.medium ?? 0, tone: "medium" },
    { key: "low", label: "Low", count: band.low ?? 0, tone: "low" },
  ];
  if ((band.unscored ?? 0) > 0) bands.push({ key: "unscored", label: "Not scored", count: band.unscored, tone: "neutral" });

  return (
    <section className="panel" aria-labelledby="risk-breakdown-title">
      <div className="panel-head">
        <h2 id="risk-breakdown-title">Risk breakdown</h2>
      </div>

      <div className="chart-block">
        <h3 className="chart-title">
          {active === 0 ? "No active findings" : `${severe} of ${active} active findings are high or critical`}
        </h3>
        <p className="chart-sub">Score bands: critical 80 and up, high 60–79, medium 40–59, low below 40.</p>
        <BarList rows={bands} total={active} />
      </div>

      <div className="chart-block">
        <h3 className="chart-title">
          {active === 0 ? "Nothing to verify" : `${confirmed} of ${active} are confirmed by a scanner probe`}
        </h3>
        <p className="chart-sub">The rest are inferred: the service reports a version with a known CVE, but nothing tested it.</p>
        <BarList
          total={active}
          rows={[
            { key: "confirmed", label: "Confirmed", count: confirmed, tone: "accent" },
            { key: "inferred", label: "Inferred", count: inferred, tone: "neutral" },
          ]}
        />
      </div>
    </section>
  );
}

/* ---- Recent scans ------------------------------------------------------------------------ */

function RecentScans({ scans }: { scans: Scan[] }) {
  return (
    <section className="panel" aria-labelledby="recent-scans-title">
      <div className="panel-head">
        <h2 id="recent-scans-title">Recent scans</h2>
        <a href={toHash("scans", {})}>View all scans</a>
      </div>
      {scans.length === 0 ? (
        <p className="muted">No scans yet.</p>
      ) : (
        <TableWrap label="Latest five scans">
          <table className="table">
            <caption className="sr-only">The most recent scans, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">Status</th>
                <th scope="col" className="hide-sm">Profile</th>
                <th scope="col">Started</th>
                <th scope="col">Problems</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => {
                const problems = s.warnings.length + (s.error ? 1 : 0);
                return (
                  <tr key={s.scan_id}>
                    <td className="mono nowrap">{s.target_domain}</td>
                    <td><StatusBadge status={s.status} /></td>
                    <td className="capitalize hide-sm">{s.profile}</td>
                    <td className="muted nowrap">{relativeTime(s.started_at)}</td>
                    <td>
                      {problems > 0
                        ? <Badge tone={s.error ? "danger" : "warning"}>{problems} {problems === 1 ? "problem" : "problems"}</Badge>
                        : <span className="muted">None</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
    </section>
  );
}

/* ---- Page -------------------------------------------------------------------------------- */

const lastScanText = (s: Scan) =>
  `Last scan: ${s.target_domain}, ${ACTIVE_SCAN_STATUSES.includes(s.status) ? "running" : s.status} ${relativeTime(s.started_at)}`;

export function OverviewView() {
  const { data, error, loading, reload } = useApi(async (signal) => {
    const [overview, top, scans] = await Promise.all([
      getOverview(signal),
      listFindings({ status: "active", sort: "risk_score", order: "desc", pageSize: TOP_RISKS }, signal),
      listScans(1, signal, RECENT_SCANS),
    ]);
    return { overview, top: top.items, scans: scans.items };
  }, []);

  // While a scan is running the numbers are moving; keep them live.
  const running = data ? ACTIVE_SCAN_STATUSES.includes(data.overview.last_scan?.status ?? "") : false;
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(reload, POLL_MS);
    return () => clearInterval(timer);
  }, [running, reload]);

  const header = (
    <PageHeader
      title="Overview"
      description="What attackers are most likely to exploit against you, ranked by exploitation rather than severity."
      actions={
        <>
          {data?.overview.last_scan && <span className="chip" data-tone={data.overview.last_scan.status === "failed" ? "danger" : "ok"}>{lastScanText(data.overview.last_scan)}</span>}
          <NewScanLink />
        </>
      }
    />
  );

  if (error && !data) {
    return <>{header}<ErrorBanner error={error} onRetry={reload} /></>;
  }
  if (!data) {
    return (
      <>
        {header}
        <div className="panel" aria-busy={loading}><SkeletonRows rows={8} /></div>
      </>
    );
  }

  const { overview, top, scans } = data;
  const { findings, assets } = overview;

  if (overview.scans_total === 0) {
    return (
      <>
        {header}
        <div className="panel">
          <EmptyState title="Nothing has been scanned yet" action={<a className="btn btn-primary" href={toHash("domains", {})}>Add a domain</a>}>
            Cerberus discovers what a domain exposes, matches it against known vulnerabilities, and ranks
            what to fix first. Add a domain you own, prove it with a DNS record, then run your first scan.
          </EmptyState>
        </div>
      </>
    );
  }

  const critical = findings.by_risk_band.critical ?? 0;
  const criticalAssets = assets.by_criticality.critical ?? 0;

  return (
    <div className="stack">
      {header}
      {error && <ErrorBanner error={error} onRetry={reload} />}

      <div className="kpi-grid">
        <Kpi
          icon="findings"
          tone="warning"
          title="Active findings"
          value={findings.active}
          qualifier={critical > 0 ? `${critical} critical` : "None critical"}
          qualifierTone={critical > 0 ? "danger" : "success"}
          caption="Open or acknowledged."
          href={toHash("findings", {})}
          linkText="View all"
        />
        <Kpi
          icon="flame"
          tone="danger"
          title="Actively exploited"
          value={findings.actively_exploited}
          qualifier={findings.actively_exploited > 0 ? "Fix first" : "None"}
          qualifierTone={findings.actively_exploited > 0 ? "danger" : "success"}
          caption="Listed in CISA KEV: attackers are using these now."
          href={toHash("findings", { kev: true })}
          linkText="Show them"
        />
        <Kpi
          icon="check"
          tone="success"
          title="Confirmed"
          value={findings.confirmed}
          qualifier={`of ${findings.active}`}
          qualifierTone="info"
          caption="A scanner probe matched the host."
          href={toHash("findings", { detection: "active_detection" })}
          linkText="Show them"
        />
        <Kpi
          icon="assets"
          tone="info"
          title="Assets"
          value={assets.total}
          qualifier={criticalAssets > 0 ? `${criticalAssets} critical` : undefined}
          qualifierTone="danger"
          caption="Hosts and ports discovered."
          href={toHash("assets", {})}
          linkText="View all"
        />
      </div>

      <div className="overview-grid">
        <section aria-labelledby="top-risks-title">
          <div className="panel-head">
            <h2 id="top-risks-title">Top risks</h2>
            <a href={toHash("findings", {})}>View all findings</a>
          </div>
          {top.length === 0 ? (
            <div className="panel">
              <EmptyState title="No active findings" level={3}>
                Nothing open or acknowledged is matched to a known vulnerability. Resolved findings are
                still available under Findings.
              </EmptyState>
            </div>
          ) : (
            <ul className="card-grid" role="list">
              {top.map((f) => (
                <li key={f.id}>
                  <a
                    className="risk-card"
                    href={toHash("findings", { finding: f.id })}
                    aria-label={`${f.cve_id} on ${f.asset}, risk score ${f.risk_score?.toFixed(1) ?? "not scored"}. Show detail.`}
                  >
                    <span className="cluster" style={{ justifyContent: "space-between", flexWrap: "nowrap" }}>
                      <span className="cve">{f.cve_id}</span>
                      <span className="score"><RiskScore score={f.risk_score} /></span>
                    </span>
                    <span className="where">{f.asset}</span>
                    <span className="cluster">
                      <ExploitBadge kev={f.kev_listed} />
                      <DetectionBadge method={f.detection_method} />
                    </span>
                    {f.reasoning && <span className="clamp">{f.reasoning}</span>}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </section>

        <RiskBreakdown overview={overview} />
      </div>

      <RecentScans scans={scans} />
    </div>
  );
}
