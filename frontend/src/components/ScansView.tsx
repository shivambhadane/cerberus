import { Fragment, useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ACTIVE_SCAN_STATUSES as ACTIVE, ApiError, listDomains, listScans, startScan } from "../api";
import { duration, formatDate, relativeTime } from "../lib/format";
import { toHash, useRoute } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { Domain, Scan } from "../types";
import { Badge, Banner, EmptyState, ErrorBanner, PageHeader, Pagination, SkeletonRows, StatusBadge, TableWrap } from "./ui";

const POLL_MS = 4000;

const PROFILES = [
  { id: "safe", label: "Safe", note: "Default", description: "Non-destructive detection only: known CVEs, exposed panels and files, misconfiguration and TLS issues, at medium severity and above.", optIn: false },
  { id: "passive", label: "Passive", note: "", description: "Never contacts the target. Certificate transparency and DNS only, so it finds names but no ports or vulnerabilities.", optIn: false },
  { id: "thorough", label: "Thorough", note: "Opt-in", description: "Broader coverage for targets you own: adds low and informational severity and default-credential checks. Still non-destructive.", optIn: true },
] as const;

function ScanForm({
  domains,
  initialDomainId,
  disabled,
  onStarted,
}: {
  domains: Domain[];
  initialDomainId: string | null;
  disabled: boolean;
  onStarted: () => void;
}) {
  const ids = { domain: useId(), accept: useId() };
  const verified = domains.filter((d) => d.verification_status === "verified");
  const [domainId, setDomainId] = useState(
    verified.find((d) => d.id === initialDomainId)?.id ?? verified[0]?.id ?? "",
  );
  const [profile, setProfile] = useState<string>("safe");
  const [accepted, setAccepted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = PROFILES.find((p) => p.id === profile) ?? PROFILES[0];
  const ready = domainId !== "" && (!selected.optIn || accepted);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await startScan(domainId, profile, accepted);
      onStarted();
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="panel stack" onSubmit={submit} aria-labelledby="new-scan-title">
      <h2 id="new-scan-title">Start a scan</h2>

      <Banner tone="warning">
        Cerberus performs active reconnaissance, so it only scans domains you have proven you own. To scan
        a local lab (loopback or private addresses), use the CLI with <code>--allow-private</code>.
      </Banner>

      <div className="field" style={{ maxWidth: "28rem" }}>
        <label className="field-label" htmlFor={ids.domain}>Domain to scan</label>
        <select id={ids.domain} className="select" value={domainId} onChange={(e) => setDomainId(e.target.value)} disabled={disabled}>
          {verified.map((d) => <option key={d.id} value={d.id}>{d.domain}</option>)}
        </select>
      </div>

      <fieldset style={{ border: 0, padding: 0, margin: 0 }} disabled={disabled}>
        <legend className="field-label" style={{ marginBottom: "var(--space-2)" }}>Scan profile</legend>
        <div className="stack" style={{ gap: "var(--space-1)" }}>
          {PROFILES.map((p) => (
            <label key={p.id} className="check" style={{ alignItems: "flex-start", minHeight: "auto", padding: "var(--space-1) 0" }}>
              <input type="radio" name="profile" value={p.id} checked={profile === p.id} style={{ marginTop: "0.2rem" }}
                onChange={() => { setProfile(p.id); setAccepted(false); }} />
              <span>
                <strong>{p.label}</strong> {p.note && <span className="muted">({p.note})</span>}
                <span className="muted" style={{ display: "block", fontSize: "var(--text-sm)" }}>{p.description}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      {selected.optIn && (
        <label className="check" htmlFor={ids.accept}>
          <input id={ids.accept} type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} />
          I understand this profile probes more broadly, and I accept it for this scan.
        </label>
      )}

      {error && <p role="alert" style={{ color: "var(--danger-text)" }}>{error}</p>}
      {disabled && <p className="muted" role="status">A scan is already running. Only one runs at a time.</p>}

      <div>
        <button type="submit" className="btn btn-primary" disabled={!ready || submitting || disabled}>
          {submitting ? "Starting…" : "Start scan"}
        </button>
      </div>
    </form>
  );
}

function ScanRow({ scan, open, onToggle }: { scan: Scan; open: boolean; onToggle: () => void }) {
  const running = ACTIVE.includes(scan.status);
  const problems = scan.warnings.length + (scan.error ? 1 : 0);
  return (
    <Fragment>
      <tr data-selected={open}>
        <td>
          <button type="button" className="row-button" aria-expanded={open} aria-controls={`scan-${scan.scan_id}`} onClick={onToggle}>
            {scan.target_domain}
            <span className="sr-only">, {open ? "hide" : "show"} scan details</span>
          </button>
        </td>
        <td><StatusBadge status={scan.status} /></td>
        <td className="capitalize">{scan.profile}</td>
        <td className="muted nowrap" title={formatDate(scan.started_at)}>{relativeTime(scan.started_at)}</td>
        <td className="muted nowrap">{running ? "running…" : duration(scan.started_at, scan.completed_at)}</td>
        <td className="num">
          {(scan.observation_count ?? 0) > 0 ? (
            <a href={toHash("evidence", { scan: scan.scan_id })}>{scan.observation_count}<span className="sr-only"> observations from this scan</span></a>
          ) : "0"}
        </td>
        <td>{problems > 0 ? <Badge tone={scan.error ? "danger" : "warning"}>{problems} {problems === 1 ? "problem" : "problems"}</Badge> : <span className="muted">None</span>}</td>
      </tr>
      {open && (
        <tr id={`scan-${scan.scan_id}`}>
          <td colSpan={7}>
            <div className="stack" style={{ gap: "var(--space-2)" }}>
              <p className="muted mono">Scan {scan.scan_id} · started {formatDate(scan.started_at)}</p>
              {scan.error && <Banner tone="error" role="alert"><strong>The scan failed.</strong>{scan.error}</Banner>}
              {scan.warnings.length > 0 && (
                <Banner tone="warning">
                  <strong>The scan finished, but not everything ran.</strong>
                  <ul style={{ margin: "var(--space-1) 0 0", paddingLeft: "var(--space-4)" }}>
                    {scan.warnings.map((w) => <li key={w}>{w}</li>)}
                  </ul>
                </Banner>
              )}
              {problems === 0 && <p className="muted">No problems were reported by any tool.</p>}
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  );
}

export function ScansView({ onScanFinished }: { onScanFinished: () => void }) {
  const { params, patch } = useRoute();
  const page = Math.max(1, Number(params.get("page") ?? "1") || 1);
  const { data, error, reload } = useApi((signal) => listScans(page, signal), [page]);
  const domains = useApi((signal) => listDomains(signal), []);
  const hasVerified = domains.data?.some((d) => d.verification_status === "verified") ?? false;
  const [open, setOpen] = useState<string | null>(null);
  const [announce, setAnnounce] = useState("");

  const active = data?.items.some((s) => ACTIVE.includes(s.status)) ?? false;

  // Poll while something is running; announce, and refresh the banner, when it finishes.
  const wasActive = useRef(false);
  useEffect(() => {
    if (wasActive.current && !active && data) {
      setAnnounce("The scan has finished.");
      onScanFinished();
    }
    wasActive.current = active;
    if (!active) return;
    const timer = setInterval(reload, POLL_MS);
    return () => clearInterval(timer);
  }, [active, data]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="stack">
      <PageHeader title="Scans" description="Start a scan and follow what each one found and what it could not run." />
      {domains.data && hasVerified && (
        <ScanForm
          domains={domains.data}
          initialDomainId={params.get("domain")}
          disabled={active}
          onStarted={() => { setAnnounce("Scan started."); reload(); }}
        />
      )}
      {domains.data && !hasVerified && (
        <div className="panel">
          <EmptyState title="Verify a domain first" action={<a className="btn btn-primary" href={toHash("domains", {})}>Go to Targets</a>}>
            Cerberus only scans domains you have proven you own. Add one, publish the DNS record it gives you,
            and it will appear here ready to scan.
          </EmptyState>
        </div>
      )}
      {domains.error && <ErrorBanner error={domains.error} onRetry={domains.reload} />}
      <div role="status" aria-live="polite" className="sr-only">{announce}</div>

      {error && <ErrorBanner error={error} onRetry={reload} />}

      <section className="panel" aria-labelledby="history-title">
        <h2 id="history-title" style={{ marginBottom: "var(--space-3)" }}>Scan history</h2>
        {!data && <SkeletonRows rows={4} />}

        {data && data.items.length === 0 && (
          <EmptyState title="No scans yet" level={3}>
            Start one above. It discovers what a domain exposes, matches it against known vulnerabilities,
            and ranks what to fix first. A safe-profile scan of a small target takes a few minutes.
          </EmptyState>
        )}

        {data && data.items.length > 0 && (
          <TableWrap label="Scans, newest first" busy={active}>
            <table className="table">
              <caption className="sr-only">Scans, newest first</caption>
              <thead>
                <tr>
                  <th scope="col">Target</th>
                  <th scope="col">Status</th>
                  <th scope="col">Profile</th>
                  <th scope="col">Started</th>
                  <th scope="col">Duration</th>
                  <th scope="col" className="num">Evidence</th>
                  <th scope="col">Problems</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <ScanRow key={s.scan_id} scan={s} open={open === s.scan_id} onToggle={() => setOpen(open === s.scan_id ? null : s.scan_id)} />
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}

        {data && <Pagination page={page} total={data.total} noun="scans" onPage={(p) => patch({ page: p === 1 ? undefined : p }, false)} />}
      </section>
    </div>
  );
}
