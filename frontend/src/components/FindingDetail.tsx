import { useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { ApiError, getFinding, updateFindingStatus } from "../api";
import { formatDate, fixed1, percent } from "../lib/format";
import { toHash } from "../lib/router";
import type { Criticality, FindingDetail as Detail } from "../types";
import { CriticalityEditor } from "./CriticalityEditor";
import { Banner, DetectionBadge, ErrorBanner, ExploitBadge, RiskScore, SkeletonRows, StatusBadge } from "./ui";

const STATUSES = [
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
];

export function FindingDetail({
  findingId,
  onClose,
  onChanged,
}: {
  findingId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  const statusId = useId();

  useEffect(() => {
    const controller = new AbortController();
    setDetail(null);
    setError(null);
    setNotice("");
    getFinding(findingId, controller.signal)
      .then(setDetail)
      .catch((e: ApiError) => e.name !== "AbortError" && setError(e));
    return () => controller.abort();
  }, [findingId]);

  // Move focus into the panel once it has content, so a keyboard user lands on it.
  useEffect(() => {
    if (detail) heading.current?.focus();
  }, [detail?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function changeStatus(status: string) {
    setSaving(true);
    try {
      setDetail(await updateFindingStatus(findingId, status));
      setNotice(`Status set to ${status.replace("_", " ")}.`);
      onChanged();
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setSaving(false);
    }
  }

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") onClose();
  };

  return (
    <aside className="panel detail" id="finding-detail" aria-label="Finding detail" onKeyDown={onKeyDown}>
      {error && <ErrorBanner error={error} />}
      {!detail && !error && <SkeletonRows rows={6} />}
      {detail && (
        <div className="stack">
          <div className="cluster" style={{ justifyContent: "space-between" }}>
            <h2 ref={heading} tabIndex={-1} className="mono">{detail.cve_id}</h2>
            <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>
              Close<span className="sr-only"> finding detail</span>
            </button>
          </div>

          <div className="cluster">
            <RiskScore score={detail.risk_score} />
            <ExploitBadge kev={detail.kev_listed} poc={detail.has_public_exploit} />
            <DetectionBadge method={detail.detection_method} />
            <StatusBadge status={detail.status} />
          </div>

          <dl className="kv">
            <dt>Asset</dt>
            <dd>{detail.asset.hostname}:{detail.asset.port}</dd>
            <dt>CVSS</dt>
            <dd>{fixed1(detail.cvss_score)}</dd>
            <dt>EPSS</dt>
            <dd>{percent(detail.epss_score)}</dd>
            <dt>KEV added</dt>
            <dd>{detail.kev_date_added ?? "Not listed"}</dd>
            <dt>Found by</dt>
            <dd>{detail.detected_by_tool ?? "version match"}</dd>
            <dt>Detected</dt>
            <dd>{formatDate(detail.detected_at)}</dd>
          </dl>

          <section aria-labelledby={`${statusId}-crit`}>
            <h3 id={`${statusId}-crit`} className="field-label" style={{ marginBottom: "var(--space-2)" }}>Asset criticality</h3>
            <CriticalityEditor
              asset={{
                id: detail.asset.id,
                hostname: detail.asset.hostname,
                port: detail.asset.port,
                criticality: (detail.asset_criticality as Criticality | null) ?? null,
                criticality_reason: detail.asset_criticality_reason,
                criticality_source: detail.asset_criticality_source,
              }}
              onSaved={() => {
                setNotice("Criticality saved. This asset's findings have been re-ranked.");
                onChanged();
                getFinding(findingId).then(setDetail).catch(() => undefined);
              }}
            />
          </section>

          {detail.reasoning && (
            <p className="reasoning-text">
              <strong>Why this rank. </strong>
              {detail.reasoning}
            </p>
          )}
          {detail.evidence && (
            <p className="reasoning-text">
              <strong>How it was found. </strong>
              {detail.evidence}
            </p>
          )}

          <div className="field">
            <label className="field-label" htmlFor={statusId}>Finding status</label>
            <select id={statusId} className="select" value={detail.status} disabled={saving} onChange={(e) => void changeStatus(e.target.value)}>
              {STATUSES.map((s) => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
          </div>

          <div role="status" aria-live="polite">
            {notice && <Banner tone="success">{notice}</Banner>}
          </div>

          {detail.description && <p className="reasoning-text">{detail.description}</p>}

          <div className="detail-actions">
            <a className="btn btn-secondary btn-sm" href={toHash("evidence", { target: `${detail.asset.hostname}:${detail.asset.port}` })}>
              View evidence for this asset
            </a>
          </div>
        </div>
      )}
    </aside>
  );
}
