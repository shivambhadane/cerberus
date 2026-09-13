import { useEffect, useState } from "react";
import { ApiError, getFinding, updateFindingStatus } from "../api";
import type { FindingDetail as Detail } from "../types";
import { ExploitBadge, RiskScore } from "./RiskScore";

const STATUSES = ["open", "acknowledged", "resolved", "false_positive"];

export function FindingDetail({ findingId, onStatusChange }: {
  findingId: string;
  onStatusChange: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    setDetail(null);
    setError(null);
    getFinding(findingId)
      .then((d) => active && setDetail(d))
      .catch((e: ApiError) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [findingId]);

  async function changeStatus(status: string) {
    setSaving(true);
    try {
      setDetail(await updateFindingStatus(findingId, status));
      onStatusChange();
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setSaving(false);
    }
  }

  if (error) return <div className="panel detail banner error">{error}</div>;
  if (!detail) return <div className="panel detail dim">Loading…</div>;

  return (
    <div className="panel detail">
      <h2>{detail.cve_id}</h2>
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14 }}>
        <RiskScore score={detail.risk_score} />
        <ExploitBadge kev={detail.kev_listed} poc={detail.has_public_exploit} />
        <span className="badge status">{detail.status}</span>
      </div>

      <dl>
        <dt>Asset</dt>
        <dd>{detail.asset.hostname}:{detail.asset.port}</dd>
        <dt>CVSS</dt>
        <dd>{detail.cvss_score?.toFixed(1) ?? "—"}</dd>
        <dt>EPSS</dt>
        <dd>{detail.epss_score !== null ? `${(detail.epss_score * 100).toFixed(1)}%` : "—"}</dd>
        <dt>KEV added</dt>
        <dd>{detail.kev_date_added ?? "—"}</dd>
        <dt>Criticality</dt>
        <dd>{detail.asset_criticality ?? "—"}</dd>
      </dl>

      {detail.reasoning && (
        <p className="reasoning" style={{ marginBottom: 14 }}>
          <strong className="dim">Why this rank: </strong>
          {detail.reasoning}
        </p>
      )}

      <div className="row" style={{ marginBottom: 14 }}>
        <select
          value={detail.status}
          disabled={saving}
          onChange={(e) => changeStatus(e.target.value)}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {detail.description && <p className="desc">{detail.description}</p>}
    </div>
  );
}
