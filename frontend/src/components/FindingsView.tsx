import { useCallback, useEffect, useState } from "react";
import { ApiError, listFindings } from "../api";
import type { Finding } from "../types";
import { FindingDetail } from "./FindingDetail";
import { ExploitBadge, RiskScore } from "./RiskScore";

export function FindingsView() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [kevOnly, setKevOnly] = useState(false);
  const [minRiskScore, setMinRiskScore] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listFindings({ kevOnly, minRiskScore });
      setFindings(data.findings);
      setTotal(data.total);
      setError(null);
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setLoading(false);
    }
  }, [kevOnly, minRiskScore]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <div className="panel">
        <div className="controls">
          <label>
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={(e) => setKevOnly(e.target.checked)}
            />
            Actively exploited only
          </label>
          <label>
            Min risk
            <input
              type="number"
              style={{ width: 80 }}
              value={minRiskScore}
              min={0}
              max={100}
              onChange={(e) => setMinRiskScore(e.target.value)}
            />
          </label>
          <span className="spacer" />
          <span className="dim">{total} findings</span>
          <button onClick={() => void load()} disabled={loading}>
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className={`layout ${selected ? "with-detail" : ""}`}>
        <div className="panel">
          {findings.length === 0 && !loading ? (
            <p className="empty">
              No findings yet. Run a scan from the Scan tab, or
              <br />
              <code className="mono">python cerberus.py scan --target example.com --authorized</code>
            </p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th className="num">Risk</th>
                  <th>CVE</th>
                  <th>Exploited</th>
                  <th className="num">CVSS</th>
                  <th className="num">EPSS</th>
                  <th>Asset</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    aria-selected={selected === f.id}
                    onClick={() => setSelected(selected === f.id ? null : f.id)}
                  >
                    <td className="num"><RiskScore score={f.risk_score} /></td>
                    <td>
                      <div className="mono">{f.cve_id}</div>
                      {f.reasoning && <div className="reasoning">{f.reasoning}</div>}
                    </td>
                    <td><ExploitBadge kev={f.kev_listed} /></td>
                    <td className="num dim">{f.cvss_score?.toFixed(1) ?? "—"}</td>
                    <td className="num dim">
                      {f.epss_score !== null ? `${Math.round(f.epss_score * 100)}%` : "—"}
                    </td>
                    <td className="mono dim">{f.asset}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {selected && <FindingDetail findingId={selected} onStatusChange={load} />}
      </div>
    </>
  );
}
