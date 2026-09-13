import { useEffect, useRef, useState } from "react";
import { ApiError, getScan, startScan } from "../api";
import type { Scan } from "../types";

const ACTIVE = ["pending", "discovering", "enriching", "scoring"];
const POLL_MS = 4000;

export function ScanPanel({ onComplete }: { onComplete: () => void }) {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  function poll(scanId: string) {
    timer.current = window.setTimeout(async () => {
      try {
        const next = await getScan(scanId);
        setScan(next);
        if (ACTIVE.includes(next.status)) {
          poll(scanId);
        } else if (next.status === "completed") {
          onComplete();
        }
      } catch (e) {
        setError((e as ApiError).message);
      }
    }, POLL_MS);
  }

  async function submit() {
    setSubmitting(true);
    setError(null);
    try {
      const created = await startScan(target.trim());
      setScan({
        scan_id: created.scan_id,
        target_domain: target.trim(),
        status: created.status,
        started_at: new Date().toISOString(),
        completed_at: null,
        error: null,
      });
      poll(created.scan_id);
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setSubmitting(false);
    }
  }

  const running = scan !== null && ACTIVE.includes(scan.status);
  const canSubmit = target.trim().length > 0 && authorized && !submitting && !running;

  return (
    <>
      <div className="banner warn">
        <span>
          Cerberus performs active reconnaissance. Only scan systems you own or have written
          authorization to test — see <code>docs/RULES_OF_ENGAGEMENT.md</code>.
        </span>
      </div>

      <div className="panel">
        <h2>New scan</h2>
        <div className="row" style={{ marginBottom: 12 }}>
          <input
            type="text"
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={running}
          />
          <button className="primary" onClick={() => void submit()} disabled={!canSubmit}>
            {running ? "Scanning…" : "Start scan"}
          </button>
        </div>
        <label style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            style={{ marginTop: 3 }}
          />
          <span className="dim" style={{ fontSize: 13 }}>
            I own this target, or I have explicit written authorization to scan it.
          </span>
        </label>
      </div>

      {error && <div className="banner error">{error}</div>}

      {scan && (
        <div className="panel">
          <h2>Scan status</h2>
          <dl className="detail" style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "8px 14px" }}>
            <dt className="dim">Target</dt>
            <dd className="mono">{scan.target_domain}</dd>
            <dt className="dim">Status</dt>
            <dd className="mono">{scan.status}</dd>
            <dt className="dim">Scan ID</dt>
            <dd className="mono">{scan.scan_id}</dd>
          </dl>
          {scan.error && <div className="banner error">{scan.error}</div>}
          {scan.status === "completed" && (
            <div className="banner ok">Scan complete — see the Findings tab.</div>
          )}
        </div>
      )}
    </>
  );
}
