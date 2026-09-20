import { useId, useState } from "react";
import type { FormEvent } from "react";
import { ApiError, setCriticality } from "../api";
import type { Asset, Criticality } from "../types";
import { Badge, CRITICALITY_TONE } from "./ui";

const LEVELS: { value: Criticality; label: string; hint: string }[] = [
  { value: "critical", label: "Critical", hint: "Business-critical: an outage or breach here is a major incident" },
  { value: "high", label: "High", hint: "Production or data-tier systems" },
  { value: "medium", label: "Medium", hint: "The default when nothing says otherwise" },
  { value: "low", label: "Low", hint: "Dev, test, staging, or forgotten boxes" },
];

/** Where the current level came from: a guess from the hostname, or a person's decision. */
export function CriticalitySummary({ asset }: { asset: Pick<Asset, "criticality" | "criticality_source" | "criticality_reason"> }) {
  if (!asset.criticality) return <span className="muted">Not set</span>;
  return (
    <span>
      <Badge tone={CRITICALITY_TONE[asset.criticality] ?? "neutral"}>{asset.criticality}</Badge>{" "}
      <span className="muted">{asset.criticality_source === "manual" ? "set by you" : "inferred from hostname"}</span>
    </span>
  );
}

/**
 * Criticality is 25% of the risk score by default, and the built-in value is a guess from the
 * hostname. This lets a person replace the guess with a decision; that decision is then never
 * overwritten by a re-scan, and the asset's findings are re-ranked immediately.
 */
export function CriticalityEditor({
  asset,
  onSaved,
}: {
  asset: Pick<Asset, "id" | "hostname" | "port" | "criticality" | "criticality_reason" | "criticality_source">;
  onSaved: (updated: Asset) => void;
}) {
  const id = useId();
  const [editing, setEditing] = useState(false);
  const [level, setLevel] = useState<Criticality>(asset.criticality ?? "medium");
  const [reason, setReason] = useState(asset.criticality_source === "manual" ? (asset.criticality_reason ?? "") : "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      onSaved(await setCriticality(asset.id, level, reason.trim()));
      setEditing(false);
    } catch (e) {
      setError((e as ApiError).message);
    } finally {
      setSaving(false);
    }
  }

  if (!editing) {
    return (
      <div className="cluster">
        <CriticalitySummary asset={asset} />
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditing(true)}>
          Change<span className="sr-only"> criticality of {asset.hostname}:{asset.port}</span>
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="stack" style={{ gap: "var(--space-3)" }}>
      <div className="field">
        <label className="field-label" htmlFor={`${id}-level`}>Criticality of {asset.hostname}:{asset.port}</label>
        <select id={`${id}-level`} className="select" value={level} onChange={(e) => setLevel(e.target.value as Criticality)}>
          {LEVELS.map((l) => (
            <option key={l.value} value={l.value}>{l.label} — {l.hint}</option>
          ))}
        </select>
      </div>
      <div className="field">
        <label className="field-label" htmlFor={`${id}-reason`}>Why (optional, shown in the score's explanation)</label>
        <input id={`${id}-reason`} className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="e.g. customer-facing checkout" />
      </div>
      {error && <p role="alert" style={{ color: "var(--danger-text)" }}>{error}</p>}
      <div className="cluster">
        <button type="submit" className="btn btn-primary btn-sm" disabled={saving}>
          {saving ? "Saving…" : "Save and re-rank"}
        </button>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditing(false)} disabled={saving}>Cancel</button>
      </div>
    </form>
  );
}
