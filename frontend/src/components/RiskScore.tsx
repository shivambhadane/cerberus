export function riskBand(score: number | null): string {
  if (score === null) return "low";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export function RiskScore({ score }: { score: number | null }) {
  if (score === null) return <span className="dim mono">—</span>;
  return <span className={`risk ${riskBand(score)}`}>{score.toFixed(1)}</span>;
}

export function ExploitBadge({ kev, poc }: { kev: boolean; poc?: boolean }) {
  if (kev) return <span className="badge kev">KEV</span>;
  if (poc) return <span className="badge poc">PoC</span>;
  return <span className="badge quiet">none</span>;
}
