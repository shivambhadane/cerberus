import { parseApiTime } from "../lib/format";
import type { SourceStatus } from "../types";
import { Banner } from "./ui";

const STALE_AFTER_HOURS = 24;

const hoursSince = (iso: string) => (Date.now() - parseApiTime(iso).getTime()) / 3_600_000;

/**
 * Mirrors the backend's cache check. Without KEV data every finding scores as "not exploited",
 * which silently inverts the ranking, so an empty or stale cache must be impossible to miss.
 * A fresh cache is good news only worth a line on the overview, so other screens stay quiet.
 */
export function EnrichmentBanner({ sources, quietWhenFresh = false }: { sources: SourceStatus[]; quietWhenFresh?: boolean }) {
  const kev = sources.find((s) => s.name === "kev");

  if (!kev || kev.record_count === 0) {
    return (
      <Banner tone="error" role="alert">
        <strong>The exploitation data is empty, so rankings are wrong.</strong>
        Every finding is currently scored as if nothing were being exploited. Load it with{" "}
        <code>python scripts/refresh_enrichment.py</code>.
      </Banner>
    );
  }

  const age = hoursSince(kev.last_refreshed_at);
  if (age > STALE_AFTER_HOURS) {
    return (
      <Banner tone="warning" role="status">
        <strong>The exploitation data is {Math.floor(age)} hours old.</strong>
        Newly exploited CVEs may be missing from the ranking. Refresh it with{" "}
        <code>python scripts/refresh_enrichment.py</code>.
      </Banner>
    );
  }

  if (quietWhenFresh) return null;

  return (
    <Banner tone="success">
      Exploitation data is current: {kev.record_count.toLocaleString()} actively exploited CVEs, refreshed{" "}
      {Math.max(0, Math.floor(age))} h ago.
    </Banner>
  );
}
