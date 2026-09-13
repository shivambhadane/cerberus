import type { SourceStatus } from "../types";

const STALE_AFTER_HOURS = 24;

function hoursSince(iso: string): number {
  return (Date.now() - new Date(iso).getTime()) / 3_600_000;
}

/**
 * Mirrors the backend's cache_warning check. Without KEV data every finding scores
 * as "not exploited", which silently inverts the ranking - so it must be visible.
 */
export function EnrichmentBanner({ sources }: { sources: SourceStatus[] }) {
  const kev = sources.find((s) => s.name === "kev");

  if (!kev || kev.record_count === 0) {
    return (
      <div className="banner error">
        <strong>Enrichment cache is empty.</strong>
        <span>
          Every finding will be scored as <em>not</em> actively exploited, so this ranking is
          wrong. Run <code>python scripts/refresh_enrichment.py</code>.
        </span>
      </div>
    );
  }

  const age = hoursSince(kev.last_refreshed_at);
  if (age > STALE_AFTER_HOURS) {
    return (
      <div className="banner warn">
        <strong>Enrichment cache is {Math.floor(age)}h old.</strong>
        <span>
          Newly exploited CVEs may be missing. Run{" "}
          <code>python scripts/refresh_enrichment.py</code>.
        </span>
      </div>
    );
  }

  return (
    <div className="banner ok">
      <span>
        KEV catalogue current — {kev.record_count.toLocaleString()} actively-exploited CVEs
        cached, refreshed {Math.max(0, Math.floor(age))}h ago.
      </span>
    </div>
  );
}
