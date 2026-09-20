import type { ReactNode } from "react";
import { ApiError, PAGE_SIZE } from "../api";
import { toHash } from "../lib/router";
import { Icon } from "./icons";

/* ---- Badges ------------------------------------------------------------------------------ */

type Tone = "danger" | "warning" | "success" | "info" | "neutral";

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function riskBand(score: number | null): "critical" | "high" | "medium" | "low" {
  if (score === null) return "low";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

export function RiskScore({ score }: { score: number | null }) {
  if (score === null) return <span className="muted">Not scored</span>;
  return (
    <span className={`risk risk-${riskBand(score)}`}>
      {score.toFixed(1)}
      <span className="sr-only"> out of 100, {riskBand(score)} risk</span>
    </span>
  );
}

/** Whether attackers are known to be using this weakness. */
export function ExploitBadge({ kev, poc }: { kev: boolean; poc?: boolean }) {
  if (kev)
    return (
      <Badge tone="danger">
        <span aria-hidden="true">KEV</span>
        <span className="sr-only">Actively exploited, listed in the CISA KEV catalogue</span>
      </Badge>
    );
  if (poc)
    return (
      <Badge tone="warning">
        <span aria-hidden="true">PoC</span>
        <span className="sr-only">Public proof-of-concept exploit exists</span>
      </Badge>
    );
  return <Badge tone="neutral">No known exploitation</Badge>;
}

/**
 * How the finding was established, which is confidence that the weakness exists, not how
 * dangerous it is. A probe matching the host is stronger than a version string.
 */
export function DetectionBadge({ method }: { method: string }) {
  return method === "active_detection" ? (
    <Badge tone="success">Confirmed</Badge>
  ) : (
    <Badge tone="neutral">Inferred</Badge>
  );
}

const STATUS_TONE: Record<string, Tone> = {
  open: "info",
  acknowledged: "warning",
  resolved: "success",
  false_positive: "neutral",
  completed: "success",
  failed: "danger",
  pending: "neutral",
  discovering: "info",
  enriching: "info",
  scoring: "info",
};

export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={STATUS_TONE[status] ?? "neutral"}>{status.replace("_", " ")}</Badge>;
}

export const CRITICALITY_TONE: Record<string, Tone> = {
  critical: "danger",
  high: "warning",
  medium: "info",
  low: "neutral",
};

/* ---- Feedback ---------------------------------------------------------------------------- */

export function Banner({
  tone,
  children,
  role,
}: {
  tone: "info" | "warning" | "error" | "success";
  children: ReactNode;
  role?: "alert" | "status";
}) {
  return (
    <div className={`banner banner-${tone}`} role={role}>
      <div>{children}</div>
    </div>
  );
}

/** What happened, and what to do about it. */
export function ErrorBanner({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const hint =
    error.status === 401
      ? "Your session has ended. Sign in again."
      : error.status === 0
        ? "Start the API (uvicorn api.main:app) and try again."
        : "";
  return (
    <Banner tone="error" role="alert">
      <strong>Something went wrong.</strong>
      {error.message} {hint}
      {onRetry && (
        <div style={{ marginTop: "var(--space-2)" }}>
          <button type="button" className="btn btn-secondary btn-sm" onClick={onRetry}>
            Try again
          </button>
        </div>
      )}
    </Banner>
  );
}

/** What this is, why it is empty, how to change that. */
export function EmptyState({
  title,
  children,
  action,
  level = 2,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
  /** Heading level: 2 when the empty state stands alone under the page title, 3 inside a titled section. */
  level?: 2 | 3;
}) {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <div className="empty">
      <Heading>{title}</Heading>
      <p>{children}</p>
      {action}
    </div>
  );
}

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="stack" aria-hidden="true" style={{ gap: "var(--space-3)" }}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" />
      ))}
    </div>
  );
}

/* ---- Table helpers ----------------------------------------------------------------------- */

export function SortHeader({
  label,
  field,
  sort,
  order,
  onSort,
  numeric,
}: {
  label: string;
  field: string;
  sort: string;
  order: string;
  onSort: (field: string) => void;
  numeric?: boolean;
}) {
  const active = sort === field;
  return (
    <th scope="col" aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"} className={numeric ? "num" : undefined}>
      <button type="button" className="th-sort" data-active={active} onClick={() => onSort(field)}>
        {label}
        <span aria-hidden="true">{active ? (order === "asc" ? "▲" : "▼") : ""}</span>
      </button>
    </th>
  );
}

/** A horizontally scrolling table container. It is focusable so keyboard users can scroll it. */
export function TableWrap({ label, children, busy }: { label: string; children: ReactNode; busy?: boolean }) {
  return (
    <div className="table-wrap" role="region" aria-label={label} aria-busy={busy} tabIndex={0}>
      {children}
    </div>
  );
}

export function Pagination({
  page,
  total,
  onPage,
  noun,
}: {
  page: number;
  total: number;
  onPage: (page: number) => void;
  noun: string;
}) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const last = Math.min(total, page * PAGE_SIZE);
  return (
    <nav className="pagination" aria-label={`${noun} pages`}>
      <p className="muted" aria-live="polite">
        {total === 0 ? `No ${noun}` : `Showing ${first}–${last} of ${total} ${noun}`}
      </p>
      {pages > 1 && (
        <div className="pages">
          <button type="button" className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
            Previous
          </button>
          <span className="muted" style={{ alignSelf: "center" }}>
            Page {page} of {pages}
          </span>
          <button type="button" className="btn btn-secondary btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
            Next
          </button>
        </div>
      )}
    </nav>
  );
}

/* ---- Page header ------------------------------------------------------------------------- */

/** The one h1 on a screen, its purpose in a sentence, and the screen's primary actions. */
export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

/** The primary action of every screen: go to the scan form. */
export function NewScanLink() {
  return (
    <a className="btn btn-primary" href={toHash("scans", {})}>
      <Icon name="plus" />
      New scan
    </a>
  );
}
