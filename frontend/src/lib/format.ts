/** Times are shown in Indian Standard Time, whatever the viewer's computer is set to. */
export const DISPLAY_TIME_ZONE = "Asia/Kolkata";

const HAS_ZONE = /(?:Z|[+-]\d{2}:?\d{2})$/i;

/**
 * Parse a timestamp from the API. The API sends UTC; a string with no zone marker is treated as UTC
 * as well, never as the browser's local time. (`new Date("2026-09-20T06:24:23")` means 06:24 *local*,
 * which made every timestamp wrong by the viewer's UTC offset.)
 */
export function parseApiTime(iso: string): Date {
  return new Date(HAS_ZONE.test(iso) ? iso : `${iso.replace(" ", "T")}Z`);
}

export function formatDate(iso: string): string {
  const text = parseApiTime(iso).toLocaleString("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: DISPLAY_TIME_ZONE,
  });
  return `${text} IST`;
}

export function relativeTime(iso: string, now = Date.now()): string {
  const seconds = Math.round((now - parseApiTime(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export function duration(startIso: string, endIso: string | null): string {
  if (!endIso) return "running";
  const seconds = Math.max(
    0,
    Math.round((parseApiTime(endIso).getTime() - parseApiTime(startIso).getTime()) / 1000),
  );
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m ${seconds % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export const percent = (value: number | null) => (value === null ? "—" : `${Math.round(value * 100)}%`);
export const fixed1 = (value: number | null) => (value === null ? "—" : value.toFixed(1));
