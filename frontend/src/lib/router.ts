import { useCallback, useSyncExternalStore } from "react";

/**
 * A small hash router. The dashboard has seven screens and needs exactly two things from a
 * router: the back button, and links that survive a reload (filters, the selected finding).
 * `#/findings?status=active&finding=abc` carries both, so no dependency is warranted.
 */
export const TABS = ["overview", "domains", "labs", "scans", "findings", "assets", "surface", "evidence", "profile", "admin"] as const;
export type Tab = (typeof TABS)[number];

interface Route {
  tab: Tab;
  params: URLSearchParams;
}

function parse(): Route {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const tab = (TABS as readonly string[]).includes(path) ? (path as Tab) : "overview";
  return { tab, params: new URLSearchParams(query) };
}

// useSyncExternalStore requires a stable snapshot between changes, so parse once per hash.
let cache: { hash: string | null; route: Route } = { hash: null, route: parse() };
function snapshot(): Route {
  if (window.location.hash !== cache.hash) cache = { hash: window.location.hash, route: parse() };
  return cache.route;
}

function subscribe(callback: () => void) {
  window.addEventListener("hashchange", callback);
  return () => window.removeEventListener("hashchange", callback);
}

export type Params = Record<string, string | number | boolean | undefined>;

export function toHash(tab: Tab, params: Params = {}): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "" || value === false) continue;
    q.set(key, value === true ? "1" : String(value));
  }
  const text = q.toString();
  return `#/${tab}${text ? `?${text}` : ""}`;
}

export function useRoute() {
  const route = useSyncExternalStore(subscribe, snapshot);

  /** Go somewhere. `replace` rewrites the current history entry (used while typing in a filter). */
  const navigate = useCallback((tab: Tab, params: Params = {}, replace = false) => {
    const hash = toHash(tab, params);
    if (replace) {
      window.history.replaceState(null, "", hash);
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    } else {
      window.location.hash = hash;
    }
  }, []);

  /** Change some params on the current screen, keeping the rest. */
  const patch = useCallback(
    (changes: Params, replace = true) => {
      const current = Object.fromEntries(route.params.entries()) as Params;
      navigate(route.tab, { ...current, ...changes }, replace);
    },
    [route, navigate],
  );

  return { tab: route.tab, params: route.params, navigate, patch };
}
