import { useCallback, useEffect, useState } from "react";
import { enrichmentStatus, logout, onSessionEnded, restoreSession } from "./api";
import { AssetsView } from "./components/AssetsView";
import { AuthGate } from "./components/AuthGate";
import { DomainsView } from "./components/DomainsView";
import { EnrichmentBanner } from "./components/EnrichmentBanner";
import { FindingsView } from "./components/FindingsView";
import { Icon } from "./components/icons";
import type { IconName } from "./components/icons";
import { ObservationsView } from "./components/ObservationsView";
import { OverviewView } from "./components/OverviewView";
import { ScansView } from "./components/ScansView";
import { TABS, toHash, useRoute } from "./lib/router";
import type { Tab } from "./lib/router";
import type { SourceStatus, User } from "./types";

const NAV: Record<Tab, { label: string; icon: IconName }> = {
  overview: { label: "Overview", icon: "overview" },
  domains: { label: "Domains", icon: "domains" },
  scans: { label: "Scans", icon: "scans" },
  findings: { label: "Findings", icon: "findings" },
  assets: { label: "Assets", icon: "assets" },
  evidence: { label: "Evidence", icon: "evidence" },
};

type Auth =
  | { status: "loading" }
  | { status: "out"; notice?: string }
  | { status: "in"; user: User };

function Brand({ heading }: { heading?: boolean }) {
  return (
    <a href="/" className="brand-link" title="Cerberus Home">
      <div className="brand">
        <span className="brand-mark-crest" aria-hidden="true">
          <svg width="26" height="24" viewBox="0 0 40 42" fill="none">
            <path d="M0 25C0 19.5 2.9 14.7 7.2 12C9.6 10.4 12.6 9.4 15.8 9.4V40.6C12.6 40.6 9.6 39.6 7.2 38C2.9 35.3 0 30.5 0 25Z" fill="#F97316"/>
            <path d="M18.8 12C15.8 14.7 13.8 19.5 13.8 25C13.8 30.5 15.8 35.3 18.8 38C21.2 39.6 23.8 40.6 26.5 40.6V9.4C23.8 9.4 21.2 10.4 18.8 12Z" fill="#F97316"/>
            <path d="M30 12C27.2 14.7 25.5 19.5 25.5 25C25.5 30.5 27.2 35.3 30 38C32.2 39.6 34.6 40.6 37.2 40.6V9.4C34.6 9.4 32.2 10.4 30 12Z" fill="#F97316"/>
          </svg>
        </span>
        <span className="brand-title">
          {heading ? <h1>Cerberus</h1> : "Cerberus"}
        </span>
        <span className="brand-tag">SecOps</span>
      </div>
    </a>
  );
}

export default function App() {
  const { tab } = useRoute();
  const [auth, setAuth] = useState<Auth>({ status: "loading" });
  const [sources, setSources] = useState<SourceStatus[] | null>(null);

  // On load, pick the session back up from Firebase Auth or the refresh cookie.
  useEffect(() => {
    let current = true;
    void restoreSession().then((user) => {
      if (current) setAuth(user ? { status: "in", user } : { status: "out" });
    });
    return () => { current = false; };
  }, []);

  // A request that could not be saved by a refresh means the session is over.
  useEffect(
    () => onSessionEnded(() => {
      setSources(null);
      setAuth((now) => (now.status === "in" ? { status: "out", notice: "Your session ended. Sign in again." } : now));
    }),
    [],
  );

  const signedIn = auth.status === "in";

  const refreshStatus = useCallback(async () => {
    try {
      setSources((await enrichmentStatus()).sources);
    } catch {
      setSources(null);
    }
  }, []);

  useEffect(() => {
    if (signedIn) void refreshStatus();
  }, [signedIn, refreshStatus]);

  useEffect(() => {
    document.title = signedIn ? `${NAV[tab].label} · Cerberus` : "Sign in · Cerberus";
  }, [tab, signedIn]);

  async function signOut() {
    await logout().catch(() => undefined);
    setSources(null);
    setAuth({ status: "out" });
  }

  const skipLink = (
    <a
      className="skip-link"
      href="#main"
      onClick={(e) => {
        // The hash belongs to the router, so move focus instead of following the link.
        e.preventDefault();
        document.getElementById("main")?.focus();
      }}
    >
      Skip to content
    </a>
  );

  if (auth.status !== "in") {
    return (
      <>
        {skipLink}
        <main id="main" tabIndex={-1} className="gate-page">
          <div className="gate-brand"><Brand heading /></div>
          {auth.status === "loading" ? (
            <p className="muted" role="status">Loading…</p>
          ) : (
            <AuthGate notice={auth.notice} onSignedIn={(user) => setAuth({ status: "in", user })} />
          )}
        </main>
      </>
    );
  }

  return (
    <>
      {skipLink}
      <div className="shell">
        <header className="sidebar">
          <Brand />
          <nav aria-label="Primary">
            <ul className="nav" role="list">
              {TABS.map((id) => (
                <li key={id}>
                  <a className="nav-link" href={toHash(id, {})} aria-current={tab === id ? "page" : undefined}>
                    <Icon name={NAV[id].icon} />
                    {NAV[id].label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <div className="sidebar-footer">
            <a
              href="/"
              className="sidebar-landing-link"
              title="Open Cerberus Landing Page"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
                <path d="M2 12h20" />
              </svg>
              <span>Landing Page</span>
              <span className="landing-arrow" aria-hidden="true">↗</span>
            </a>

            <div className="user-profile-card">
              <div className="user-avatar-wrap">
                <div className="user-avatar" aria-hidden="true">
                  {(
                    auth.user.name?.trim()
                      ? auth.user.name.trim().split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase()
                      : auth.user.email.slice(0, 2).toUpperCase()
                  ) || "CB"}
                </div>
                <span className="user-status-dot" title="Active session" aria-hidden="true" />
              </div>

              <div className="who" title={auth.user.email}>
                <span className="who-name">
                  {auth.user.name?.trim() || auth.user.email.split("@")[0]}
                </span>
                <span className="who-email">{auth.user.email}</span>
                <span className="who-label sr-only">Signed in as</span>
              </div>

              <button
                type="button"
                className="user-signout-btn"
                onClick={() => void signOut()}
                title="Sign out of Cerberus"
                aria-label="Sign out"
              >
                <Icon name="signout" />
              </button>
            </div>
          </div>
        </header>

        <main id="main" tabIndex={-1} className="content">
          <div className="stack">
            {sources && <EnrichmentBanner sources={sources} quietWhenFresh={tab !== "overview"} />}
            {tab === "overview" && <OverviewView />}
            {tab === "domains" && <DomainsView />}
            {tab === "scans" && <ScansView onScanFinished={refreshStatus} />}
            {tab === "findings" && <FindingsView />}
            {tab === "assets" && <AssetsView />}
            {tab === "evidence" && <ObservationsView />}
          </div>
        </main>
      </div>
    </>
  );
}
