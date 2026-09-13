import { useCallback, useEffect, useState } from "react";
import { ApiError, enrichmentStatus, getToken, setToken } from "./api";
import { AssetsView } from "./components/AssetsView";
import { EnrichmentBanner } from "./components/EnrichmentBanner";
import { FindingsView } from "./components/FindingsView";
import { ScanPanel } from "./components/ScanPanel";
import type { SourceStatus } from "./types";

type Tab = "findings" | "assets" | "scan";

function TokenGate({ onSaved }: { onSaved: () => void }) {
  const [value, setValue] = useState(getToken());

  return (
    <div className="panel gate">
      <h2>API key</h2>
      <p>
        The Cerberus API requires a bearer token. Use the <code className="mono">API_SECRET_KEY</code>{" "}
        from your <code className="mono">.env</code>.
      </p>
      <div className="row">
        <input
          type="password"
          value={value}
          placeholder="API_SECRET_KEY"
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && value.trim()) {
              setToken(value.trim());
              onSaved();
            }
          }}
        />
        <button
          className="primary"
          disabled={!value.trim()}
          onClick={() => {
            setToken(value.trim());
            onSaved();
          }}
        >
          Connect
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("findings");
  const [sources, setSources] = useState<SourceStatus[] | null>(null);
  const [authError, setAuthError] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const checkConnection = useCallback(async () => {
    if (!getToken()) {
      setAuthError(true);
      return;
    }
    try {
      const data = await enrichmentStatus();
      setSources(data.sources);
      setAuthError(false);
    } catch (e) {
      const err = e as ApiError;
      setAuthError(err.status === 401 || !getToken());
      setSources(null);
    }
  }, []);

  useEffect(() => {
    void checkConnection();
  }, [checkConnection, reloadKey]);

  const refresh = () => setReloadKey((k) => k + 1);

  return (
    <div className="app">
      <header className="masthead">
        <h1>Cerberus</h1>
        <span className="tagline">
          What attackers are most likely to exploit against you — ranked by exploitation, not severity.
        </span>
      </header>

      {authError || !getToken() ? (
        <TokenGate onSaved={refresh} />
      ) : (
        <>
          <nav className="tabs">
            <button aria-selected={tab === "findings"} onClick={() => setTab("findings")}>
              Findings
            </button>
            <button aria-selected={tab === "assets"} onClick={() => setTab("assets")}>
              Assets
            </button>
            <button aria-selected={tab === "scan"} onClick={() => setTab("scan")}>
              Scan
            </button>
          </nav>

          {sources && <EnrichmentBanner sources={sources} />}

          <div key={reloadKey}>
            {tab === "findings" && <FindingsView />}
            {tab === "assets" && <AssetsView />}
            {tab === "scan" && <ScanPanel onComplete={refresh} />}
          </div>
        </>
      )}
    </div>
  );
}
