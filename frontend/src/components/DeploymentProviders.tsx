import { useEffect, useId, useState } from "react";
import type { FormEvent } from "react";
import {
  ApiError,
  addPlatformTarget,
  connectProvider,
  connectWithToken,
  disconnectConnection,
  listConnectionProjects,
} from "../api";
import { formatDate } from "../lib/format";
import { useApi } from "../lib/useApi";
import type { Connection, Domain, PlatformProject, ProviderInfo } from "../types";
import { Icon } from "./icons";
import { Badge, Banner, EmptyState, ErrorBanner, SkeletonRows } from "./ui";

/** The address each platform gives an app for free: the only kind a platform account can prove. */
export const PLATFORM_ADDRESS: Record<string, string> = {
  vercel: "*.vercel.app",
  netlify: "*.netlify.app",
  cloudflare: "*.pages.dev",
};

/** Plain-language hints shown on a provider's card, where the provider has a limit worth knowing. */
const PROVIDER_NOTES: Record<string, string> = {
  netlify:
    "Netlify issues account-wide tokens. Cerberus only reads your site list and verifies ownership of *.netlify.app domains.",
  cloudflare:
    "Cerberus uses Cloudflare Pages scopes (page.read, pages.metadata_read) to list and verify your *.pages.dev projects.",
  vercel:
    "Vercel tokens are stored encrypted using server-side AES-256-GCM and used strictly for project listing and hostname verification.",
};

const message = (e: unknown) => (e instanceof ApiError ? e.message : "Something went wrong. Try again.");

/** Educational guidance card showing regular users how deployment verification works. */
function DeploymentHowItWorks() {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="deployment-guide-card">
      <div className="guide-header">
        <div className="guide-title">
          <Icon name="info" />
          <span>How Platform Deployment Verification Works</span>
        </div>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => setExpanded((prev) => !prev)}
          aria-expanded={expanded}
        >
          {expanded ? "Hide guide" : "Show guide"}
        </button>
      </div>

      {expanded && (
        <>
          <p className="deployment-intro">
            Connect your hosting account once to verify free deployment subdomains (<code>*.vercel.app</code>,{" "}
            <code>*.netlify.app</code>, and <code>*.pages.dev</code>) in one click without configuring manual DNS TXT records.
          </p>

          <div className="guide-steps-grid">
            <div className="guide-step">
              <div className="guide-step-heading">
                <span className="guide-step-pill">1</span>
                <span>Connect Account</span>
              </div>
              <p className="guide-step-body">
                <strong>Netlify &amp; Cloudflare:</strong> 1-click OAuth sign-in.<br />
                <strong>Vercel:</strong> 10-second personal access token from Vercel Account Settings.
              </p>
            </div>

            <div className="guide-step">
              <div className="guide-step-heading">
                <span className="guide-step-pill">2</span>
                <span>Discover Projects</span>
              </div>
              <p className="guide-step-body">
                Cerberus queries the provider&apos;s API to list live deployment projects and active subdomains belonging to you.
              </p>
            </div>

            <div className="guide-step">
              <div className="guide-step-heading">
                <span className="guide-step-pill">3</span>
                <span>Verify &amp; Scan</span>
              </div>
              <p className="guide-step-body">
                Click <strong>Add &amp; verify</strong> on any project address. The domain is instantly verified and ready for scanning!
              </p>
            </div>
          </div>

          <div className="guide-security-footnote">
            <Icon name="lock" />
            <span>
              <strong>Zero credential exposure:</strong> Provider tokens are encrypted on the server with AES-256-GCM.
              They are never sent to your browser or exposed in logs.
            </span>
          </div>
        </>
      )}
    </div>
  );
}

/** Only ever send the browser to the provider over HTTPS, whatever the API said. */
function goToProvider(url: string) {
  const target = new URL(url);
  if (target.protocol !== "https:") throw new Error("The provider address was not HTTPS.");
  window.location.assign(target.toString());
}

/** Official SVG mark for each deployment provider. */
export function ProviderLogo({ provider, size = 20 }: { provider: string; size?: number }) {
  if (provider === "vercel") {
    return (
      <svg
        className="provider-icon provider-icon-vercel"
        viewBox="0 0 1155 1000"
        fill="currentColor"
        width={size}
        height={size}
        aria-hidden="true"
      >
        <path d="M577.344 0L1154.69 1000H0L577.344 0Z" />
      </svg>
    );
  }
  if (provider === "netlify") {
    return (
      <svg
        className="provider-icon provider-icon-netlify"
        viewBox="0 0 150 150"
        fill="none"
        width={size}
        height={size}
        aria-hidden="true"
      >
        <path d="M43.91,116.64h-1.34l-6.67-6.67v-1.34l10.19-10.19h7.06l.94,.94v7.06l-10.19,10.19Z" fill="#05bdba" />
        <path d="M35.9,41.22v-1.34l6.67-6.67h1.34l10.19,10.19v7.06l-.94,.94h-7.06l-10.19-10.19Z" fill="#05bdba" />
        <path d="M94.6,95.14h-9.7l-.81-.81v-22.71c0-4.04-1.59-7.17-6.46-7.28-2.51-.07-5.38,0-8.44,.12l-.46,.47v29.39l-.81,.81h-9.7l-.81-.81V55.53l.81-.81h21.83c8.48,0,15.36,6.88,15.36,15.36v24.25l-.81,.81Z" fill="#ffffff" />
        <path d="M45.29,80.6H6.49l-.81-.81v-9.72l.81-.81H45.29l.81,.81v9.72l-.81,.81Z" fill="#05bdba" />
        <path d="M146.34,80.6h-38.8l-.81-.81v-9.72l.81-.81h38.8l.81,.81v9.72l-.81,.81Z" fill="#05bdba" />
        <path d="M70.82,42.6V13.5l.81-.81h9.72l.81,.81v29.1l-.81,.81h-9.72l-.81-.81Z" fill="#05bdba" />
        <path d="M70.82,136.36v-29.1l.81-.81h9.72l.81,.81v29.1l-.81,.81h-9.72l-.81-.81Z" fill="#05bdba" />
      </svg>
    );
  }
  if (provider === "cloudflare") {
    return (
      <svg
        className="provider-icon provider-icon-cloudflare"
        viewBox="0 0 24 24"
        fill="currentColor"
        width={size}
        height={size}
        aria-hidden="true"
      >
        <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z" />
      </svg>
    );
  }
  return <span>{provider[0]?.toUpperCase()}</span>;
}

/**
 * Connect with an access token instead of OAuth. The token is typed here once, sent to the server, proved by
 * using it there, and stored encrypted; it is cleared from the page as soon as it has been sent.
 */
function TokenForm({
  info,
  renewing,
  onConnected,
  onCancel,
}: {
  info: ProviderInfo;
  renewing: boolean;
  onConnected: (connection: Connection) => void;
  onCancel?: () => void;
}) {
  const tokenId = useId();
  const teamId = useId();
  const [token, setToken] = useState("");
  const [team, setTeam] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) {
      setError("Please paste your access token first.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const connection = await connectWithToken(info.provider, token, team);
      setToken(""); // sent; it must not linger in the page
      onConnected(connection);
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="token-form-container stack" onSubmit={(e) => void submit(e)} noValidate>
      <div className="token-guidance-box">
        <div className="token-guidance-title">
          <span>How to create a {info.label} Access Token</span>
          <a
            href="https://vercel.com/account/tokens"
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-ghost btn-sm"
          >
            <Icon name="external" />
            <span>Open Vercel Tokens</span>
          </a>
        </div>
        <ol className="token-steps-list">
          <li className="token-step-item">
            <span className="token-step-num">1</span>
            <span>
              Go to{" "}
              <a href="https://vercel.com/account/tokens" target="_blank" rel="noopener noreferrer">
                vercel.com/account/tokens
              </a>{" "}
              in your browser.
            </span>
          </li>
          <li className="token-step-item">
            <span className="token-step-num">2</span>
            <span>
              Click <strong>Create Token</strong>, enter a name (e.g. <code>Cerberus Scanner</code>), and select your desired expiration.
            </span>
          </li>
          <li className="token-step-item">
            <span className="token-step-num">3</span>
            <span>Copy the generated token, paste it below, and click Connect.</span>
          </li>
        </ol>
      </div>

      <div className="field">
        <label className="field-label" htmlFor={tokenId}>
          {info.label} Access Token
        </label>
        <div className="input-with-button">
          <input
            id={tokenId}
            className="input mono"
            type={showToken ? "text" : "password"}
            name="access-token"
            value={token}
            placeholder="e.g. 7X89k..."
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            onChange={(e) => setToken(e.target.value)}
          />
          <button
            type="button"
            className="input-action-btn"
            onClick={() => setShowToken((prev) => !prev)}
            title={showToken ? "Hide token" : "Show token"}
            aria-label={showToken ? "Hide token" : "Show token"}
          >
            <Icon name={showToken ? "eyeOff" : "eye"} />
          </button>
        </div>
      </div>

      <div className="field">
        <label className="field-label" htmlFor={teamId}>
          Team ID <span className="muted">(optional)</span>
        </label>
        <input
          id={teamId}
          className="input mono"
          value={team}
          placeholder="team_… (leave empty for personal account)"
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => setTeam(e.target.value)}
        />
        <span className="field-hint">
          Only required if your deployments belong to a Vercel Team (found in Vercel Team Settings → General).
        </span>
      </div>

      <div className="token-security-badge">
        <Icon name="lock" />
        <span>
          Stored encrypted with AES-256-GCM. Used strictly to read project names and addresses.
        </span>
      </div>

      {error && (
        <p role="alert" className="form-error">
          {error}
        </p>
      )}

      <div className="cluster">
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy}>
          {busy ? "Verifying Token…" : renewing ? "Replace Token" : "Connect Account"}
        </button>
        {onCancel && (
          <button type="button" className="btn btn-ghost btn-sm" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

function ProjectRow({
  connection,
  project,
  onAdded,
}: {
  connection: Connection;
  project: PlatformProject;
  onAdded: (domain: Domain) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ host: string; text: string } | null>(null);

  async function add(hostname: string) {
    setBusy(hostname);
    setError(null);
    try {
      onAdded(await addPlatformTarget(connection.id, project.id, hostname));
    } catch (e) {
      setError({ host: hostname, text: message(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <li className="project">
      <h4 className="project-name">{project.name}</h4>
      {project.hostnames.length === 0 ? (
        <p className="field-hint">
          No {PLATFORM_ADDRESS[connection.provider]} address on this project. A custom domain attached to it can’t
          be verified through a platform account: add it as a custom domain and verify it with DNS.
        </p>
      ) : (
        <ul className="plain-list" role="list">
          {project.hostnames.map((host) => {
            const added = project.verified_hostnames.includes(host);
            return (
              <li key={host} className="host-row">
                <span className="host-domain-badge">{host}</span>
                {added ? (
                  <Badge tone="success">
                    <Icon name="check" /> Added &amp; verified
                  </Badge>
                ) : (
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={busy !== null}
                    onClick={() => void add(host)}
                  >
                    {busy === host ? "Verifying…" : "Add & verify"}
                    <span className="sr-only"> {host}</span>
                  </button>
                )}
                {error?.host === host && (
                  <p role="alert" className="form-error host-error">
                    {error.text}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </li>
  );
}

function ProjectPicker({
  connection,
  onAdded,
  onReconnect,
}: {
  connection: Connection;
  onAdded: (domain: Domain) => void;
  onReconnect: () => void;
}) {
  const byToken = connection.method === "token";
  const { data, error, loading, reload } = useApi(
    (signal) => listConnectionProjects(connection.id, signal),
    [connection.id],
  );
  const [filter, setFilter] = useState("");

  const needle = filter.trim().toLowerCase();
  const allProjects = data?.projects ?? [];
  const projects = allProjects.filter(
    (p) => !needle || p.name.toLowerCase().includes(needle) || p.hostnames.some((h) => h.includes(needle)),
  );

  if (error?.code === "connection_expired") {
    return (
      <Banner tone="warning" role="alert">
        <strong>This connection needs to be renewed.</strong> {error.message}
        <div className="banner-actions">
          <button type="button" className="btn btn-primary btn-sm" onClick={onReconnect}>
            {byToken ? "Enter a new token" : "Reconnect"}
          </button>
        </div>
      </Banner>
    );
  }

  return (
    <div className="stack picker">
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <SkeletonRows rows={3} />}

      {data && allProjects.length > 0 && (
        <div className="picker-topbar">
          <div className="picker-search-wrap">
            <span className="picker-search-icon" aria-hidden="true">
              <Icon name="search" />
            </span>
            <input
              className="input picker-search-input"
              value={filter}
              placeholder="Search projects or hostnames..."
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setFilter(e.target.value)}
              aria-label="Filter projects"
            />
          </div>
          <div className="cluster">
            <span className="picker-stats">
              {needle ? `Showing ${projects.length} of ${allProjects.length}` : `${allProjects.length} project${allProjects.length === 1 ? "" : "s"}`}
            </span>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={loading}
              onClick={() => reload()}
              title="Refresh project list from provider"
            >
              <Icon name="refresh" />
              <span>Sync</span>
            </button>
          </div>
        </div>
      )}

      {data && allProjects.length === 0 && (
        <EmptyState level={3} title="No projects found">
          This account has no projects Cerberus can see. If you have projects deployed, make sure to grant project
          access during authorization or check your token permissions.
        </EmptyState>
      )}

      {data && allProjects.length > 0 && (
        <ul className="plain-list project-list" role="list" aria-label={`Projects in ${connection.label}`}>
          {projects.map((project) => (
            <ProjectRow
              key={project.id}
              connection={connection}
              project={project}
              onAdded={(domain) => {
                onAdded(domain);
                reload();
              }}
            />
          ))}
          {projects.length === 0 && (
            <li className="muted" style={{ padding: "var(--space-2) 0" }}>
              No project matches “{filter}”.
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

function ConnectionRow({
  info,
  connection,
  startOpen,
  onAdded,
  onChanged,
  onError,
  onRenewToken,
}: {
  info: ProviderInfo;
  connection: Connection;
  startOpen: boolean;
  onAdded: (domain: Domain) => void;
  onChanged: (announcement: string) => void;
  onError: (text: string) => void;
  onRenewToken: () => void;
}) {
  const [open, setOpen] = useState(startOpen);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const panelId = useId();

  // Arriving back from the platform with this account: open its projects.
  useEffect(() => {
    if (startOpen) setOpen(true);
  }, [startOpen]);

  async function reconnect() {
    if (connection.method === "token") {
      onRenewToken();
      return;
    }
    try {
      goToProvider((await connectProvider(info.provider)).authorization_url);
    } catch (e) {
      onError(message(e));
    }
  }

  async function disconnect() {
    setBusy(true);
    try {
      const outcome = await disconnectConnection(connection.id);
      onChanged(
        outcome.targets_reset > 0
          ? `Disconnected ${connection.label}. ${outcome.targets_reset} target${outcome.targets_reset === 1 ? "" : "s"} now need verifying again.`
          : `Disconnected ${connection.label}.`,
      );
    } catch (e) {
      onError(message(e));
      setBusy(false);
    }
  }

  return (
    <li className="connection">
      <div className="connection-row">
        <div className="connection-name">
          <div className="connection-title-row">
            <strong>{connection.label}</strong>
            <span className="connection-method-pill">
              {connection.method === "token" ? "Personal Token" : "OAuth"}
            </span>
          </div>
          <span className="connection-meta">
            Connected {formatDate(connection.connected_at)}
          </span>
        </div>

        <div className="cluster">
          <button
            type="button"
            className="btn btn-sm"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => setOpen((now) => !now)}
          >
            <Icon name={open ? "chevronUp" : "chevronDown"} />
            <span>{open ? "Hide projects" : "View projects"}</span>
            <span className="sr-only"> for {connection.label}</span>
          </button>
          {confirming ? (
            <>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                disabled={busy}
                onClick={() => void disconnect()}
              >
                {busy ? "Disconnecting…" : "Confirm disconnect"}
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                disabled={busy}
                onClick={() => setConfirming(false)}
              >
                Cancel
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => setConfirming(true)}
            >
              Disconnect<span className="sr-only"> {connection.label}</span>
            </button>
          )}
        </div>
      </div>

      {confirming && (
        <div style={{ padding: "0 var(--space-3) var(--space-3)" }}>
          <p className="field-hint" role="status">
            Cerberus will forget this connection. Targets it verified will return to “not verified” until
            verified again. Nothing is altered on {info.label}.
          </p>
        </div>
      )}

      <div id={panelId} hidden={!open}>
        {open && <ProjectPicker connection={connection} onAdded={onAdded} onReconnect={() => void reconnect()} />}
      </div>
    </li>
  );
}

function ProviderCard({
  info,
  openConnection,
  onAdded,
  onChanged,
}: {
  info: ProviderInfo;
  openConnection: string | null;
  onAdded: (domain: Domain) => void;
  onChanged: (announcement: string) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [tokenOpen, setTokenOpen] = useState(false);
  const [justConnected, setJustConnected] = useState<string | null>(null);
  const titleId = useId();
  const tokenPanelId = useId();
  const connected = info.connections.length > 0;
  const canOAuth = info.configured;
  const canToken = Boolean(info.token_paste);
  const usable = canOAuth || canToken;
  const renewing = info.connections.some((c) => c.method === "token");

  async function connect() {
    setStarting(true);
    setError(null);
    try {
      goToProvider((await connectProvider(info.provider)).authorization_url);
    } catch (e) {
      setError(message(e));
      setStarting(false);
    }
  }

  return (
    <article className={`provider-card provider-card-${info.provider}`} aria-labelledby={titleId}>
      <div className="provider-head">
        <span className={`provider-mark provider-${info.provider}`} aria-hidden="true">
          <ProviderLogo provider={info.provider} size={24} />
        </span>
        <div className="provider-title">
          <h3 id={titleId}>{info.label}</h3>
          <span className="provider-pattern-tag">Verifies {PLATFORM_ADDRESS[info.provider]} addresses</span>
        </div>
        {!usable ? (
          <Badge tone="warning">Setup required</Badge>
        ) : connected ? (
          <Badge tone="success">
            Connected ({info.connections.length})
          </Badge>
        ) : (
          <Badge tone="neutral">Ready to connect</Badge>
        )}
      </div>

      {!usable && (
        <p className="provider-desc-note">
          This deployment provider is not yet configured on this server. Check docs/DEPLOYMENT.md for setup steps.
        </p>
      )}

      {usable && PROVIDER_NOTES[info.provider] && (
        <p className="provider-desc-note">{PROVIDER_NOTES[info.provider]}</p>
      )}

      {connected && (
        <ul className="plain-list connection-list" role="list" aria-label={`${info.label} accounts`}>
          {info.connections.map((connection) => (
            <ConnectionRow
              key={connection.id}
              info={info}
              connection={connection}
              startOpen={openConnection === connection.id || justConnected === connection.id}
              onAdded={onAdded}
              onChanged={onChanged}
              onError={setError}
              onRenewToken={() => setTokenOpen(true)}
            />
          ))}
        </ul>
      )}

      {usable && (
        <div className="cluster">
          {canOAuth && (
            <button
              type="button"
              className={connected ? "btn btn-sm" : "btn btn-primary"}
              disabled={starting}
              onClick={() => void connect()}
            >
              {starting ? "Opening…" : connected ? "Connect another account" : `Connect ${info.label}`}
            </button>
          )}
          {canToken && (
            <button
              type="button"
              className={canOAuth || connected ? "btn btn-sm" : "btn btn-primary"}
              aria-expanded={tokenOpen}
              aria-controls={tokenPanelId}
              onClick={() => setTokenOpen((now) => !now)}
            >
              {tokenOpen ? "Hide Token Form" : renewing ? "Replace Access Token" : "Connect with Access Token"}
            </button>
          )}
          {info.provider === "vercel" && !tokenOpen && (
            <a
              href="https://vercel.com/account/tokens"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-ghost btn-sm"
              title="Open Vercel Token Settings in a new tab"
            >
              <Icon name="external" />
              <span>Get Token</span>
            </a>
          )}
        </div>
      )}

      {canToken && (
        <div id={tokenPanelId} hidden={!tokenOpen}>
          {tokenOpen && (
            <TokenForm
              info={info}
              renewing={renewing}
              onCancel={() => setTokenOpen(false)}
              onConnected={(connection) => {
                setTokenOpen(false);
                setError(null);
                setJustConnected(connection.id);
                onChanged(`Connected ${connection.label} with an access token.`);
              }}
            />
          )}
        </div>
      )}

      {error && (
        <p role="alert" className="form-error">
          {error}
        </p>
      )}
    </article>
  );
}

export function DeploymentPanel({
  providers,
  loading,
  error,
  reload,
  openConnection,
  onAdded,
  onChanged,
}: {
  providers: ProviderInfo[] | null;
  loading: boolean;
  error: ApiError | null;
  reload: () => void;
  openConnection: string | null;
  onAdded: (domain: Domain) => void;
  onChanged: (announcement: string) => void;
}) {
  return (
    <section className="stack" aria-labelledby="deployment-heading">
      <div className="deployment-head">
        <h2 id="deployment-heading">Deployment Providers</h2>
        <DeploymentHowItWorks />
      </div>

      {error && <ErrorBanner error={error} onRetry={reload} />}

      {!providers && loading && (
        <div className="panel" aria-busy="true">
          <SkeletonRows rows={3} />
        </div>
      )}

      <div className="provider-grid">
        {providers?.map((info) => (
          <ProviderCard
            key={info.provider}
            info={info}
            openConnection={openConnection}
            onAdded={onAdded}
            onChanged={onChanged}
          />
        ))}
      </div>
    </section>
  );
}
