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
    "Netlify has no read-only access level. Cerberus only reads your site list, but the token Netlify issues can do more than that.",
};

/** Where to make an access token, and what to warn about, for the providers that accept one. */
const TOKEN_HELP: Record<string, { where: string; warning: string; team: string }> = {
  vercel: {
    where:
      "In Vercel open Account Settings → Tokens → Create Token. Limit its scope to the team that owns the app and give it a short expiry.",
    warning:
      "Vercel has no read-only token, so this one can do more than Cerberus needs. Cerberus only reads project names and addresses, keeps the token encrypted on the server, and never shows it again. Delete the token on Vercel when you are done.",
    team: "Only if the token is limited to a team: Team Settings → General → Team ID (it starts with team_). Leave it empty for a personal account.",
  },
};

const message = (e: unknown) => (e instanceof ApiError ? e.message : "Something went wrong. Try again.");

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
}: {
  info: ProviderInfo;
  renewing: boolean;
  onConnected: (connection: Connection) => void;
}) {
  const tokenId = useId();
  const teamId = useId();
  const hintId = useId();
  const help = TOKEN_HELP[info.provider];
  const [token, setToken] = useState("");
  const [team, setTeam] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) {
      setError("Paste your access token first.");
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
    <form className="token-form stack" onSubmit={(e) => void submit(e)} noValidate>
      {help && <p className="field-hint">{help.where}</p>}
      <div className="field">
        <label className="field-label" htmlFor={tokenId}>
          {info.label} access token
        </label>
        <input
          id={tokenId}
          className="input mono"
          type="password"
          name="access-token"
          value={token}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="none"
          spellCheck={false}
          aria-describedby={hintId}
          onChange={(e) => setToken(e.target.value)}
        />
      </div>
      <div className="field">
        <label className="field-label" htmlFor={teamId}>
          Team ID <span className="muted">(optional)</span>
        </label>
        <input
          id={teamId}
          className="input mono"
          value={team}
          placeholder="team_…"
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => setTeam(e.target.value)}
        />
        {help && <span className="field-hint">{help.team}</span>}
      </div>
      {help && (
        <p id={hintId} className="field-hint">
          {help.warning}
        </p>
      )}
      {error && (
        <p role="alert" className="form-error">
          {error}
        </p>
      )}
      <div className="cluster">
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy}>
          {busy ? "Checking…" : renewing ? "Replace token" : "Connect with token"}
        </button>
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
                <code>{host}</code>
                {added ? (
                  <Badge tone="success">Added and verified</Badge>
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
  const id = useId();
  const { data, error, loading, reload } = useApi((signal) => listConnectionProjects(connection.id, signal), [
    connection.id,
  ]);
  const [filter, setFilter] = useState("");

  const needle = filter.trim().toLowerCase();
  const projects = (data?.projects ?? []).filter(
    (p) => !needle || p.name.toLowerCase().includes(needle) || p.hostnames.some((h) => h.includes(needle)),
  );

  if (error?.code === "connection_expired") {
    return (
      <Banner tone="warning" role="alert">
        <strong>This connection needs to be renewed.</strong>
        {error.message}
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
      {data && data.projects.length === 0 && (
        <EmptyState level={3} title="No projects found">
          This account has no projects Cerberus can see. If you expected some, disconnect and connect again, and
          make sure to share the projects when the platform asks.
        </EmptyState>
      )}
      {data && data.projects.length > 8 && (
        <div className="field">
          <label className="field-label" htmlFor={id}>Filter projects</label>
          <input
            id={id}
            className="input"
            value={filter}
            placeholder="Project or address"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      )}
      {data && data.projects.length > 0 && (
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
          {projects.length === 0 && <li className="muted">No project matches “{filter}”.</li>}
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
    // A token connection is renewed by pasting a new token, not by sending the person to the platform.
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
        <span className="connection-name">
          <strong>{connection.label}</strong>
          <span className="muted">
            Connected {formatDate(connection.connected_at)}
            {connection.method === "token" ? " with an access token" : ""}
          </span>
        </span>
        <span className="cluster">
          <button
            type="button"
            className="btn btn-sm"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => setOpen((now) => !now)}
          >
            {open ? "Hide projects" : "Choose a project"}
            <span className="sr-only"> for {connection.label}</span>
          </button>
          {confirming ? (
            <>
              <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={() => void disconnect()}>
                {busy ? "Disconnecting…" : "Confirm disconnect"}
              </button>
              <button type="button" className="btn btn-ghost btn-sm" disabled={busy} onClick={() => setConfirming(false)}>
                Cancel
              </button>
            </>
          ) : (
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setConfirming(true)}>
              Disconnect<span className="sr-only"> {connection.label}</span>
            </button>
          )}
        </span>
      </div>
      {confirming && (
        <p className="field-hint" role="status">
          Cerberus forgets this connection. Targets it verified go back to “not verified” until you verify them
          again. Nothing changes on {info.label}; you can also remove the app from {info.label}’s own settings.
        </p>
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
    <article className="panel provider-card stack" aria-labelledby={titleId}>
      <div className="provider-head">
        <span className={`provider-mark provider-${info.provider}`} aria-hidden="true">
          <ProviderLogo provider={info.provider} size={22} />
        </span>
        <div className="provider-title">
          <h3 id={titleId}>{info.label}</h3>
          <span className="field-hint">Verifies {PLATFORM_ADDRESS[info.provider]} addresses</span>
        </div>
        {!usable ? (
          <Badge tone="warning">Not set up on this server</Badge>
        ) : connected ? (
          <Badge tone="success">Connected</Badge>
        ) : (
          <Badge tone="neutral">Not connected</Badge>
        )}
      </div>

      {!usable && (
        <p className="field-hint">
          The person running this Cerberus has not registered a {info.label} OAuth app yet, so it can’t be used
          here. The setup steps are in docs/DEPLOYMENT.md.
        </p>
      )}
      {canOAuth && PROVIDER_NOTES[info.provider] && (
        <p className="field-hint">{PROVIDER_NOTES[info.provider]}</p>
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
              {tokenOpen ? "Hide access token form" : "Use an access token"}
            </button>
          )}
        </div>
      )}
      {canToken && (
        <div id={tokenPanelId} hidden={!tokenOpen}>
          {tokenOpen && (
            <TokenForm
              info={info}
              renewing={renewing}
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
        <h2 id="deployment-heading">Add a deployment</h2>
        <p className="muted deployment-intro">
          No custom domain? Connect the account your app is deployed on and Cerberus asks the platform whether
          the address is yours. Only the free platform addresses, such as <code>*.vercel.app</code>,{" "}
          <code>*.netlify.app</code> and <code>*.pages.dev</code>, can be verified this way. A custom domain still
          needs a DNS record. Tokens stay on the server and are never sent to your browser.
        </p>
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
