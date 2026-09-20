import { useEffect, useId, useState } from "react";
import {
  ApiError,
  addPlatformTarget,
  connectProvider,
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

const message = (e: unknown) => (e instanceof ApiError ? e.message : "Something went wrong. Try again.");

/** Only ever send the browser to the provider over HTTPS, whatever the API said. */
function goToProvider(url: string) {
  const target = new URL(url);
  if (target.protocol !== "https:") throw new Error("The provider address was not HTTPS.");
  window.location.assign(target.toString());
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
            Reconnect
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
}: {
  info: ProviderInfo;
  connection: Connection;
  startOpen: boolean;
  onAdded: (domain: Domain) => void;
  onChanged: (announcement: string) => void;
  onError: (text: string) => void;
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
          <span className="muted">Connected {formatDate(connection.connected_at)}</span>
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
  const titleId = useId();
  const connected = info.connections.length > 0;

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
          {info.label[0]}
        </span>
        <div className="provider-title">
          <h3 id={titleId}>{info.label}</h3>
          <span className="field-hint">Verifies {PLATFORM_ADDRESS[info.provider]} addresses</span>
        </div>
        {!info.configured ? (
          <Badge tone="warning">Not set up on this server</Badge>
        ) : connected ? (
          <Badge tone="success">Connected</Badge>
        ) : (
          <Badge tone="neutral">Not connected</Badge>
        )}
      </div>

      {!info.configured && (
        <p className="field-hint">
          The person running this Cerberus has not registered a {info.label} OAuth app yet, so it can’t be used
          here. The setup steps are in docs/DEPLOYMENT.md.
        </p>
      )}
      {info.configured && PROVIDER_NOTES[info.provider] && (
        <p className="field-hint">{PROVIDER_NOTES[info.provider]}</p>
      )}

      {connected && (
        <ul className="plain-list connection-list" role="list" aria-label={`${info.label} accounts`}>
          {info.connections.map((connection) => (
            <ConnectionRow
              key={connection.id}
              info={info}
              connection={connection}
              startOpen={openConnection === connection.id}
              onAdded={onAdded}
              onChanged={onChanged}
              onError={setError}
            />
          ))}
        </ul>
      )}

      {info.configured && (
        <div className="cluster">
          <button
            type="button"
            className={connected ? "btn btn-sm" : "btn btn-primary"}
            disabled={starting}
            onClick={() => void connect()}
          >
            {starting ? "Opening…" : connected ? "Connect another account" : `Connect ${info.label}`}
          </button>
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
