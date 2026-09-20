import { listConnections } from "../api";
import { formatDate } from "../lib/format";
import { toHash } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { User } from "../types";
import { Avatar, displayName } from "./Avatar";
import { ProviderLogo } from "./DeploymentProviders";
import { Icon } from "./icons";
import { Badge, EmptyState, ErrorBanner, PageHeader, SkeletonRows } from "./ui";

const SIGN_IN_METHODS: Record<string, string> = {
  "google.com": "Google",
  "github.com": "GitHub",
  password: "Email and password",
};

const PROVIDER_LABELS: Record<string, string> = { vercel: "Vercel", netlify: "Netlify", cloudflare: "Cloudflare" };

export function signInMethod(user: Pick<User, "auth_provider">): string {
  // Accounts made before sign-in methods were recorded (or with the local password login) have none.
  return user.auth_provider ? (SIGN_IN_METHODS[user.auth_provider] ?? user.auth_provider) : "Email and password";
}

function ConnectedAccounts() {
  const { data, error, loading, reload } = useApi((signal) => listConnections(signal), []);
  return (
    <section className="panel" aria-labelledby="profile-connections">
      <div className="panel-head">
        <h2 id="profile-connections">Connected deployment accounts</h2>
        <a className="btn btn-ghost btn-sm" href={toHash("domains", {})}>
          Manage on Targets
        </a>
      </div>
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <SkeletonRows rows={2} />}
      {data && data.length === 0 && (
        <EmptyState title="Nothing connected">
          Connect Vercel, Netlify or Cloudflare from Targets to verify a site you deploy there without owning a
          custom domain.
        </EmptyState>
      )}
      {data && data.length > 0 && (
        <ul className="plain-list" role="list">
          {data.map((connection) => (
            <li key={connection.id} className="connection-row">
              <span className="connection-name">
                <span className={`provider-mark-sm provider-${connection.provider}`} aria-hidden="true">
                  <ProviderLogo provider={connection.provider} size={15} />
                </span>
                <span className="connection-labels">
                  <strong>{PROVIDER_LABELS[connection.provider] ?? connection.provider}</strong>
                  <span className="muted">{connection.label}</span>
                </span>
              </span>
              <span className="muted">Connected {formatDate(connection.connected_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function ProfileView({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const method = signInMethod(user);
  const fromGoogle = user.auth_provider === "google.com";

  return (
    <div className="stack">
      <PageHeader title="Profile" description="Your Cerberus account and how you signed in." />

      <section className="panel profile-card" aria-labelledby="profile-identity">
        <Avatar user={user} size="lg" label={user.picture_url ? "Your profile photo" : "Your initials"} />
        <div className="profile-identity">
          <h2 id="profile-identity">{displayName(user)}</h2>
          <p className="muted">{user.email}</p>
          <div className="cluster">
            <Badge tone="neutral">Signed in with {method}</Badge>
            <Badge tone={user.email_verified ? "success" : "warning"}>
              {user.email_verified ? "Email verified" : "Email not verified"}
            </Badge>
          </div>
        </div>
        <button type="button" className="btn profile-signout" onClick={onSignOut}>
          <Icon name="signout" />
          Sign out
        </button>
      </section>

      <section className="panel" aria-labelledby="profile-details">
        <div className="panel-head">
          <h2 id="profile-details">Account details</h2>
        </div>
        <dl className="facts">
          <dt>Name</dt>
          <dd>{user.name?.trim() || <span className="muted">Not set</span>}</dd>
          <dt>Email</dt>
          <dd>{user.email}</dd>
          <dt>Sign-in method</dt>
          <dd>{method}</dd>
          <dt>Member since</dt>
          <dd>{formatDate(user.created_at)}</dd>
          <dt>Last sign-in</dt>
          <dd>{user.last_login_at ? formatDate(user.last_login_at) : <span className="muted">Not recorded</span>}</dd>
        </dl>
        <p className="field-hint">
          {fromGoogle
            ? "Your name and photo come from your Google account. The photo follows changes you make to your Google profile the next time you sign in."
            : user.picture_url
              ? `Your photo comes from your ${method} account.`
              : "No profile photo is on file for this sign-in method, so Cerberus shows your initials. Sign in with Google to use your Google photo."}
        </p>
      </section>

      <ConnectedAccounts />
    </div>
  );
}
