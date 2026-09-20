import { useEffect, useId, useState } from "react";
import type { FormEvent } from "react";
import { ApiError, addDomain, listDomains, listProviders, verifyDomain, verifyPlatformTarget } from "../api";
import { relativeTime } from "../lib/format";
import { toHash, useRoute } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { Connection, Domain, ProviderInfo, VerifyResult } from "../types";
import { DeploymentPanel } from "./DeploymentProviders";
import { TestLabsView } from "./TestLabsView";
import { Badge, Banner, EmptyState, ErrorBanner, PageHeader, SkeletonRows } from "./ui";

const STATUS_TONE = { verified: "success", pending: "warning", failed: "danger" } as const;
const STATUS_LABEL = { verified: "Verified", pending: "Not verified yet", failed: "Verification failed" } as const;

const PROVIDER_LABEL: Record<string, string> = { vercel: "Vercel", netlify: "Netlify", cloudflare: "Cloudflare" };

type Method = "domain" | "deployment" | "labs";

/** What each short code the callback can put in the URL means to a person. */
const CONNECT_ERRORS: Record<string, string> = {
  access_denied: "Access was declined, so nothing was connected.",
  invalid_state: "That connection attempt expired or did not start here. Start it again from this page.",
  authorization_failed: "The platform did not accept the sign-in. Try connecting again.",
  too_many_connections: "You have reached the limit of connected accounts. Disconnect one first.",
  provider_unavailable: "The platform could not be reached. Try again in a moment.",
  provider_not_configured: "This provider is not set up on this server.",
};

/** Copy a value to the clipboard, and say so. */
function CopyButton({ text, what }: { text: string; what: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable: the value is on screen to select by hand */
    }
  }
  return (
    <button type="button" className="btn btn-ghost btn-sm" onClick={() => void copy()}>
      {copied ? "Copied" : "Copy"}
      <span className="sr-only"> {what}</span>
    </button>
  );
}

function AddDomain({ onAdded }: { onAdded: (domain: Domain) => void }) {
  const id = useId();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const domain = await addDomain(value);
      setValue("");
      onAdded(domain);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="panel stack" onSubmit={submit} aria-label="Add a custom domain" noValidate>
      <div className="toolbar">
        <div className="field grow">
          <label className="field-label" htmlFor={id}>Domain you own</label>
          <input
            id={id}
            className="input"
            value={value}
            placeholder="example.com"
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            aria-describedby={`${id}-hint`}
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={busy || !value.trim()}>
          {busy ? "Adding…" : "Add domain"}
        </button>
      </div>
      <span id={`${id}-hint`} className="field-hint">
        Just the name, without https:// or a path. You verify it with a DNS record, and subdomains of a verified
        domain are covered by it.
      </span>
      {error && <p role="alert" className="form-error">{error}</p>}
    </form>
  );
}

/** "Add a custom domain", "Add a deployment", or "Test labs": ways to add and verify targets. */
function MethodChoice({ value, onChange }: { value: Method; onChange: (next: Method) => void }) {
  const name = useId();
  const options: { id: Method; title: string; body: string }[] = [
    {
      id: "domain",
      title: "Custom domain",
      body: "A domain you control DNS for, like example.com. Verified with a DNS TXT record.",
    },
    {
      id: "deployment",
      title: "Deployment",
      body: "An app on Vercel, Netlify or Cloudflare Pages, like my-app.vercel.app. Verified through your account there.",
    },
    {
      id: "labs",
      title: "Test labs & benchmarks",
      body: "Sanctioned targets (Juice Shop, DVWA, Apache 2.4.49, Acunetix) to safely test scans.",
    },
  ];
  return (
    <fieldset className="choice-group">
      <legend className="field-label">What do you want to add?</legend>
      <div className="choice-options">
      {options.map((option) => (
        <label key={option.id} className="choice" data-checked={value === option.id}>
          <input
            type="radio"
            name={name}
            value={option.id}
            checked={value === option.id}
            onChange={() => onChange(option.id)}
          />
          <span className="choice-body">
            <strong>{option.title}</strong>
            <span className="muted">{option.body}</span>
          </span>
        </label>
      ))}
      </div>
    </fieldset>
  );
}

function DomainCard({
  domain,
  connections,
  onChanged,
}: {
  domain: Domain;
  connections: Connection[];
  onChanged: () => void;
}) {
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const titleId = `domain-${domain.id}`;

  const platform = domain.provider ?? (domain.verification ? null : domain.verification_method);
  const platformLabel = platform ? (PROVIDER_LABEL[platform] ?? platform) : null;
  const accounts = platform ? connections.filter((c) => c.provider === platform) : [];

  async function check() {
    setChecking(true);
    setError(null);
    try {
      const outcome = await verifyDomain(domain.id);
      setResult(outcome);
      if (outcome.verified) onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Try again.");
    } finally {
      setChecking(false);
    }
  }

  async function checkWith(connection: Connection) {
    if (!domain.provider_project_id) return;
    setChecking(true);
    setError(null);
    try {
      await verifyPlatformTarget(domain.id, connection.id, domain.provider_project_id);
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Try again.");
    } finally {
      setChecking(false);
    }
  }

  return (
    <article className="panel stack" aria-labelledby={titleId}>
      <div className="domain-head">
        <h3 id={titleId} className="mono">{domain.domain}</h3>
        <span className="cluster">
          {platformLabel && <Badge tone="info">via {platformLabel}</Badge>}
          <Badge tone={STATUS_TONE[domain.verification_status]}>{STATUS_LABEL[domain.verification_status]}</Badge>
        </span>
      </div>

      {domain.verification_status === "verified" ? (
        <p className="muted">
          {platformLabel ? `Verified through your ${platformLabel} account` : "Verified"}
          {domain.verified_at ? ` ${relativeTime(domain.verified_at)}` : ""}.{" "}
          <a href={toHash("scans", { domain: domain.id })}>
            Scan this domain<span className="sr-only">: {domain.domain}</span>
          </a>
          {platformLabel && (
            <span className="field-hint block">
              Cerberus asks {platformLabel} again before every scan, so a removed project or a revoked connection
              stops scans.
            </span>
          )}
        </p>
      ) : platformLabel ? (
        <>
          <p>
            <strong>{domain.domain}</strong> is not verified right now. This usually means the {platformLabel}{" "}
            account that proved it was disconnected, or the project no longer lists this address.
          </p>
          {accounts.length > 0 && domain.provider_project_id ? (
            <div className="cluster">
              {accounts.map((connection) => (
                <button
                  key={connection.id}
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={checking}
                  onClick={() => void checkWith(connection)}
                >
                  {checking ? "Checking…" : `Verify with ${connection.label}`}
                  <span className="sr-only"> for {domain.domain}</span>
                </button>
              ))}
            </div>
          ) : (
            <p className="field-hint">
              Connect your {platformLabel} account under “Add a deployment”, then verify it here.
            </p>
          )}
        </>
      ) : (
        domain.verification && (
          <>
            <p>
              To prove you own <strong>{domain.domain}</strong>, add this DNS record wherever you manage its DNS,
              then check. DNS changes can take a few minutes to appear.
            </p>
            <dl className="kv record">
              <dt>Type</dt>
              <dd>TXT</dd>
              <dt>Name</dt>
              <dd>
                <code>{domain.verification.record_name}</code>{" "}
                <CopyButton text={domain.verification.record_name} what={`record name for ${domain.domain}`} />
              </dd>
              <dt>Value</dt>
              <dd>
                <code>{domain.verification.record_value}</code>{" "}
                <CopyButton text={domain.verification.record_value} what={`record value for ${domain.domain}`} />
              </dd>
            </dl>
            <div className="cluster">
              <button type="button" className="btn btn-primary btn-sm" onClick={() => void check()} disabled={checking}>
                {checking ? "Checking…" : "Check verification"}
                <span className="sr-only"> for {domain.domain}</span>
              </button>
            </div>
          </>
        )
      )}

      {/* Always in the page, so a screen reader hears the result when it appears. */}
      <div role="status" aria-live="polite">
        {result && !result.verified && (
          <Banner tone={result.reason === "lookup_failed" ? "warning" : "info"}>{result.detail}</Banner>
        )}
        {result?.verified && <Banner tone="success">{result.domain.domain} is verified. You can scan it now.</Banner>}
      </div>
      {error && <p role="alert" className="form-error">{error}</p>}
    </article>
  );
}

export function DomainsView() {
  const { params, navigate } = useRoute();
  const domains = useApi((signal) => listDomains(signal), []);
  const providers = useApi((signal) => listProviders(signal), []);
  const [method, setMethod] = useState<Method>("domain");
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [openConnection, setOpenConnection] = useState<string | null>(null);
  const [announce, setAnnounce] = useState("");

  // The platform sends the browser back here with a short outcome code (`?provider=vercel&connected=1`).
  // Show it once, then take it out of the URL so a reload does not repeat it. The codes are only text
  // to display and a connection to open: the connection itself was made server-side.
  useEffect(() => {
    const provider = params.get("provider");
    if (!provider) return;
    const label = PROVIDER_LABEL[provider] ?? "The platform";
    setMethod("deployment");
    if (params.get("connected") === "1") {
      setNotice({ tone: "success", text: `${label} is connected. Choose a project below to add and verify it.` });
      setOpenConnection(params.get("account"));
      providers.reload();
    } else {
      const code = params.get("error") ?? "";
      setNotice({ tone: "error", text: CONNECT_ERRORS[code] ?? `${label} could not be connected. Try again.` });
    }
    navigate("domains", {}, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const connections: Connection[] = (providers.data ?? []).flatMap((info: ProviderInfo) => info.connections);

  function added(domain: Domain) {
    setAnnounce(
      domain.verification_status === "verified"
        ? `${domain.domain} is verified. You can scan it now.`
        : `Added ${domain.domain}. Publish the DNS record to verify it.`,
    );
    domains.reload();
  }

  return (
    <div className="stack">
      <PageHeader
        title="Targets"
        description="Prove you control a domain or a deployment, then scan it. Cerberus only scans targets you have verified."
      />

      <MethodChoice value={method} onChange={setMethod} />

      {notice && (
        <Banner tone={notice.tone} role={notice.tone === "error" ? "alert" : "status"}>
          {notice.text}
        </Banner>
      )}

      {method === "domain" ? (
        <AddDomain onAdded={added} />
      ) : method === "deployment" ? (
        <DeploymentPanel
          providers={providers.data}
          loading={providers.loading}
          error={providers.error}
          reload={providers.reload}
          openConnection={openConnection}
          onAdded={added}
          onChanged={(text) => {
            setAnnounce(text);
            providers.reload();
            domains.reload();
          }}
        />
      ) : (
        <TestLabsView onAdded={added} embedded={true} />
      )}
      <div role="status" aria-live="polite" className="sr-only">{announce}</div>

      <h2 className="section-title">Your targets</h2>
      {domains.error && <ErrorBanner error={domains.error} onRetry={domains.reload} />}
      {!domains.data && domains.loading && <div className="panel" aria-busy="true"><SkeletonRows rows={3} /></div>}

      {domains.data && domains.data.length === 0 && (
        <div className="panel">
          <EmptyState level={3} title="No targets yet">
            Add a custom domain and publish the DNS record, or connect the platform your app is deployed on. Once
            a target is verified it is yours to scan.
          </EmptyState>
        </div>
      )}

      {domains.data?.map((domain) => (
        <DomainCard key={domain.id} domain={domain} connections={connections} onChanged={domains.reload} />
      ))}
    </div>
  );
}
