import { useId, useState } from "react";
import type { FormEvent } from "react";
import { ApiError, addDomain, listDomains, verifyDomain } from "../api";
import { relativeTime } from "../lib/format";
import { toHash } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { Domain, VerifyResult } from "../types";
import { Badge, Banner, EmptyState, ErrorBanner, PageHeader, SkeletonRows } from "./ui";

const STATUS_TONE = { verified: "success", pending: "warning", failed: "danger" } as const;
const STATUS_LABEL = { verified: "Verified", pending: "Not verified yet", failed: "Verification failed" } as const;

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
    <form className="panel stack" onSubmit={submit} aria-label="Add a domain" noValidate>
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
        Just the name, without https:// or a path. Subdomains of a verified domain are covered by it.
      </span>
      {error && <p role="alert" className="form-error">{error}</p>}
    </form>
  );
}

function DomainCard({ domain, onChanged }: { domain: Domain; onChanged: () => void }) {
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const titleId = `domain-${domain.id}`;
  const { record_name: name, record_value: value } = domain.verification;

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

  return (
    <article className="panel stack" aria-labelledby={titleId}>
      <div className="domain-head">
        <h2 id={titleId} className="mono">{domain.domain}</h2>
        <Badge tone={STATUS_TONE[domain.verification_status]}>{STATUS_LABEL[domain.verification_status]}</Badge>
      </div>

      {domain.verification_status === "verified" ? (
        <p className="muted">
          Verified {domain.verified_at ? relativeTime(domain.verified_at) : ""}.{" "}
          <a href={toHash("scans", { domain: domain.id })}>
            Scan this domain<span className="sr-only">: {domain.domain}</span>
          </a>
        </p>
      ) : (
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
              <code>{name}</code> <CopyButton text={name} what={`record name for ${domain.domain}`} />
            </dd>
            <dt>Value</dt>
            <dd>
              <code>{value}</code> <CopyButton text={value} what={`record value for ${domain.domain}`} />
            </dd>
          </dl>
          <div className="cluster">
            <button type="button" className="btn btn-primary btn-sm" onClick={() => void check()} disabled={checking}>
              {checking ? "Checking…" : "Check verification"}
              <span className="sr-only"> for {domain.domain}</span>
            </button>
          </div>
        </>
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
  const { data, error, loading, reload } = useApi((signal) => listDomains(signal), []);
  const [announce, setAnnounce] = useState("");

  return (
    <div className="stack">
      <PageHeader
        title="Domains"
        description="Prove you own a domain, then scan it. Cerberus only scans domains you have verified."
      />

      <AddDomain onAdded={(domain) => { setAnnounce(`Added ${domain.domain}. Publish the DNS record to verify it.`); reload(); }} />
      <div role="status" aria-live="polite" className="sr-only">{announce}</div>

      {error && <ErrorBanner error={error} onRetry={reload} />}
      {!data && loading && <div className="panel" aria-busy="true"><SkeletonRows rows={3} /></div>}

      {data && data.length === 0 && (
        <div className="panel">
          <EmptyState title="No domains yet">
            Add a domain you own above. You will get a DNS record to publish; once Cerberus can see it, the
            domain is yours to scan.
          </EmptyState>
        </div>
      )}

      {data?.map((domain) => <DomainCard key={domain.id} domain={domain} onChanged={reload} />)}
    </div>
  );
}
