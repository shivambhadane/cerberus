import { useState } from "react";
import { ApiError, addTestbed, listTestbeds } from "../api";
import { toHash } from "../lib/router";
import { useApi } from "../lib/useApi";
import type { Domain, TestbedTarget } from "../types";
import { Badge, Banner, EmptyState, ErrorBanner, PageHeader, SkeletonRows } from "./ui";

function CopyCode({ text, what }: { text: string; what: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="code-block-wrapper">
      <pre className="code-snippet">
        <code>{text}</code>
      </pre>
      <button
        type="button"
        className="btn btn-ghost btn-sm copy-code-btn"
        onClick={() => void copy()}
        title={`Copy ${what}`}
      >
        {copied ? "Copied!" : "Copy"}
        <span className="sr-only"> {what}</span>
      </button>
    </div>
  );
}

function TestbedCard({
  target,
  onAdded,
}: {
  target: TestbedTarget;
  onAdded: (domain: Domain) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAdd() {
    setBusy(true);
    setError(null);
    try {
      const res = await addTestbed(target.id);
      onAdded(res);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to add target. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const isDocker = target.category === "docker";
  const primaryLabel = isDocker ? "Docker Lab" : "Public Benchmark";
  const extraTags = (target.tags || []).filter(
    (tag) => tag.toLowerCase() !== primaryLabel.toLowerCase()
  );

  return (
    <article className="panel stack testbed-card" aria-labelledby={`testbed-${target.id}`}>
      <div className="testbed-card-head">
        <div>
          <div className="cluster gap-xs">
            <Badge tone={isDocker ? "warning" : "info"}>{primaryLabel}</Badge>
            {extraTags.map((tag) => (
              <Badge key={tag} tone="neutral">
                {tag}
              </Badge>
            ))}
          </div>
          <h3 id={`testbed-${target.id}`} className="testbed-title">
            {target.name}
          </h3>
          <p className="mono muted text-sm">{target.domain}{target.ports && target.ports.length > 0 ? ` (port ${target.ports.join(", ")})` : ""}</p>
        </div>
        <div className="testbed-action">
          {target.already_added && target.domain_id ? (
            <a
              href={toHash("scans", { domain: target.domain_id })}
              className="btn btn-primary btn-sm"
            >
              Scan this target
            </a>
          ) : (
            <button
              type="button"
              className="btn btn-primary btn-sm"
              disabled={busy}
              onClick={() => void handleAdd()}
            >
              {busy ? "Adding…" : "Add & verify"}
            </button>
          )}
        </div>
      </div>

      <p className="testbed-desc">{target.description}</p>

      {target.docker_command && (
        <div className="stack gap-xs">
          <span className="field-label text-xs">Run container command:</span>
          <CopyCode text={target.docker_command} what={`Docker command for ${target.name}`} />
        </div>
      )}

      {target.docker_teardown && (
        <p className="field-hint text-xs">
          Stop container: <code className="mono">{target.docker_teardown}</code>
        </p>
      )}

      {target.url && (
        <p className="field-hint text-xs">
          URL:{" "}
          <a href={target.url} target="_blank" rel="noopener noreferrer">
            {target.url}
          </a>
        </p>
      )}

      {target.vulnerabilities && target.vulnerabilities.length > 0 && (
        <div className="testbed-flaws">
          <span className="field-label text-xs">Tested Vulnerabilities:</span>
          <div className="cluster gap-xs">
            {target.vulnerabilities.map((flaw) => (
              <span key={flaw} className="testbed-flaw-pill">
                {flaw}
              </span>
            ))}
          </div>
        </div>
      )}

      {target.provider_disclaimer && (
        <p className="field-hint text-xs italic">{target.provider_disclaimer}</p>
      )}

      {error && <p role="alert" className="form-error">{error}</p>}
    </article>
  );
}

export function TestLabsView({
  onAdded,
  embedded = false,
}: {
  onAdded?: (domain: Domain) => void;
  embedded?: boolean;
}) {
  const testbeds = useApi((signal) => listTestbeds(signal), []);
  const [filter, setFilter] = useState<"all" | "docker" | "public">("all");
  const [notice, setNotice] = useState<string | null>(null);

  const items = (testbeds.data ?? []).filter(
    (t) => filter === "all" || t.category === filter
  );

  function handleAdded(domain: Domain) {
    setNotice(`'${domain.domain}' has been added as a verified target. You can now launch a scan against it!`);
    testbeds.reload();
    if (onAdded) onAdded(domain);
  }

  return (
    <div className="stack">
      {!embedded && (
        <PageHeader
          title="Test Labs & Benchmarks"
          description="Sanctioned vulnerability targets and local Docker environments to test Cerberus safely and benchmark scanner precision with 1 click."
        />
      )}

      {notice && (
        <Banner tone="success" role="status">
          {notice}
        </Banner>
      )}

      <div className="toolbar space-between">
        <div className="cluster gap-xs">
          <button
            type="button"
            className={`btn btn-sm ${filter === "all" ? "btn-primary" : "btn-ghost"}`}
            onClick={() => setFilter("all")}
          >
            All targets ({testbeds.data?.length ?? 0})
          </button>
          <button
            type="button"
            className={`btn btn-sm ${filter === "docker" ? "btn-primary" : "btn-ghost"}`}
            onClick={() => setFilter("docker")}
          >
            Docker Labs ({testbeds.data?.filter((t) => t.category === "docker").length ?? 0})
          </button>
          <button
            type="button"
            className={`btn btn-sm ${filter === "public" ? "btn-primary" : "btn-ghost"}`}
            onClick={() => setFilter("public")}
          >
            Public Benchmarks ({testbeds.data?.filter((t) => t.category === "public").length ?? 0})
          </button>
        </div>
      </div>

      {testbeds.error && <ErrorBanner error={testbeds.error} onRetry={testbeds.reload} />}

      {!testbeds.data && testbeds.loading && (
        <div className="panel" aria-busy="true">
          <SkeletonRows rows={4} />
        </div>
      )}

      {testbeds.data && items.length === 0 && (
        <div className="panel">
          <EmptyState level={3} title="No testbeds found">
            Try switching filter view.
          </EmptyState>
        </div>
      )}

      <div className="testbed-grid">
        {items.map((target) => (
          <TestbedCard key={target.id} target={target} onAdded={handleAdded} />
        ))}
      </div>
    </div>
  );
}
