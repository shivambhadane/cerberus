import { listAssets } from "../api";
import { relativeTime } from "../lib/format";
import { toHash, useRoute } from "../lib/router";
import { useApi } from "../lib/useApi";
import { CriticalityEditor } from "./CriticalityEditor";
import { EmptyState, ErrorBanner, NewScanLink, PageHeader, Pagination, SkeletonRows, TableWrap } from "./ui";

export function AssetsView() {
  const { params, patch } = useRoute();
  const page = Math.max(1, Number(params.get("page") ?? "1") || 1);
  const { data, error, loading, reload } = useApi((signal) => listAssets(page, signal), [page]);

  return (
    <div className="stack">
      <PageHeader title="Assets" description="The hosts and ports Cerberus found, and how much each one matters." actions={<NewScanLink />} />
      <p className="legend">
        Criticality is a quarter of every finding's score. Cerberus starts with a guess from the hostname
        (<strong>inferred</strong>); replace it with your own judgement and the asset's findings are re-ranked
        straight away. Your setting is never overwritten by a re-scan.
      </p>

      {error && <ErrorBanner error={error} onRetry={reload} />}

      <div className="panel">
        {!data && loading && <SkeletonRows rows={6} />}

        {data && data.items.length === 0 && (
          <EmptyState title="No assets yet" action={<a className="btn btn-primary" href={toHash("scans", {})}>Start a scan</a>}>
            Assets are the hosts and open ports a scan discovers. Run a scan against a domain you are
            authorized to test and they will be listed here.
          </EmptyState>
        )}

        {data && data.items.length > 0 && (
          <TableWrap label="Assets" busy={loading}>
            <table className="table">
              <caption className="sr-only">Discovered assets</caption>
              <thead>
                <tr>
                  <th scope="col">Asset</th>
                  <th scope="col">Technology</th>
                  <th scope="col">Criticality</th>
                  <th scope="col" className="num">Findings</th>
                  <th scope="col">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <span className="mono nowrap">{a.hostname}:{a.port}</span>
                      {a.ip_address && <p className="muted mono">{a.ip_address}</p>}
                    </td>
                    <td>
                      <span className="mono">{a.technology ?? "Not identified"}</span>
                      {a.discovered_by_tool && <p className="muted">via {a.discovered_by_tool}</p>}
                    </td>
                    <td style={{ minWidth: "16rem" }}>
                      <CriticalityEditor asset={a} onSaved={reload} />
                    </td>
                    <td className="num">
                      {a.finding_count > 0 ? (
                        <a href={toHash("findings", { asset: a.id })}>
                          {a.finding_count}<span className="sr-only"> findings for {a.hostname}:{a.port}</span>
                        </a>
                      ) : (
                        "0"
                      )}
                    </td>
                    <td className="muted nowrap">
                      {relativeTime(a.last_seen_at)}
                      <p><a href={toHash("evidence", { target: `${a.hostname}:${a.port}` })}>Evidence<span className="sr-only"> for {a.hostname}:{a.port}</span></a></p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}

        {data && <Pagination page={page} total={data.total} noun="assets" onPage={(p) => patch({ page: p === 1 ? undefined : p }, false)} />}
      </div>
    </div>
  );
}
