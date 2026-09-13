import { useEffect, useState } from "react";
import { ApiError, listAssets } from "../api";
import type { Asset } from "../types";

export function AssetsView() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAssets()
      .then((d) => {
        setAssets(d.assets);
        setTotal(d.total);
      })
      .catch((e: ApiError) => setError(e.message));
  }, []);

  if (error) return <div className="banner error">{error}</div>;

  return (
    <div className="panel">
      <h2>Discovered assets ({total})</h2>
      {assets.length === 0 ? (
        <p className="empty">No assets discovered yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th className="num">Port</th>
              <th>Technology</th>
              <th>IP</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.hostname}</td>
                <td className="num">{a.port}</td>
                <td className="mono dim">{a.technology ?? "—"}</td>
                <td className="mono dim">{a.ip_address ?? "—"}</td>
                <td className="dim">{new Date(a.last_seen_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
