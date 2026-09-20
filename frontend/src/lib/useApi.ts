import { useCallback, useEffect, useState } from "react";
import { ApiError } from "../api";

interface State<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
}

/**
 * Fetch on mount and whenever `deps` change, cancelling the previous request so a slow
 * response can never overwrite a newer one (typing in a search box fires several).
 */
export function useApi<T>(fetcher: (signal: AbortSignal) => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<State<T>>({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    // Keep the previous data on screen while reloading, so tables don't flash empty.
    setState((s) => ({ ...s, loading: true }));
    fetcher(controller.signal)
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((e: unknown) => {
        if ((e as Error).name === "AbortError") return;
        setState((s) => ({ ...s, error: e as ApiError, loading: false }));
      });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}
