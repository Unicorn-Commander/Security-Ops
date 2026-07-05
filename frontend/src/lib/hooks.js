/* Small data hooks: useResource (load + reload + poll) and useMutation. */
import React from 'react';
import { api } from './api.js';

export function useResource(loader, deps = [], { pollWhile } = {}) {
  const [data, setData] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const loaderRef = React.useRef(loader);
  loaderRef.current = loader;

  const reload = React.useCallback(async ({ quiet } = {}) => {
    if (!quiet) setLoading(true);
    try { const d = await loaderRef.current(); setData(d); setError(null); }
    catch (e) { setError(e); }
    finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  React.useEffect(() => { reload(); }, [reload]);

  const shouldPoll = pollWhile ? pollWhile(data) : false;
  React.useEffect(() => {
    if (!shouldPoll) return undefined;
    const t = setInterval(() => reload({ quiet: true }), 4000);
    return () => clearInterval(t);
  }, [shouldPoll, reload]);

  return { data, error, loading, reload, setData };
}

export function useMutation() {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState(null);
  const run = React.useCallback(async (path, opts) => {
    setBusy(true); setError(null);
    try { return await api(path, opts); }
    catch (e) { setError(e); throw e; }
    finally { setBusy(false); }
  }, []);
  return { run, busy, error, setError };
}
