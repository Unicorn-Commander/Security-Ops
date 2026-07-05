/* Runs — the ledger of authorized scans. Every concrete target is checked by the
 * server-side authorization gate BEFORE a run row exists; a denial (403) creates
 * no run and is surfaced here as a first-class, intentional state. Live-polls
 * while any run is RUNNING. */
import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource, useMutation } from '../lib/hooks.js';
import { PageHead, StatusBadge, EmptyState, SkeletonRows, ErrorBanner, Drawer, useToast, rowActivate } from '../components/ui.jsx';
import { PlayIcon, ShieldIcon, ChevronRightIcon, CrosshairIcon, CircleXIcon } from '../components/icons.jsx';
import { fmtMoney, relTime, titleCase } from '../lib/format.js';

const MODES = ['QUICK', 'STANDARD', 'DEEP'];
const FILTERS = [
  { label: 'All', value: '' },
  { label: 'Running', value: 'RUNNING' },
  { label: 'Pending', value: 'PENDING' },
  { label: 'Completed', value: 'COMPLETED' },
  { label: 'Failed', value: 'FAILED' },
  { label: 'Stopped', value: 'STOPPED' },
  { label: 'Denied', value: 'DENIED' },
];

/* A gate denial is not an error to hide — it's the product working. Give the 403
 * the same deny-verdict treatment as the scope preview on the Engagements page.
 * Client-side validation (missing engagement/targets) falls back to ErrorBanner. */
function GateFeedback({ error }) {
  if (!error) return null;
  const denied = error.status === 403 || /deny|denied|scope|gate|forbid|attest/i.test(error.code || '');
  if (!denied) return <ErrorBanner error={error} />;
  return (
    <div className="verdict verdict--deny" style={{ marginBottom: 'var(--s-4)' }}>
      <div className="verdict__head">
        <CircleXIcon size={22} style={{ color: 'var(--danger-strong)' }} />
        <div className="verdict__title">Gate denied — no run was created</div>
        <span className="chip" style={{ marginLeft: 'auto' }}>{error.code}</span>
      </div>
      <p style={{ marginTop: 8, color: 'var(--text-2)' }}>{error.message}</p>
      {error.detail != null && (
        <pre className="code" style={{ marginTop: 10, whiteSpace: 'pre-wrap' }}>
          {typeof error.detail === 'string' ? error.detail : JSON.stringify(error.detail, null, 2)}
        </pre>
      )}
    </div>
  );
}

function StartRunDrawer({ onClose, prefillEngagement }) {
  const toast = useToast();
  const navigate = useNavigate();
  const { data: engData, loading: engLoading } = useResource(() => api('/engagements?limit=100'), []);
  const active = (engData?.items || []).filter((e) => e.status === 'ACTIVE');
  const [engId, setEngId] = React.useState(prefillEngagement || '');
  const [mode, setMode] = React.useState('STANDARD');
  const [targetsText, setTargetsText] = React.useState('');
  const [profile, setProfile] = React.useState('');
  const { run, busy, error, setError } = useMutation();

  // Keep the selection pinned to a real ACTIVE engagement once the list resolves.
  React.useEffect(() => {
    if (active.length && !active.some((e) => e.id === engId)) setEngId(active[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engData]);

  const targets = targetsText.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);

  async function submit(e) {
    e.preventDefault();
    if (!engId) { setError({ code: 'input', message: 'Select an active engagement to start a run.' }); return; }
    if (targets.length === 0) { setError({ code: 'input', message: 'Enter at least one target — each is authorization-checked by the gate.' }); return; }
    const body = { mode, targets };
    if (profile.trim()) body.model_profile = profile.trim();
    try {
      const created = await run(`/engagements/${engId}/runs`, { method: 'POST', body });
      toast({ title: 'Run started', detail: `${targets.length} target${targets.length === 1 ? '' : 's'} authorized and queued.` });
      onClose();
      navigate(`/runs/${created.id}`);
    } catch { /* surfaced inline via GateFeedback */ }
  }

  return (
    <Drawer title="Start a run" subtitle="Each target is gate-checked before the run is created" onClose={onClose}
      footer={<>
        <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn--primary" form="run-form" disabled={busy || active.length === 0}><PlayIcon size={13} />{busy ? 'Starting…' : 'Start run'}</button>
      </>}>
      <GateFeedback error={error} />
      {!engLoading && active.length === 0 ? (
        <EmptyState icon={<ShieldIcon />} title="No active engagements">
          <p className="muted">A run can only target an <b>ACTIVE</b> engagement with attested scope. Create one and activate it on the Engagements page first.</p>
        </EmptyState>
      ) : (
        <form id="run-form" onSubmit={submit} className="stack">
          <div className="field">
            <label className="label">Engagement</label>
            <select className="select" value={engId} onChange={(e) => setEngId(e.target.value)} disabled={engLoading}>
              {engLoading && <option>Loading…</option>}
              {active.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
            </select>
            <div className="hint">Only active engagements are listed — the gate enforces scope + attestation per target.</div>
          </div>
          <div className="field">
            <label className="label">Mode</label>
            <div className="segmented">
              {MODES.map((m) => <button type="button" key={m} className={mode === m ? 'is-active' : ''} onClick={() => setMode(m)}>{titleCase(m)}</button>)}
            </div>
          </div>
          <div className="field">
            <label className="label">Targets</label>
            <textarea className="textarea mono" value={targetsText} onChange={(e) => setTargetsText(e.target.value)}
              placeholder={'https://brigade.unicorncommander.ai/login\nbrigade.unicorncommander.ai/api'} />
            <div className="hint">One per line or comma-separated. {targets.length > 0 ? `${targets.length} target${targets.length === 1 ? '' : 's'} — each gate-checked.` : 'Each is gate-checked; a denial creates no run.'}</div>
          </div>
          <div className="field">
            <label className="label">Model profile <span className="muted" style={{ textTransform: 'none', letterSpacing: 0 }}>· optional</span></label>
            <input className="input mono" value={profile} onChange={(e) => setProfile(e.target.value)} placeholder="inherits the engagement profile" />
          </div>
        </form>
      )}
    </Drawer>
  );
}

export default function Runs() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [status, setStatus] = React.useState('');
  const [starting, setStarting] = React.useState(() => params.has('engagement'));
  const prefill = params.get('engagement') || '';

  const { data, loading, error, reload } = useResource(
    () => api(`/runs?limit=100${status ? `&status=${status}` : ''}`),
    [status],
    { pollWhile: (d) => (d?.items || []).some((r) => r.status === 'RUNNING') },
  );
  const items = data?.items || [];
  const runningCount = items.filter((r) => r.status === 'RUNNING').length;

  function closeDrawer() {
    setStarting(false);
    if (params.has('engagement')) { params.delete('engagement'); setParams(params, { replace: true }); }
    reload();
  }

  return (
    <div className="page">
      <PageHead title="Runs"
        subtitle="Every target is authorization-checked by the gate before a run is created. A denial records an audit event and starts nothing."
        actions={<button className="btn btn--primary" onClick={() => setStarting(true)}><PlayIcon size={13} />Start run</button>} />

      <ErrorBanner error={error} />

      <div className="card">
        <div className="card__head">
          <PlayIcon size={16} style={{ color: 'var(--muted)' }} />
          <h2>All runs</h2>
          <div className="spacer" />
          {runningCount > 0 && (
            <span className="statusdot" style={{ marginRight: 'var(--s-3)' }}>
              <i className="live" style={{ background: 'var(--info)' }} />{runningCount} running · auto-refreshing
            </span>
          )}
          <div className="pillbar">
            {FILTERS.map((f) => (
              <button key={f.value} className={status === f.value ? 'is-active' : ''} onClick={() => setStatus(f.value)}>{f.label}</button>
            ))}
          </div>
        </div>

        {loading ? (
          <SkeletonRows rows={5} cols={6} />
        ) : items.length === 0 ? (
          <div className="card__body">
            <EmptyState icon={<CrosshairIcon />} title={status ? `No ${titleCase(status).toLowerCase()} runs` : 'No runs yet'}>
              <p className="muted">Start a run against an active engagement — every target is gate-checked before anything executes.</p>
            </EmptyState>
          </div>
        ) : (
          <div className="tablewrap"><table className="tbl tbl--rows">
            <thead><tr><th>Target(s)</th><th>Status</th><th>Mode</th><th>Model profile</th><th>Started</th><th>Cost</th><th></th></tr></thead>
            <tbody>
              {items.map((r) => {
                const targets = r.targets || [];
                const more = Math.max(0, targets.length - 1);
                return (
                  <tr key={r.id} {...rowActivate(() => navigate(`/runs/${r.id}`), `Open run ${(r.targets && r.targets[0]) || r.id}`)}>
                    <td>
                      <div className="mono nowrap" style={{ color: 'var(--text)' }}>{targets[0] || r.id}</div>
                      {more > 0 && <div className="muted" style={{ fontSize: 11 }}>+{more} more target{more === 1 ? '' : 's'}</div>}
                    </td>
                    <td><StatusBadge value={r.status} /></td>
                    <td>{titleCase(r.mode)}</td>
                    <td className="mono muted" style={{ fontSize: 12 }}>{r.model_profile || '—'}</td>
                    <td className="muted nowrap">{relTime(r.started_at || r.created_at)}</td>
                    <td className="col-actions tnum muted">{fmtMoney(r.cost_usd)}</td>
                    <td className="col-actions"><ChevronRightIcon size={16} style={{ color: 'var(--faint)' }} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        )}
      </div>

      {starting && <StartRunDrawer onClose={closeDrawer} prefillEngagement={prefill} />}
    </div>
  );
}
