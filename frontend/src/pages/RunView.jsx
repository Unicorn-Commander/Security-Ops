import React from 'react';
import { useParams, useNavigate, useSearchParams, Link } from 'react-router-dom';

const API = '/api/v1';

async function apiFetch(path, { method = 'GET', body } = {}) {
  const token = localStorage.getItem('secops_token');
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(API + path, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
  });
  const raw = await res.text();
  let data = null;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = null; }
  if (!res.ok) {
    const env = (data && data.error) || {};
    const err = new Error(env.message || `Request failed (${res.status})`);
    err.code = env.code || 'error';
    err.detail = env.detail || null;
    err.status = res.status;
    throw err;
  }
  return data;
}

function fmt(dt) {
  if (!dt) return '—';
  try { return new Date(dt).toLocaleString(); } catch { return String(dt); }
}

const RUN_MODES = ['QUICK', 'STANDARD', 'DEEP'];
const RUN_COLORS = {
  PENDING: '#d97706', RUNNING: '#2563eb', STOPPED: '#dc2626',
  COMPLETED: '#16a34a', FAILED: '#dc2626', DENIED: '#dc2626',
};
const SEV_COLORS = {
  INFO: '#64748b', LOW: '#0891b2', MEDIUM: '#d97706', HIGH: '#ea580c', CRITICAL: '#dc2626',
};

function RunBadge({ value }) {
  return <span className="badge" style={{ background: RUN_COLORS[value] || '#475569' }}>{value}</span>;
}
function SevBadge({ value }) {
  return <span className="badge" style={{ background: SEV_COLORS[value] || '#475569' }}>{value}</span>;
}

// --- Start a run. THE gate is enforced server-side in services.runs.start_run:
// each target is check-scoped; a denial returns 403 and creates no RUNNING run. ---
function StartRun({ defaultEngagement, onStarted }) {
  const [engagementId, setEngagementId] = React.useState(defaultEngagement || '');
  const [mode, setMode] = React.useState('STANDARD');
  const [targetsText, setTargetsText] = React.useState('');
  const [modelProfile, setModelProfile] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    const targets = targetsText.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    if (!engagementId.trim()) { setError({ code: 'input', message: 'Engagement id is required.' }); return; }
    if (targets.length === 0) { setError({ code: 'input', message: 'At least one target is required.' }); return; }

    setSubmitting(true);
    try {
      const body = { mode, targets };
      if (modelProfile.trim()) body.model_profile = modelProfile.trim();
      const run = await apiFetch(`/engagements/${engagementId.trim()}/runs`, { method: 'POST', body });
      onStarted(run.id);
    } catch (e) {
      setError(e);
    } finally { setSubmitting(false); }
  }

  return (
    <div>
      <h1>Start a run</h1>
      <p className="muted">Every concrete target is authorization-checked by the gate before the run row is created. A denial (403) records an audit event and creates no run.</p>

      <div className="card">
        {error && (
          <div className="error">
            <div><strong>{error.code}</strong>: {error.message}</div>
            {error.detail && <pre style={{ marginTop: 8 }}>{JSON.stringify(error.detail, null, 2)}</pre>}
          </div>
        )}
        <form onSubmit={submit}>
          <div className="field">
            <label className="label">Engagement id</label>
            <input className="input mono" value={engagementId} onChange={(e) => setEngagementId(e.target.value)} placeholder="uuid of an ACTIVE engagement" />
          </div>
          <div className="grid2">
            <div className="field">
              <label className="label">Mode</label>
              <select className="select" value={mode} onChange={(e) => setMode(e.target.value)}>
                {RUN_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
            <div className="field">
              <label className="label">Model profile (optional)</label>
              <input className="input" value={modelProfile} onChange={(e) => setModelProfile(e.target.value)} placeholder="inherits the engagement profile" />
            </div>
          </div>
          <div className="field">
            <label className="label">Targets (one per line or comma-separated — each is gate-checked)</label>
            <textarea value={targetsText} onChange={(e) => setTargetsText(e.target.value)} placeholder={'https://brigade.unicorncommander.ai/login\nbrigade.unicorncommander.ai/api'} />
          </div>
          <button className="btn" disabled={submitting}>{submitting ? 'Starting…' : 'Start run'}</button>
        </form>
      </div>

      <p className="muted">
        Tip: create + activate an engagement on the <Link to="/engagements" className="mono">Engagements</Link> page,
        then use its “Start run” action to prefill the engagement id here.
      </p>
    </div>
  );
}

// --- View a single run + its findings, polling while it is live. ---
function RunDetail({ runId }) {
  const [run, setRun] = React.useState(null);
  const [findings, setFindings] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const [r, f] = await Promise.all([
        apiFetch(`/runs/${runId}`),
        apiFetch(`/runs/${runId}/findings?limit=200&offset=0`),
      ]);
      setRun(r);
      setFindings(f.items || []);
      setError(null);
    } catch (e) {
      setError(e);
    } finally { setLoading(false); }
  }, [runId]);

  React.useEffect(() => { setLoading(true); load(); }, [load]);

  const status = run ? run.status : null;
  React.useEffect(() => {
    if (status !== 'PENDING' && status !== 'RUNNING') return undefined;
    const t = window.setInterval(() => { load(); }, 4000);
    return () => window.clearInterval(t);
  }, [status, load]);

  async function stop() {
    if (!window.confirm('Stop this run?')) return;
    setBusy(true);
    try { await apiFetch(`/runs/${runId}/stop`, { method: 'POST' }); await load(); }
    catch (e) { setError(e); }
    finally { setBusy(false); }
  }

  if (loading && !run) return <div className="card empty">Loading run…</div>;

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0 }}>Run</h1>
        <Link to="/runs" className="btn btn-ghost btn-sm">+ New run</Link>
      </div>
      <div className="mono muted" style={{ marginBottom: 12 }}>{runId}</div>

      {error && <div className="error">{error.code}: {error.message}</div>}

      {run && (
        <div className="card">
          <div className="row" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
            <div className="row">
              <RunBadge value={run.status} />
              <span className="mono">{run.mode}</span>
              <span className="muted mono">{run.model_profile}</span>
            </div>
            {(run.status === 'PENDING' || run.status === 'RUNNING') && (
              <button className="btn btn-danger btn-sm" disabled={busy} onClick={stop}>Stop run</button>
            )}
          </div>

          <div className="grid2">
            <div className="field" style={{ marginBottom: 0 }}>
              <label className="label">Engagement</label>
              <div className="mono">{run.engagement_id}</div>
            </div>
            <div className="field" style={{ marginBottom: 0 }}>
              <label className="label">Strix run id</label>
              <div className="mono">{run.strix_run_id || '—'}</div>
            </div>
          </div>

          <div className="field" style={{ marginTop: 12, marginBottom: 0 }}>
            <label className="label">Targets ({(run.targets || []).length})</label>
            {(run.targets || []).length === 0 ? <span className="muted">—</span>
              : (run.targets || []).map((t, i) => <div key={i} className="mono">{t}</div>)}
          </div>

          <div className="row" style={{ marginTop: 12, gap: 24 }}>
            <div><span className="label">Started</span><div className="muted">{fmt(run.started_at)}</div></div>
            <div><span className="label">Ended</span><div className="muted">{fmt(run.ended_at)}</div></div>
            <div><span className="label">Cost</span><div className="muted">{run.cost_usd != null ? `$${run.cost_usd}` : '—'}</div></div>
          </div>

          {run.error && <div className="error" style={{ marginTop: 12 }}>{run.error}</div>}

          {run.status === 'PENDING' && (
            <p className="muted" style={{ marginTop: 12 }}>
              The gate authorized this run. The Strix runner executes in Phase 2 — in Phase 1 the run stays PENDING
              (this view proves the authorization path end-to-end). Findings will populate here once the runner lands.
            </p>
          )}
        </div>
      )}

      <div className="card">
        <h2>Findings</h2>
        {findings.length === 0 ? (
          <div className="empty">No findings recorded for this run yet.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th><th>Title</th><th>Status</th><th>Endpoint</th><th>CWE</th><th>Verified by</th><th>Found</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td><SevBadge value={f.severity} /></td>
                    <td>{f.title}</td>
                    <td className="mono">{f.status}</td>
                    <td className="mono">{f.endpoint || '—'}</td>
                    <td className="mono">{f.cwe || '—'}</td>
                    <td className="muted">{f.verified_by || '—'}</td>
                    <td className="muted">{fmt(f.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default function RunView() {
  const { runId } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  if (!runId) {
    return (
      <StartRun
        defaultEngagement={searchParams.get('engagement') || ''}
        onStarted={(id) => navigate(`/runs/${id}`)}
      />
    );
  }
  return <RunDetail runId={runId} />;
}
