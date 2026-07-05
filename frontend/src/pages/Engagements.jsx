import React from 'react';
import { Link } from 'react-router-dom';

// --- tiny self-contained API client (blueprint's src/api/client.js is a sibling
// module owned by another builder; this reduced skeleton stays runnable on its
// own by speaking the same '/api/v1' + {error:{code,message,detail}} envelope). ---
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

const TARGET_KINDS = ['DOMAIN', 'URL', 'IP_RANGE', 'REPO'];
const RUN_MODES = ['QUICK', 'STANDARD', 'DEEP'];

const STATUS_COLORS = {
  DRAFT: '#64748b', ACTIVE: '#16a34a', PAUSED: '#d97706',
  COMPLETED: '#2563eb', STOPPED: '#dc2626', EXPIRED: '#78716c',
};
function StatusBadge({ value }) {
  return <span className="badge" style={{ background: STATUS_COLORS[value] || '#475569' }}>{value}</span>;
}

const emptyRule = () => ({ kind: 'DOMAIN', value: '' });

function RuleList({ title, hint, rules, setRules }) {
  const patch = (i, p) => setRules(rules.map((r, j) => (j === i ? { ...r, ...p } : r)));
  return (
    <div className="field">
      <label className="label">{title}</label>
      {rules.length === 0 && <div className="muted" style={{ marginBottom: 6 }}>none</div>}
      {rules.map((r, i) => (
        <div className="row" key={i} style={{ marginBottom: 6 }}>
          <select className="select" style={{ width: 130 }} value={r.kind} onChange={(e) => patch(i, { kind: e.target.value })}>
            {TARGET_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <input
            className="input" style={{ flex: 1, minWidth: 200 }} value={r.value}
            placeholder={hint}
            onChange={(e) => patch(i, { value: e.target.value })}
          />
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setRules(rules.filter((_, j) => j !== i))}>{'✕'}</button>
        </div>
      ))}
      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setRules([...rules, emptyRule()])}>+ add rule</button>
    </div>
  );
}

export default function Engagements() {
  const [items, setItems] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);

  // create-engagement form
  const [name, setName] = React.useState('');
  const [modelProfile, setModelProfile] = React.useState('hybrid-local-sweep-verify');
  const [intensity, setIntensity] = React.useState('STANDARD');
  const [inScope, setInScope] = React.useState([emptyRule()]);
  const [exclusions, setExclusions] = React.useState([]);
  const [creating, setCreating] = React.useState(false);
  const [formMsg, setFormMsg] = React.useState(null);

  // scope dry-run (POST /engagements/{id}/scope/check — no audit-deny side effect)
  const [checkEng, setCheckEng] = React.useState('');
  const [checkTarget, setCheckTarget] = React.useState('');
  const [checkResult, setCheckResult] = React.useState(null);
  const [checking, setChecking] = React.useState(false);

  async function load() {
    setLoading(true); setError(null);
    try {
      const page = await apiFetch('/engagements?limit=100&offset=0');
      setItems(page.items || []);
    } catch (e) { setError(e); }
    finally { setLoading(false); }
  }
  React.useEffect(() => { load(); }, []);

  async function submitCreate(e) {
    e.preventDefault();
    setCreating(true); setFormMsg(null);
    try {
      const payload = {
        name: name.trim(),
        model_profile: modelProfile.trim() || 'hybrid-local-sweep-verify',
        scope: {
          in_scope: inScope.filter((r) => r.value.trim()).map((r) => ({ kind: r.kind, value: r.value.trim() })),
          exclusions: exclusions.filter((r) => r.value.trim()).map((r) => ({ kind: r.kind, value: r.value.trim() })),
          rules_of_engagement: {
            intensity,
            allowed_vuln_classes: [],
            max_concurrency: 1,
          },
        },
      };
      const created = await apiFetch('/engagements', { method: 'POST', body: payload });
      setFormMsg({ ok: true, text: `Created "${created.name}" (${created.status}). Attest its in-scope targets, then Activate.` });
      setName(''); setInScope([emptyRule()]); setExclusions([]);
      await load();
    } catch (e) {
      setFormMsg({ ok: false, text: `${e.code}: ${e.message}` });
    } finally { setCreating(false); }
  }

  async function activate(id) {
    setError(null);
    try { await apiFetch(`/engagements/${id}/activate`, { method: 'POST' }); await load(); }
    catch (e) { setError(e); }
  }

  async function emergencyStop(id) {
    if (!window.confirm('Emergency stop this engagement? This halts all runs and sets it STOPPED.')) return;
    setError(null);
    try { await apiFetch(`/engagements/${id}/stop`, { method: 'POST' }); await load(); }
    catch (e) { setError(e); }
  }

  async function runScopeCheck(e) {
    e.preventDefault();
    if (!checkEng || !checkTarget.trim()) return;
    setChecking(true); setCheckResult(null);
    try {
      const dec = await apiFetch(`/engagements/${checkEng}/scope/check`, {
        method: 'POST', body: { target: checkTarget.trim() },
      });
      setCheckResult(dec);
    } catch (e) {
      // Even a hard error carries the envelope code/message — surface it as a decision.
      setCheckResult({ allowed: false, code: e.code, reason: e.message, target: checkTarget.trim(), violations: e.detail ? [JSON.stringify(e.detail)] : [] });
    } finally { setChecking(false); }
  }

  return (
    <div>
      <h1>Engagements</h1>
      <p className="muted">A scope-of-engagement is the record the authorization gate enforces. No run touches a target unless it is in an ACTIVE engagement and covered by a valid attested target.</p>

      {error && <div className="error">{error.code}: {error.message}</div>}

      {/* Create */}
      <div className="card">
        <h2>New engagement</h2>
        {formMsg && <div className={formMsg.ok ? 'success' : 'error'}>{formMsg.text}</div>}
        <form onSubmit={submitCreate}>
          <div className="grid2">
            <div className="field">
              <label className="label">Name</label>
              <input className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Q3 pilot — own suite" />
            </div>
            <div className="field">
              <label className="label">Intensity (RoE)</label>
              <select className="select" value={intensity} onChange={(e) => setIntensity(e.target.value)}>
                {RUN_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
          </div>
          <div className="field">
            <label className="label">Model profile</label>
            <input className="input" value={modelProfile} onChange={(e) => setModelProfile(e.target.value)} placeholder="hybrid-local-sweep-verify" />
          </div>
          <RuleList title="In scope" hint="domain glob (*.example.com) / URL prefix / CIDR / repo url" rules={inScope} setRules={setInScope} />
          <RuleList title="Exclusions (never touch — wins over in-scope)" hint="path/host to exclude" rules={exclusions} setRules={setExclusions} />
          <button className="btn" disabled={creating}>{creating ? 'Creating…' : 'Create engagement'}</button>
        </form>
      </div>

      {/* Scope dry-run */}
      <div className="card">
        <h2>Scope check (dry-run)</h2>
        <p className="muted">Preview the gate decision for a concrete target without recording an audit denial.</p>
        <form onSubmit={runScopeCheck} className="row" style={{ alignItems: 'flex-end' }}>
          <div className="field" style={{ marginBottom: 0, minWidth: 220, flex: 1 }}>
            <label className="label">Engagement</label>
            <select className="select" value={checkEng} onChange={(e) => setCheckEng(e.target.value)}>
              <option value="">select…</option>
              {items.map((eg) => <option key={eg.id} value={eg.id}>{eg.name} ({eg.status})</option>)}
            </select>
          </div>
          <div className="field" style={{ marginBottom: 0, minWidth: 260, flex: 2 }}>
            <label className="label">Target</label>
            <input className="input" value={checkTarget} onChange={(e) => setCheckTarget(e.target.value)} placeholder="https://brigade.unicorncommander.ai/login" />
          </div>
          <button className="btn" disabled={checking || !checkEng}>{checking ? 'Checking…' : 'Check'}</button>
        </form>
        {checkResult && (
          <div style={{ marginTop: 12 }}>
            <span className="badge" style={{ background: checkResult.allowed ? '#16a34a' : '#dc2626' }}>
              {checkResult.allowed ? 'ALLOWED' : 'DENIED'}
            </span>
            <span className="mono" style={{ marginLeft: 8 }}>{checkResult.code}</span>
            <div className="muted" style={{ marginTop: 4 }}>{checkResult.reason}</div>
            {checkResult.violations && checkResult.violations.length > 0 && (
              <ul className="muted" style={{ margin: '6px 0 0 18px' }}>
                {checkResult.violations.map((v, i) => <li key={i} className="mono">{v}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* List */}
      <div className="card">
        <h2>All engagements</h2>
        {loading ? (
          <div className="empty">Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty">No engagements yet. Create one above.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th><th>Status</th><th>Profile</th><th>In scope</th><th>Created</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((eg) => {
                  const inScopeRules = (eg.scope && eg.scope.in_scope) || [];
                  return (
                    <tr key={eg.id}>
                      <td>
                        <div>{eg.name}</div>
                        <div className="mono muted" style={{ fontSize: 11 }}>{eg.id}</div>
                        {eg.emergency_stopped && <span className="badge" style={{ background: '#dc2626', marginTop: 4 }}>E-STOP</span>}
                      </td>
                      <td><StatusBadge value={eg.status} /></td>
                      <td className="mono">{eg.model_profile}</td>
                      <td className="mono">
                        {inScopeRules.length === 0 ? <span className="muted">—</span>
                          : inScopeRules.map((r, i) => <div key={i}>{r.kind}: {r.value}</div>)}
                      </td>
                      <td className="muted">{fmt(eg.created_at)}</td>
                      <td>
                        <div className="row">
                          {eg.status === 'DRAFT' && (
                            <button className="btn btn-sm" onClick={() => activate(eg.id)}>Activate</button>
                          )}
                          {eg.status === 'ACTIVE' && (
                            <Link className="btn btn-sm" to={`/runs?engagement=${eg.id}`}>Start run {'▸'}</Link>
                          )}
                          {!eg.emergency_stopped && eg.status !== 'STOPPED' && eg.status !== 'COMPLETED' && (
                            <button className="btn btn-danger btn-sm" onClick={() => emergencyStop(eg.id)}>E-Stop</button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
