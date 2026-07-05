import React from 'react';

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
// OWNED first — it's the self-owned escape hatch used by the pilot (your own suite).
const ATTEST_METHODS = ['OWNED', 'CHECKBOX', 'TYPED_CONFIRMATION', 'DNS_TXT', 'FILE_DROP', 'HTTP_HEADER'];

const ATTEST_COLORS = {
  UNATTESTED: '#64748b', ATTESTED: '#16a34a', EXPIRED: '#d97706', REVOKED: '#dc2626',
};
function AttestBadge({ value }) {
  return <span className="badge" style={{ background: ATTEST_COLORS[value] || '#475569' }}>{value}</span>;
}

export default function Targets() {
  const [items, setItems] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);

  // register form
  const [kind, setKind] = React.useState('DOMAIN');
  const [value, setValue] = React.useState('');
  const [label, setLabel] = React.useState('');
  const [owner, setOwner] = React.useState('');
  const [registering, setRegistering] = React.useState(false);
  const [regMsg, setRegMsg] = React.useState(null);

  // attest panel (opened for a specific target)
  const [attestId, setAttestId] = React.useState(null);
  const [method, setMethod] = React.useState('OWNED');
  const [checkboxAck, setCheckboxAck] = React.useState(false);
  const [typedConfirmation, setTypedConfirmation] = React.useState('');
  const [evidenceText, setEvidenceText] = React.useState('');
  const [expiresAt, setExpiresAt] = React.useState('');
  const [attesting, setAttesting] = React.useState(false);
  const [attestMsg, setAttestMsg] = React.useState(null);

  async function load() {
    setLoading(true); setError(null);
    try {
      const page = await apiFetch('/targets?limit=200&offset=0');
      setItems(page.items || []);
    } catch (e) { setError(e); }
    finally { setLoading(false); }
  }
  React.useEffect(() => { load(); }, []);

  async function submitRegister(e) {
    e.preventDefault();
    setRegistering(true); setRegMsg(null);
    try {
      const created = await apiFetch('/targets', {
        method: 'POST',
        body: {
          kind,
          value: value.trim(),
          label: label.trim() || null,
          owner_principal: owner.trim() || null,
        },
      });
      setRegMsg({ ok: true, text: `Registered ${created.kind} ${created.value} (UNATTESTED — attest it below before it is scannable).` });
      setValue(''); setLabel(''); setOwner('');
      await load();
    } catch (e) {
      setRegMsg({ ok: false, text: `${e.code}: ${e.message}` });
    } finally { setRegistering(false); }
  }

  function openAttest(t) {
    setAttestId(t.id);
    setMethod('OWNED');
    setCheckboxAck(false);
    setTypedConfirmation('');
    setEvidenceText('');
    setExpiresAt('');
    setAttestMsg(null);
  }

  async function submitAttest(e) {
    e.preventDefault();
    setAttestMsg(null);
    let evidence = null;
    if (evidenceText.trim()) {
      try { evidence = JSON.parse(evidenceText); }
      catch { setAttestMsg({ ok: false, text: 'Evidence must be valid JSON (e.g. {"dns_txt":"strix-auth=..."}).' }); return; }
    }
    const body = {
      method,
      checkbox_ack: checkboxAck,
      typed_confirmation: typedConfirmation.trim() || null,
      evidence,
    };
    if (expiresAt) body.expires_at = new Date(expiresAt).toISOString();

    setAttesting(true);
    try {
      await apiFetch(`/targets/${attestId}/attest`, { method: 'POST', body });
      setAttestId(null);
      await load();
    } catch (e) {
      setAttestMsg({ ok: false, text: `${e.code}: ${e.message}` });
    } finally { setAttesting(false); }
  }

  const attestTarget = items.find((t) => t.id === attestId) || null;

  return (
    <div>
      <h1>Authorized targets</h1>
      <p className="muted">The registry the gate consults. A target is only scannable once it passes attestation (valid, unexpired, not revoked). External domains/URLs/IP-ranges need ownership proof; self-owned assets use method OWNED.</p>

      {error && <div className="error">{error.code}: {error.message}</div>}

      {/* Register */}
      <div className="card">
        <h2>Register target</h2>
        {regMsg && <div className={regMsg.ok ? 'success' : 'error'}>{regMsg.text}</div>}
        <form onSubmit={submitRegister}>
          <div className="grid2">
            <div className="field">
              <label className="label">Kind</label>
              <select className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
                {TARGET_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>
            <div className="field">
              <label className="label">Value</label>
              <input className="input" required value={value} onChange={(e) => setValue(e.target.value)} placeholder="brigade.unicorncommander.ai / https://… / 10.0.0.0/24 / repo url" />
            </div>
          </div>
          <div className="grid2">
            <div className="field">
              <label className="label">Label (optional)</label>
              <input className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Own suite — Brigade" />
            </div>
            <div className="field">
              <label className="label">Owner principal (optional)</label>
              <input className="input" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="demo@example.invalid" />
            </div>
          </div>
          <button className="btn" disabled={registering}>{registering ? 'Registering…' : 'Register target'}</button>
        </form>
      </div>

      {/* Attest panel */}
      {attestTarget && (
        <div className="card">
          <h2>Attest — <span className="mono">{attestTarget.kind}: {attestTarget.value}</span></h2>
          <p className="muted">
            Minimum proof: acknowledge + typed confirmation. External DOMAIN/URL/IP_RANGE additionally require
            DNS_TXT / FILE_DROP / HTTP_HEADER evidence. Method OWNED is for assets you own (the pilot).
          </p>
          {attestMsg && <div className={attestMsg.ok ? 'success' : 'error'}>{attestMsg.text}</div>}
          <form onSubmit={submitAttest}>
            <div className="grid2">
              <div className="field">
                <label className="label">Method</label>
                <select className="select" value={method} onChange={(e) => setMethod(e.target.value)}>
                  {ATTEST_METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div className="field">
                <label className="label">Expires at (optional)</label>
                <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
              </div>
            </div>
            <div className="field">
              <label className="row" style={{ gap: 8, cursor: 'pointer' }}>
                <input type="checkbox" style={{ width: 'auto' }} checked={checkboxAck} onChange={(e) => setCheckboxAck(e.target.checked)} />
                <span>I am authorized to test this target (checkbox_ack)</span>
              </label>
            </div>
            <div className="field">
              <label className="label">Typed confirmation</label>
              <input className="input" value={typedConfirmation} onChange={(e) => setTypedConfirmation(e.target.value)} placeholder={`type the target value to confirm: ${attestTarget.value}`} />
            </div>
            <div className="field">
              <label className="label">Evidence (JSON — required for external DNS_TXT / FILE_DROP / HTTP_HEADER)</label>
              <textarea value={evidenceText} onChange={(e) => setEvidenceText(e.target.value)} placeholder='{"dns_txt": "strix-authorization=abc123"}' />
            </div>
            <div className="row">
              <button className="btn" disabled={attesting}>{attesting ? 'Attesting…' : 'Attest target'}</button>
              <button type="button" className="btn btn-ghost" onClick={() => setAttestId(null)}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      {/* List */}
      <div className="card">
        <h2>Registry</h2>
        {loading ? (
          <div className="empty">Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty">No targets registered yet.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Kind</th><th>Value</th><th>Attestation</th><th>Method</th><th>Attested by</th><th>Expires</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((t) => (
                  <tr key={t.id}>
                    <td>{t.kind}</td>
                    <td>
                      <div className="mono">{t.value}</div>
                      {t.label && <div className="muted" style={{ fontSize: 12 }}>{t.label}</div>}
                    </td>
                    <td><AttestBadge value={t.attestation_status} /></td>
                    <td className="mono">{t.attestation_method || '—'}</td>
                    <td className="muted">{t.attested_by || '—'}</td>
                    <td className="muted">{fmt(t.expires_at)}</td>
                    <td>
                      <button className="btn btn-sm" onClick={() => openAttest(t)}>
                        {t.attestation_status === 'ATTESTED' ? 'Re-attest' : 'Attest'}
                      </button>
                    </td>
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
