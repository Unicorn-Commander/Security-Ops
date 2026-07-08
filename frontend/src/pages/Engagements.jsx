/* Engagements — the scope-of-engagement records the authorization gate enforces.
 * Live scope-check (gate preview), create drawer with a scope-rule builder,
 * activate / emergency-stop, and branded report export. */
import React from 'react';
import { api } from '../lib/api.js';
import { useResource, useMutation } from '../lib/hooks.js';
import { PageHead, StatusBadge, EmptyState, SkeletonRows, ErrorBanner, Drawer, useToast, useConfirm, CopyButton, rowActivate } from '../components/ui.jsx';
import { ShieldIcon, PlusIcon, PlayIcon, StopIcon, CrosshairIcon, CircleCheckIcon, CircleXIcon, FileIcon, CheckIcon, XIcon, ChevronRightIcon, DownloadIcon } from '../components/icons.jsx';
import { fmtDate, relTime, titleCase } from '../lib/format.js';
import { Link, useSearchParams } from 'react-router-dom';

const KINDS = ['DOMAIN', 'URL', 'IP_RANGE', 'REPO'];
const PROFILES = ['hybrid-local-sweep-verify', 'local-sweep', 'local-verify', 'frontier-verify'];
const INTENSITY = ['QUICK', 'STANDARD', 'DEEP'];
const rule = () => ({ kind: 'DOMAIN', value: '' });

function RuleBuilder({ title, hint, rules, setRules }) {
  const patch = (i, p) => setRules(rules.map((r, j) => (j === i ? { ...r, ...p } : r)));
  return (
    <div className="field">
      <label className="label">{title}</label>
      {rules.map((r, i) => (
        <div className="row" key={i} style={{ marginBottom: 6, flexWrap: 'nowrap' }}>
          <select className="select" style={{ width: 118, flex: 'none' }} value={r.kind} onChange={(e) => patch(i, { kind: e.target.value })}>
            {KINDS.map((k) => <option key={k}>{k}</option>)}
          </select>
          <input className="input mono grow" value={r.value} placeholder={hint} onChange={(e) => patch(i, { value: e.target.value })} />
          <button type="button" className="iconbtn" aria-label="Remove scope rule" onClick={() => setRules(rules.filter((_, j) => j !== i))}><XIcon size={15} /></button>
        </div>
      ))}
      <button type="button" className="btn btn--sm btn--ghost" onClick={() => setRules([...rules, rule()])} style={{ marginTop: 4 }}><PlusIcon size={13} />Add rule</button>
    </div>
  );
}

function ScopeCheck({ engagements }) {
  const [engId, setEngId] = React.useState('');
  const [target, setTarget] = React.useState('');
  const [result, setResult] = React.useState(null);
  const { run, busy } = useMutation();

  React.useEffect(() => { if (!engId && engagements.length) setEngId(engagements.find((e) => e.status === 'ACTIVE')?.id || engagements[0].id); }, [engagements, engId]);

  async function check(e) {
    e.preventDefault();
    if (!engId || !target.trim()) return;
    try { setResult(await run(`/engagements/${engId}/scope/check`, { method: 'POST', body: { target: target.trim() } })); }
    catch (err) { setResult({ allowed: false, code: err.code, reason: err.message, target: target.trim(), violations: err.detail ? [JSON.stringify(err.detail)] : [] }); }
  }

  return (
    <div className="card" style={{ marginBottom: 'var(--s-6)' }}>
      <div className="card__head"><CrosshairIcon size={16} style={{ color: 'var(--accent-strong)' }} /><h2>Gate preview</h2><span className="muted" style={{ fontSize: 12 }}>dry-run the authorization decision — no audit, no run</span></div>
      <div className="card__body">
        <form onSubmit={check} className="row" style={{ alignItems: 'flex-end', gap: 'var(--s-3)' }}>
          <div className="field grow" style={{ minWidth: 200, maxWidth: 260 }}>
            <label className="label">Engagement</label>
            <select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
              {engagements.map((e) => <option key={e.id} value={e.id}>{e.name} · {e.status}</option>)}
            </select>
          </div>
          <div className="field grow" style={{ minWidth: 260 }}>
            <label className="label">Target</label>
            <input className="input mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://brigade.unicorncommander.ai/login" />
          </div>
          <button className="btn btn--primary" disabled={busy || !engId}><CrosshairIcon size={15} />{busy ? 'Checking…' : 'Check'}</button>
        </form>
        {result && (
          <div className={`verdict ${result.allowed ? 'verdict--allow' : 'verdict--deny'}`} style={{ marginTop: 'var(--s-4)' }}>
            <div className="verdict__head">
              <div className="verdict__ic">{result.allowed ? <CircleCheckIcon size={18} /> : <CircleXIcon size={18} />}</div>
              <div className="verdict__title">{result.allowed ? 'Allowed' : 'Denied'}</div>
              <span className="chip" style={{ marginLeft: 'auto' }}>{result.code}</span>
            </div>
            <p style={{ marginTop: 8, color: 'var(--text-2)' }}>{result.reason}</p>
            {result.violations?.length > 0 && (
              <div className="row" style={{ gap: 6, marginTop: 8 }}>
                {result.violations.map((v, i) => <span key={i} className="chip" style={{ color: 'var(--danger-strong)' }}>{v}</span>)}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function CreateDrawer({ onClose, onCreated }) {
  const toast = useToast();
  const [name, setName] = React.useState('');
  const [profile, setProfile] = React.useState(PROFILES[0]);
  const [intensity, setIntensity] = React.useState('STANDARD');
  const [inScope, setInScope] = React.useState([rule()]);
  const [excl, setExcl] = React.useState([]);
  const { run, busy, error } = useMutation();

  async function submit(e) {
    e.preventDefault();
    const body = {
      name: name.trim(), model_profile: profile,
      scope: {
        in_scope: inScope.filter((r) => r.value.trim()).map((r) => ({ kind: r.kind, value: r.value.trim() })),
        exclusions: excl.filter((r) => r.value.trim()).map((r) => ({ kind: r.kind, value: r.value.trim() })),
        rules_of_engagement: { intensity, allowed_vuln_classes: [], max_concurrency: 1 },
      },
    };
    try {
      const created = await run('/engagements', { method: 'POST', body });
      toast({ title: `Engagement "${created.name}" created`, detail: 'Attest its targets, then activate.' });
      onCreated();
    } catch { /* surfaced inline */ }
  }

  return (
    <Drawer title="New engagement" subtitle="Draft a scope the gate will enforce" onClose={onClose}
      footer={<><button className="btn btn--ghost" onClick={onClose}>Cancel</button><button className="btn btn--primary" form="eng-form" disabled={busy || !name.trim()}>{busy ? 'Creating…' : 'Create engagement'}</button></>}>
      <ErrorBanner error={error} />
      <form id="eng-form" onSubmit={submit} className="stack">
        <div className="field">
          <label className="label">Name</label>
          <input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="ACME Corp — Q3 external" />
        </div>
        <div className="grid grid-2">
          <div className="field">
            <label className="label">Model profile</label>
            <select className="select" value={profile} onChange={(e) => setProfile(e.target.value)}>{PROFILES.map((p) => <option key={p}>{p}</option>)}</select>
          </div>
          <div className="field">
            <label className="label">Intensity</label>
            <div className="segmented">{INTENSITY.map((m) => <button type="button" key={m} className={intensity === m ? 'is-active' : ''} onClick={() => setIntensity(m)}>{titleCase(m)}</button>)}</div>
          </div>
        </div>
        <hr className="divider" />
        <RuleBuilder title="In scope" hint="*.example.com / https://app… / 10.0.0.0/24 / repo url" rules={inScope} setRules={setInScope} />
        <RuleBuilder title="Exclusions — never touch (wins over in-scope)" hint="path or host to exclude" rules={excl} setRules={setExcl} />
      </form>
    </Drawer>
  );
}

function DetailDrawer({ engagement, onClose, onChanged }) {
  const toast = useToast();
  const confirm = useConfirm();
  const { run, busy } = useMutation();
  const [report, setReport] = React.useState(null);
  const [genBusy, setGenBusy] = React.useState(false);
  const e = engagement;
  const inScopeN = (e.scope?.in_scope || []).length;
  const exclN = (e.scope?.exclusions || []).length;

  async function act(path, msg) {
    try { await run(path, { method: 'POST' }); toast({ title: msg }); onChanged(); onClose(); }
    catch (err) { toast({ kind: 'danger', title: err.message }); }
  }
  async function activate() {
    const ok = await confirm({
      title: 'Activate engagement?',
      body: `Activating authorizes real scans against ${inScopeN} in-scope rule${inScopeN === 1 ? '' : 's'}${exclN ? ` (with ${exclN} exclusion${exclN === 1 ? '' : 's'})` : ''}. Only targets covered by a valid attestation will pass the gate.`,
      confirmLabel: 'Activate',
    });
    if (ok) act(`/engagements/${e.id}/activate`, 'Engagement activated');
  }
  async function estop() {
    const ok = await confirm({
      title: 'Emergency-stop this engagement?',
      body: `This revokes authorization for “${e.name}” and signals every running scan under it to halt immediately. The engagement is set to STOPPED and cannot run again until re-activated.`,
      confirmLabel: 'Emergency stop',
      danger: true,
    });
    if (ok) act(`/engagements/${e.id}/stop`, 'Emergency stop engaged');
  }
  async function loadReport() {
    setGenBusy(true);
    try { const md = await api(`/engagements/${e.id}/report?format=json`); setReport(typeof md === 'string' ? md : md.report_markdown); }
    catch (err) { toast({ kind: 'danger', title: err.message }); }
    finally { setGenBusy(false); }
  }
  function downloadReport() {
    if (!report) return;
    const slug = (e.name || 'engagement').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'engagement';
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `security-ops-report-${slug}.md`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <Drawer title={e.name} subtitle={e.id} onClose={onClose}
      footer={<>
        {e.status === 'DRAFT' && <button className="btn btn--primary" disabled={busy} onClick={activate}><CheckIcon size={15} />Activate</button>}
        {e.status === 'ACTIVE' && <Link className="btn btn--primary" to={`/runs?engagement=${e.id}`}><PlayIcon size={13} />Start run</Link>}
        {!['STOPPED', 'COMPLETED', 'EXPIRED'].includes(e.status) && <button className="btn btn--danger" disabled={busy} onClick={estop}><StopIcon size={13} />E-Stop</button>}
      </>}>
      <div className="row-tight"><StatusBadge value={e.status} />{e.emergency_stopped && <span className="badge badge--danger"><span className="dot" />E-Stop</span>}</div>
      <dl className="dl">
        <dt>Profile</dt><dd className="mono">{e.model_profile}</dd>
        <dt>Intensity</dt><dd>{titleCase(e.rules_of_engagement?.intensity || 'standard')}</dd>
        <dt>Created</dt><dd>{fmtDate(e.created_at)} · <span className="muted">{e.created_by}</span></dd>
        <dt>Expires</dt><dd>{e.expires_at ? fmtDate(e.expires_at) : 'no expiry'}</dd>
      </dl>
      <div>
        <div className="label" style={{ marginBottom: 8 }}>In scope</div>
        <div className="row" style={{ gap: 6 }}>{(e.scope?.in_scope || []).length === 0 ? <span className="muted">—</span> : e.scope.in_scope.map((r, i) => <span key={i} className="chip">{r.kind}: {r.value}</span>)}</div>
      </div>
      {(e.scope?.exclusions || []).length > 0 && (
        <div>
          <div className="label" style={{ marginBottom: 8 }}>Exclusions</div>
          <div className="row" style={{ gap: 6 }}>{e.scope.exclusions.map((r, i) => <span key={i} className="chip" style={{ color: 'var(--danger-strong)' }}>{r.kind}: {r.value}</span>)}</div>
        </div>
      )}
      <hr className="divider" />
      <div>
        <div className="row between" style={{ marginBottom: 8 }}>
          <div className="label">Engagement report</div>
          <button className="btn btn--sm btn--ghost" onClick={loadReport} disabled={genBusy}><FileIcon size={14} />{genBusy ? 'Generating…' : 'Generate'}</button>
        </div>
        {report ? (
          <div className="codebox">
            <div className="code" style={{ maxHeight: 260, whiteSpace: 'pre-wrap' }}>{report}</div>
            <div className="copy row-tight" style={{ gap: 6 }}>
              <button className="iconbtn" onClick={downloadReport} title="Download as .md" type="button" aria-label="Download report as Markdown">
                <DownloadIcon size={15} /><span style={{ marginLeft: 6, fontSize: 12 }}>Download .md</span>
              </button>
              <CopyButton text={report} />
            </div>
          </div>
        ) : <div className="hint">Wraps the frontier-verified Strix report, branded for the client.</div>}
      </div>
    </Drawer>
  );
}

export default function Engagements() {
  const { data, loading, error, reload } = useResource(() => api('/engagements?limit=100'), []);
  const [params, setParams] = useSearchParams();
  const [creating, setCreating] = React.useState(() => params.has('new'));
  const [selected, setSelected] = React.useState(null);
  const items = data?.items || [];

  // Honor the onboarding deep-link (/engagements?new=1) then drop the param.
  React.useEffect(() => {
    if (params.has('new')) { setCreating(true); params.delete('new'); setParams(params, { replace: true }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="page" data-section="engagements">
      <PageHead title="Engagements" eyebrow="Authorized scope" icon={<ShieldIcon />} subtitle="A scope-of-engagement is the record the authorization gate enforces. No run touches a target unless it sits in an active engagement and is covered by a valid attestation."
        actions={<button className="btn btn--primary" onClick={() => setCreating(true)}><PlusIcon size={15} />New engagement</button>} />

      <ErrorBanner error={error} />
      {items.length > 0 && <ScopeCheck engagements={items} />}

      <div className="card">
        <div className="card__head"><ShieldIcon size={16} style={{ color: 'var(--muted)' }} /><h2>All engagements</h2><div className="spacer" /><span className="muted" style={{ fontSize: 12 }}>{items.length} total</span></div>
        {loading ? <SkeletonRows rows={4} cols={5} /> : items.length === 0 ? (
          <div className="card__body"><EmptyState icon={<ShieldIcon />} title="No engagements yet"><p className="muted">Create one, attest its targets, then activate to authorize scans.</p></EmptyState></div>
        ) : (
          <div className="tablewrap"><table className="tbl tbl--rows">
            <thead><tr><th>Name</th><th>Status</th><th>Scope</th><th>Profile</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} {...rowActivate(() => setSelected(e), `Open engagement ${e.name}`)}>
                  <td><div style={{ fontWeight: 560 }}>{e.name}</div><div className="muted" style={{ fontSize: 11 }}>{relTime(e.created_at)}</div></td>
                  <td><StatusBadge value={e.status} /></td>
                  <td><span className="muted">{(e.scope?.in_scope || []).length} in-scope{(e.scope?.exclusions || []).length ? ` · ${e.scope.exclusions.length} excl` : ''}</span></td>
                  <td className="mono muted" style={{ fontSize: 12 }}>{e.model_profile}</td>
                  <td className="muted">{e.expires_at ? fmtDate(e.expires_at, { time: false }) : '—'}</td>
                  <td className="col-actions"><ChevronRightIcon size={16} style={{ color: 'var(--faint)' }} /></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>

      {creating && <CreateDrawer onClose={() => setCreating(false)} onCreated={() => { setCreating(false); reload(); }} />}
      {selected && <DetailDrawer engagement={selected} onClose={() => setSelected(null)} onChanged={reload} />}
    </div>
  );
}
