/* Findings — the triage inbox. Confirmed-and-suspected findings across every
 * engagement, sorted by severity, with a Detail drawer whose signature action is
 * the hand-off to Brigade. "Security-Ops finds; Brigade fixes." */
import React from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource, useMutation } from '../lib/hooks.js';
import {
  PageHead, Severity, SEV_VAR, StatusBadge, EmptyState, SkeletonRows,
  ErrorBanner, Banner, Drawer, useToast, CopyButton, Meter, rowActivate,
} from '../components/ui.jsx';
import {
  BugIcon, HandoffIcon, ChevronRightIcon, ExternalIcon, ZapIcon, CircleCheckIcon,
} from '../components/icons.jsx';
import { fmtDate, relTime, titleCase, SEVERITY_ORDER, sortBySeverity } from '../lib/format.js';

/* A finding is "open" while it still needs attention. */
const OPEN = (f) => f.status !== 'REMEDIATED' && f.status !== 'FALSE_POSITIVE';
const isUrl = (s) => /^https?:\/\//i.test(String(s || ''));
const HANDOFFABLE = new Set(['NEW', 'VERIFIED']);

const STATUS_FILTERS = [
  { value: 'ALL', label: 'All' },
  { value: 'NEW', label: 'New' },
  { value: 'VERIFIED', label: 'Verified' },
  { value: 'HANDED_OFF', label: 'Handed off' },
  { value: 'REMEDIATED', label: 'Remediated' },
  { value: 'FALSE_POSITIVE', label: 'False positive' },
];

/* ---- Compact code section with copy affordance ---- */
function CodeSection({ label, text, maxHeight = 220 }) {
  if (!text) return null;
  const body = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
  return (
    <div>
      <div className="label" style={{ marginBottom: 8 }}>{label}</div>
      <div className="codebox">
        <div className="code" style={{ maxHeight, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{body}</div>
        <div className="copy"><CopyButton text={body} /></div>
      </div>
    </div>
  );
}

/* ---- Detail drawer: the useful, satisfying triage surface ---- */
function DetailDrawer({ finding, onClose, onChanged }) {
  const toast = useToast();
  const { run, busy } = useMutation();
  const [f, setF] = React.useState(finding);
  const [notice, setNotice] = React.useState(null);

  // Refresh from the server so evidence is current when the drawer opens.
  React.useEffect(() => {
    let live = true;
    setF(finding); setNotice(null);
    api(`/findings/${finding.id}`).then((d) => { if (live) setF(d); }).catch(() => {});
    return () => { live = false; };
  }, [finding]);

  const ev = (f.evidence && typeof f.evidence === 'object') ? f.evidence : {};
  const chain = Array.isArray(ev.chain) ? ev.chain : null;
  const remediation = ev.remediation;
  const extraKeys = Object.keys(ev).filter((k) => !['remediation', 'chain', 'confidence'].includes(k));
  const canHandoff = HANDOFFABLE.has(f.status);
  const settled = f.status === 'HANDED_OFF' || f.status === 'REMEDIATED';

  async function handoff() {
    setNotice(null);
    try {
      const updated = await run(`/findings/${f.id}/handoff`, { method: 'POST' });
      setF(updated);
      toast({ title: 'Handed off to Brigade', detail: updated.handoff_ref ? `Ref ${updated.handoff_ref}` : 'Remediation queued.' });
      onChanged();
    } catch (err) {
      if (err.status === 501) {
        setNotice({ kind: 'info', title: 'Brigade intake not configured', body: "This deployment isn't wired to a Brigade remediation endpoint yet. Confirm the finding here — it can be handed off once Brigade intake is connected." });
      } else if (err.status === 409) {
        setNotice({ kind: 'ok', title: 'Already handed off', body: err.message });
      } else {
        setNotice({ kind: 'danger', title: err.status === 502 ? 'Brigade rejected the hand-off' : err.status === 422 ? "Finding isn't eligible" : 'Hand-off failed', body: err.message });
      }
    }
  }

  return (
    <Drawer
      title={f.title}
      subtitle={f.id}
      onClose={onClose}
      footer={settled ? (
        <div className="row-tight grow" style={{ color: 'var(--text-2)', fontSize: 13 }}>
          <CircleCheckIcon size={16} style={{ color: 'var(--ok)' }} />
          <span>{f.status === 'REMEDIATED' ? 'Remediated' : 'Handed off to Brigade'}</span>
          {f.handoff_ref && <span className="chip" style={{ marginLeft: 4 }}>{f.handoff_ref}</span>}
        </div>
      ) : (
        <>
          <button className="btn btn--ghost" onClick={onClose}>Close</button>
          <button
            className="btn btn--primary"
            disabled={!canHandoff || busy}
            title={canHandoff ? 'Send to Brigade for remediation' : 'Only new or verified findings can be handed off'}
            onClick={handoff}
          >
            <HandoffIcon size={15} />{busy ? 'Handing off…' : 'Hand off to Brigade'}
          </button>
        </>
      )}
    >
      <div className="row-tight" style={{ gap: 'var(--s-2)', flexWrap: 'wrap' }}>
        <Severity value={f.severity} />
        <StatusBadge value={f.status} />
        {f.handoff_ref && <span className="chip"><HandoffIcon size={12} />{f.handoff_ref}</span>}
      </div>

      {notice && (
        <Banner kind={notice.kind}>
          <div><b>{notice.title}</b>{notice.body ? <> — {notice.body}</> : null}</div>
        </Banner>
      )}

      <dl className="dl">
        <dt>CWE</dt>
        <dd>{f.cwe ? <span className="chip">{f.cwe}</span> : <span className="muted">—</span>}</dd>
        <dt>Endpoint</dt>
        <dd>
          {f.endpoint ? (
            <span className="row-tight" style={{ gap: 6, flexWrap: 'wrap' }}>
              <span className="mono" style={{ fontSize: 12.5, wordBreak: 'break-all' }}>{f.endpoint}</span>
              <CopyButton text={f.endpoint} />
              {isUrl(f.endpoint) && (
                <a className="iconbtn" href={f.endpoint} target="_blank" rel="noreferrer noopener" title="Open"><ExternalIcon size={15} /></a>
              )}
            </span>
          ) : <span className="muted">—</span>}
        </dd>
        {ev.confidence != null && (<><dt>Confidence</dt><dd>{titleCase(String(ev.confidence))}</dd></>)}
        <dt>Verified by</dt>
        <dd className="muted">{f.verified_by || '—'}</dd>
        <dt>Found</dt>
        <dd>{fmtDate(f.created_at)} · <span className="muted">{relTime(f.created_at)}</span></dd>
        <dt>Engagement</dt>
        <dd className="mono muted" style={{ fontSize: 12 }}>{f.engagement_id || '—'}</dd>
        <dt>Run</dt>
        <dd style={{ fontSize: 12 }}>{f.run_id ? <Link className="mono" to={`/runs/${f.run_id}`} style={{ color: 'var(--accent-strong)' }}>{f.run_id}</Link> : <span className="mono muted">—</span>}</dd>
      </dl>

      {remediation && (
        <div>
          <div className="label" style={{ marginBottom: 8 }}>Remediation</div>
          <Banner kind="info"><div style={{ whiteSpace: 'pre-wrap' }}>{typeof remediation === 'string' ? remediation : JSON.stringify(remediation, null, 2)}</div></Banner>
        </div>
      )}

      {chain && chain.length > 0 && (
        <div>
          <div className="label" style={{ marginBottom: 12 }}><span className="row-tight"><ZapIcon size={13} style={{ color: 'var(--accent-strong)' }} />Exploit chain</span></div>
          <ol className="chain" style={{ listStyle: 'none', margin: 0 }}>
            {chain.map((step, i) => (
              <li key={i} className="chain__step">
                <span className="chain__num">{i + 1}</span>
                <div className="chain__label" style={{ wordBreak: 'break-word' }}>{typeof step === 'string' ? step : JSON.stringify(step)}</div>
              </li>
            ))}
          </ol>
        </div>
      )}

      <CodeSection label="Proof of concept" text={f.poc} maxHeight={260} />
      <CodeSection label="Payload" text={f.payload} />

      {extraKeys.length > 0 && (
        <CodeSection
          label="Evidence"
          text={JSON.stringify(extraKeys.reduce((o, k) => { o[k] = ev[k]; return o; }, {}), null, 2)}
        />
      )}
    </Drawer>
  );
}

export default function Findings() {
  const [severity, setSeverity] = React.useState('ALL');
  const [status, setStatus] = React.useState('ALL');
  const [selected, setSelected] = React.useState(null);

  // Table respects filters.
  const query = React.useMemo(() => {
    const p = new URLSearchParams();
    if (severity !== 'ALL') p.set('severity', severity);
    if (status !== 'ALL') p.set('status', status);
    p.set('limit', '200');
    return p.toString();
  }, [severity, status]);
  const { data, loading, error, reload } = useResource(() => api(`/findings?${query}`), [query]);

  // Summary strip always reflects the whole inbox, regardless of filters.
  const { data: all, reload: reloadAll } = useResource(() => api('/findings?limit=200'), []);

  const rows = React.useMemo(() => [...(data?.items || [])].sort(sortBySeverity), [data]);
  const allItems = all?.items || [];
  const bySev = React.useMemo(() => {
    const m = {}; for (const s of SEVERITY_ORDER) m[s] = 0;
    for (const f of allItems) if (m[f.severity] != null) m[f.severity] += 1;
    return m;
  }, [allItems]);
  const openCount = allItems.filter(OPEN).length;
  const criticalOpen = allItems.filter((f) => f.severity === 'CRITICAL' && OPEN(f)).length;
  const handedCount = allItems.filter((f) => f.status === 'HANDED_OFF').length;
  const sevSegments = SEVERITY_ORDER.map((s) => ({ label: titleCase(s), value: bySev[s], color: SEV_VAR[s] }));
  const filtered = severity !== 'ALL' || status !== 'ALL';

  const refreshAll = () => { reload(); reloadAll(); };

  return (
    <div className="page">
      <PageHead
        title="Findings"
        subtitle="The confirmed-and-suspected findings across every engagement. Triage them here, then hand the confirmed ones to Brigade for remediation — Security-Ops finds, Brigade fixes."
      />

      <ErrorBanner error={error} />

      {/* Summary strip — one tight row: counts + a labelled severity distribution */}
      <div className="card" style={{ marginBottom: 'var(--s-6)' }}>
        <div className="card__body" style={{ display: 'flex', gap: 'var(--s-7)', alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="row" style={{ gap: 'var(--s-7)', flex: 'none' }}>
            <div>
              <div className="tile__label"><BugIcon />Open</div>
              <div className="tnum" style={{ fontSize: 28, fontWeight: 680, letterSpacing: '-0.03em', marginTop: 6 }}>{openCount}</div>
            </div>
            <div>
              <div className="tile__label">Critical open</div>
              <div className="tnum" style={{ fontSize: 28, fontWeight: 680, letterSpacing: '-0.03em', marginTop: 6, color: criticalOpen ? 'var(--sev-critical)' : 'var(--text)' }}>{criticalOpen}</div>
            </div>
            <div>
              <div className="tile__label"><HandoffIcon />Handed off</div>
              <div className="tnum" style={{ fontSize: 28, fontWeight: 680, letterSpacing: '-0.03em', marginTop: 6, color: handedCount ? 'var(--ok)' : 'var(--text)' }}>{handedCount}</div>
            </div>
          </div>
          <div className="grow" style={{ minWidth: 280 }}>
            <Meter segments={sevSegments} />
            <div className="row" style={{ gap: 'var(--s-4)', marginTop: 12, rowGap: 8 }}>
              {SEVERITY_ORDER.map((s) => (
                <span key={s} className="row-tight" style={{ gap: 7 }}>
                  <Severity value={s} />
                  <b className="tnum" style={{ fontSize: 13 }}>{bySev[s]}</b>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="row between" style={{ marginBottom: 'var(--s-4)', rowGap: 'var(--s-3)' }}>
        <div className="row" style={{ gap: 'var(--s-3)' }}>
          <div className="pillbar">
            <button className={severity === 'ALL' ? 'is-active' : ''} onClick={() => setSeverity('ALL')}>All</button>
            {SEVERITY_ORDER.map((s) => (
              <button key={s} className={severity === s ? 'is-active' : ''} onClick={() => setSeverity(s)}>{titleCase(s)}</button>
            ))}
          </div>
        </div>
        <div className="pillbar">
          {STATUS_FILTERS.map((s) => (
            <button key={s.value} className={status === s.value ? 'is-active' : ''} onClick={() => setStatus(s.value)}>{s.label}</button>
          ))}
        </div>
      </div>

      {/* Findings table */}
      <div className="card">
        <div className="card__head">
          <BugIcon size={16} style={{ color: 'var(--muted)' }} />
          <h2>Findings</h2>
          <div className="spacer" />
          <span className="muted" style={{ fontSize: 12 }}>{loading ? '—' : `${rows.length} shown`}</span>
        </div>
        {loading ? (
          <SkeletonRows rows={6} cols={6} />
        ) : rows.length === 0 ? (
          <div className="card__body">
            <EmptyState icon={<BugIcon />} title={filtered ? 'No findings match these filters' : 'No findings yet'}>
              <p className="muted">{filtered ? 'Clear the severity or status filter to see the rest of the inbox.' : 'Findings land here as runs complete. Confirmed ones can be handed to Brigade to fix.'}</p>
            </EmptyState>
          </div>
        ) : (
          <div className="tablewrap"><table className="tbl tbl--rows">
            <thead>
              <tr>
                <th style={{ width: 108 }}>Severity</th>
                <th>Finding</th>
                <th>CWE</th>
                <th>Status</th>
                <th>Verified by</th>
                <th>Found</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} {...rowActivate(() => setSelected(f), `Open finding ${f.title}`)}>
                  <td><Severity value={f.severity} /></td>
                  <td>
                    <div style={{ fontWeight: 560 }}>{f.title}</div>
                    {f.endpoint && <div className="muted mono" style={{ fontSize: 11, marginTop: 2 }}>{f.endpoint}</div>}
                  </td>
                  <td>{f.cwe ? <span className="chip">{f.cwe}</span> : <span className="muted">—</span>}</td>
                  <td>
                    <div className="row-tight" style={{ gap: 6 }}>
                      <StatusBadge value={f.status} />
                      {f.status === 'HANDED_OFF' && f.handoff_ref && <span className="chip">{f.handoff_ref}</span>}
                    </div>
                  </td>
                  <td className="muted">{f.verified_by || '—'}</td>
                  <td className="muted nowrap">{relTime(f.created_at)}</td>
                  <td className="col-actions"><ChevronRightIcon size={16} style={{ color: 'var(--faint)' }} /></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>

      {selected && <DetailDrawer finding={selected} onClose={() => setSelected(null)} onChanged={refreshAll} />}
    </div>
  );
}
