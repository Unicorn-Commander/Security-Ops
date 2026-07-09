/* Findings — the triage inbox. Confirmed-and-suspected findings across every
 * engagement, sorted by severity, with a Detail drawer whose signature action is
 * the hand-off to Brigade. "Security-Ops finds; Brigade fixes." */
import React from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource, useMutation } from '../lib/hooks.js';
import {
  PageHead, Severity, SEV_VAR, StatusBadge, Confidence, EmptyState, SkeletonRows,
  ErrorBanner, Banner, Drawer, useToast, CopyButton, Meter, rowActivate,
} from '../components/ui.jsx';
import {
  BugIcon, HandoffIcon, ChevronRightIcon, ExternalIcon, ZapIcon, CircleCheckIcon,
  CircleXIcon, RefreshIcon, FileIcon, ShieldIcon,
} from '../components/icons.jsx';
import { fmtDate, relTime, titleCase, SEVERITY_ORDER, sortBySeverity } from '../lib/format.js';

/* A finding is "open" while it still needs attention. */
const OPEN = (f) => f.status !== 'REMEDIATED' && f.status !== 'FALSE_POSITIVE';
const isUrl = (s) => /^https?:\/\//i.test(String(s || ''));
const HANDOFFABLE = new Set(['NEW', 'VERIFIED']);

/* A finding is "validated" once the verify pass re-checked it and it held. This is
 * the rarest trust signal an autonomous pentester can show — VERIFIED status means
 * the engine re-exploited it, and verified_by names the model that did. */
const isValidated = (f) => f.status === 'VERIFIED' || !!f.verified_by;
const hostOf = (endpoint) => { try { return new URL(endpoint).host; } catch { return null; } };

/* Confidence tone — the "how sure" axis, kept compact for the dense table (the
 * exported <Confidence> pill is used at full size in the drawer). Diamond shape so
 * it never blurs with severity's bars or status's round dot. */
const CONF_TONE = {
  confirmed: { short: 'Confirmed', color: 'var(--ok)' },
  high:      { short: 'High',      color: 'var(--ok)' },
  medium:    { short: 'Medium',    color: 'var(--warn)' },
  low:       { short: 'Tentative', color: 'var(--muted)' },
  uncertain: { short: 'Uncertain', color: 'var(--muted)' },
};
function confTone(value) {
  if (value == null || value === '') return null;
  return CONF_TONE[String(value).toLowerCase()] || { short: titleCase(String(value)), color: 'var(--warn)' };
}

/* Compact confidence mark for a table cell — diamond + one-word label. */
function ConfMark({ value }) {
  const t = confTone(value);
  if (!t) return null;
  return (
    <span
      className="conf conf--compact"
      style={{ color: t.color }}
      title={`${t.short} confidence — how sure the engine is this is real, separate from how severe it is`}
    >
      <span className="conf__mark" aria-hidden="true" />
      <span className="conf__label">{t.short}</span>
    </span>
  );
}

/* Subtle "Validated" treatment — reads as earned, not another loud badge. */
function ValidatedRibbon({ verifiedBy }) {
  return (
    <div className="trust-ribbon">
      <span className="trust-ribbon__icon">
        <ShieldIcon size={15} />
      </span>
      <div>
        <b style={{ color: 'var(--ok)' }}>Validated</b>
        <span style={{ color: 'var(--text-2)' }}> — the engine re-exploited this and it held.</span>
        {verifiedBy && <> Confirmed by <span className="mono" style={{ color: 'var(--text)' }}>{verifiedBy}</span>.</>}
      </div>
    </div>
  );
}

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
  const [closureReason, setClosureReason] = React.useState('');
  // Story vs Evidence — the XBOW split. Story = the human-readable case; Evidence =
  // the reproducible artifacts. Default to the story, reset on finding change.
  const [tab, setTab] = React.useState('story');

  // Refresh from the server so evidence is current when the drawer opens.
  React.useEffect(() => {
    let live = true;
    setF(finding); setNotice(null); setTab('story'); setClosureReason(finding.closure_reason || '');
    api(`/findings/${finding.id}`).then((d) => { if (live) setF(d); }).catch(() => {});
    return () => { live = false; };
  }, [finding]);

  const ev = (f.evidence && typeof f.evidence === 'object') ? f.evidence : {};
  const chain = Array.isArray(ev.chain) ? ev.chain : null;
  const remediation = ev.remediation;
  const extraKeys = Object.keys(ev).filter((k) => !['remediation', 'chain', 'confidence'].includes(k));
  const confidence = ev.confidence;
  const validated = isValidated(f);
  const host = f.endpoint ? hostOf(f.endpoint) : null;
  // A finding is here because it out-ranks the rest; describe why using only fields
  // we actually have — never fabricated EPSS/KEV scores.
  const sevWord = titleCase(f.severity || '');
  const impact = [
    `A ${sevWord.toLowerCase()}-severity finding`,
    f.cwe ? `classified ${f.cwe}` : null,
    host ? `on ${host}` : null,
  ].filter(Boolean).join(' ') + '.';
  // Count of reproducible artifacts, for the Evidence tab.
  const artifactCount = (f.poc ? 1 : 0) + (f.payload ? 1 : 0) + (extraKeys.length ? 1 : 0) + (f.endpoint ? 1 : 0);
  const canHandoff = HANDOFFABLE.has(f.status);
  // HANDED_OFF is terminal here — Brigade owns the finding once handed off.
  const handedOff = f.status === 'HANDED_OFF';
  const closed = f.status === 'FALSE_POSITIVE' || f.status === 'REMEDIATED';
  const terminalReason = f.closure_reason || (handedOff ? 'handed off to Brigade' : '');

  // Operator triage — set the finding's status (Mark verified / false positive /
  // reopen). Mirrors the hand-off path: POST the new status, refresh, toast, refetch.
  async function triage(status, label) {
    setNotice(null);
    try {
      const body = { status };
      if (status === 'FALSE_POSITIVE' || status === 'REMEDIATED') {
        body.closure_reason = closureReason.trim() || null;
      }
      const updated = await run(`/findings/${f.id}/status`, { method: 'POST', body });
      setF(updated);
      toast({ title: label });
      onChanged();
    } catch (err) {
      setNotice({ kind: 'danger', title: 'Update failed', body: err.message });
    }
  }

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
      footer={handedOff ? (
        <div className="row-tight grow" style={{ color: 'var(--text-2)', fontSize: 13 }}>
          <CircleCheckIcon size={16} style={{ color: 'var(--ok)' }} />
          <span>Handed off to Brigade</span>
          {f.handoff_ref && <span className="chip" style={{ marginLeft: 4 }}>{f.handoff_ref}</span>}
        </div>
      ) : (
        <>
          <button className="btn btn--ghost" onClick={onClose}>Close</button>
          {(f.status === 'NEW' || f.status === 'VERIFIED') && (
            <div className="field" style={{ minWidth: 260, marginRight: 'auto' }}>
              <label className="label">Closure reason</label>
              <textarea
                className="textarea"
                value={closureReason}
                onChange={(e) => setClosureReason(e.target.value)}
                placeholder="Why is this being closed?"
                rows={2}
              />
            </div>
          )}
          {closed && (
            <button
              className="btn btn--ghost"
              disabled={busy}
              title="Reopen this finding for triage"
              onClick={() => triage('NEW', 'Reopened')}
            >
              <RefreshIcon size={15} />Reopen
            </button>
          )}
          {(f.status === 'NEW' || f.status === 'VERIFIED') && (
            <button
              className="btn btn--danger"
              disabled={busy}
              title="Dismiss this finding as a false positive"
              onClick={() => triage('FALSE_POSITIVE', 'Marked false positive')}
            >
              <CircleXIcon size={15} />Mark false positive
            </button>
          )}
          {(f.status === 'NEW' || f.status === 'VERIFIED') && (
            <button
              className="btn btn--ghost"
              disabled={busy}
              title="Close this finding as remediated"
              onClick={() => triage('REMEDIATED', 'Marked remediated')}
            >
              <CircleCheckIcon size={15} />Mark remediated
            </button>
          )}
          {f.status === 'NEW' && (
            <button
              className="btn"
              disabled={busy}
              title="Confirm this finding"
              onClick={() => triage('VERIFIED', 'Marked verified')}
            >
              <CircleCheckIcon size={15} />Mark verified
            </button>
          )}
          {canHandoff && (
            <button
              className="btn btn--primary"
              disabled={busy}
              title="Send to Brigade for remediation"
              onClick={handoff}
            >
              <HandoffIcon size={15} />{busy ? 'Handing off…' : 'Hand off to Brigade'}
            </button>
          )}
        </>
      )}
    >
      {/* Two orthogonal axes, always both visible: how BAD + how SURE, plus status. */}
      <div className="row-tight" style={{ gap: 'var(--s-2)', flexWrap: 'wrap' }}>
        <Severity value={f.severity} />
        <Confidence value={confidence} />
        <StatusBadge value={f.status} />
        {f.handoff_ref && <span className="chip"><HandoffIcon size={12} />{f.handoff_ref}</span>}
      </div>

      {/* The rarest trust signal an autonomous engine can show — kept tasteful. */}
      {validated && <ValidatedRibbon verifiedBy={f.verified_by} />}

      {(closed || handedOff) && (
        <div className="banner banner--ok" style={{ alignItems: 'flex-start' }}>
          <CircleCheckIcon />
          <div className="grow">
            <div><b>Closed</b>{terminalReason ? <> — {terminalReason}</> : null}</div>
            <div className="muted" style={{ marginTop: 4 }}>
              {f.closed_by ? <span className="mono">{f.closed_by}</span> : 'Unknown actor'}
              {f.closed_at ? <> · {fmtDate(f.closed_at)} · {relTime(f.closed_at)}</> : null}
            </div>
          </div>
        </div>
      )}

      {notice && (
        <Banner kind={notice.kind}>
          <div><b>{notice.title}</b>{notice.body ? <> — {notice.body}</> : null}</div>
        </Banner>
      )}

      {/* Story / Evidence toggle — the elegant explanation must never substitute for
          the reproducible artifact, so keep the two zones visually distinct. */}
      <div className="segmented" role="tablist" aria-label="Finding detail view">
        <button role="tab" aria-selected={tab === 'story'} className={tab === 'story' ? 'is-active' : ''} onClick={() => setTab('story')}>
          <span className="row-tight" style={{ gap: 6 }}><BugIcon size={13} />Story</span>
        </button>
        <button role="tab" aria-selected={tab === 'evidence'} className={tab === 'evidence' ? 'is-active' : ''} onClick={() => setTab('evidence')}>
          <span className="row-tight" style={{ gap: 6 }}>
            <FileIcon size={13} />Evidence
            {artifactCount > 0 && <span className="chip chip--mini tnum">{artifactCount}</span>}
          </span>
        </button>
      </div>

      {tab === 'story' ? (
        <div role="tabpanel" aria-label="Story" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-5)' }}>
          {/* The case: why this finding is here, in plain language. */}
          <div>
            <div className="label" style={{ marginBottom: 8 }}>The case</div>
            <p className="text-2" style={{ lineHeight: 1.6, margin: 0 }}>{impact}</p>
            <div className="row-tight" style={{ gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
              {f.cwe && <span className="chip">{f.cwe}</span>}
              {host && <span className="chip" style={{ fontFamily: 'var(--mono)' }}>{host}</span>}
            </div>
          </div>

          {remediation ? (
            <div>
              <div className="label" style={{ marginBottom: 8 }}>Remediation</div>
              <Banner kind="info"><div style={{ whiteSpace: 'pre-wrap' }}>{typeof remediation === 'string' ? remediation : JSON.stringify(remediation, null, 2)}</div></Banner>
            </div>
          ) : null}

          {chain && chain.length > 0 ? (
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
          ) : null}

          {!remediation && !(chain && chain.length) && (
            <p className="muted" style={{ fontSize: 13, margin: 0 }}>No exploit chain or remediation narrative recorded yet — see Evidence for the raw artifacts.</p>
          )}
        </div>
      ) : (
        <div role="tabpanel" aria-label="Evidence" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-5)' }}>
          {/* Reproducible artifacts + provenance — the proof, kept apart from the story. */}
          <dl className="dl">
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
            <dt>CWE</dt>
            <dd>{f.cwe ? <span className="chip">{f.cwe}</span> : <span className="muted">—</span>}</dd>
            <dt>Confidence</dt>
            <dd>{confidence != null && confidence !== '' ? <Confidence value={confidence} /> : <span className="muted">—</span>}</dd>
            <dt>Verified by</dt>
            <dd>{f.verified_by ? <span className="row-tight" style={{ gap: 6 }}><CircleCheckIcon size={14} style={{ color: 'var(--ok)' }} /><span className="mono" style={{ fontSize: 12 }}>{f.verified_by}</span></span> : <span className="muted">—</span>}</dd>
            <dt>Found</dt>
            <dd>{fmtDate(f.created_at)} · <span className="muted">{relTime(f.created_at)}</span></dd>
            <dt>Engagement</dt>
            <dd className="mono muted" style={{ fontSize: 12 }}>{f.engagement_id || '—'}</dd>
            <dt>Run</dt>
            <dd style={{ fontSize: 12 }}>{f.run_id ? <Link className="mono" to={`/runs/${f.run_id}`} style={{ color: 'var(--accent-strong)' }}>{f.run_id}</Link> : <span className="mono muted">—</span>}</dd>
          </dl>

          <CodeSection label="Proof of concept" text={f.poc} maxHeight={260} />
          <CodeSection label="Payload" text={f.payload} />

          {(closed || handedOff) && (
            <div>
              <div className="label" style={{ marginBottom: 8 }}>Closure</div>
              <div className="card" style={{ padding: 'var(--s-4)', borderColor: 'var(--border-strong)' }}>
                <div className="row between" style={{ alignItems: 'flex-start', gap: 'var(--s-4)' }}>
                  <div>
                    <div style={{ fontWeight: 560 }}>{terminalReason || 'Closed'}</div>
                    <div className="muted" style={{ marginTop: 4 }}>
                      {f.closed_by ? <span className="mono">{f.closed_by}</span> : 'Unknown actor'}
                      {f.closed_at ? <> · {fmtDate(f.closed_at)} · {relTime(f.closed_at)}</> : null}
                    </div>
                  </div>
                  <StatusBadge value={f.status} />
                </div>
              </div>
            </div>
          )}

          {extraKeys.length > 0 && (
            <CodeSection
              label="Raw evidence"
              text={JSON.stringify(extraKeys.reduce((o, k) => { o[k] = ev[k]; return o; }, {}), null, 2)}
            />
          )}

          {!f.poc && !f.payload && extraKeys.length === 0 && (
            <p className="muted" style={{ fontSize: 13, margin: 0 }}>No proof-of-concept, payload, or raw evidence attached to this finding.</p>
          )}
        </div>
      )}
    </Drawer>
  );
}

export default function Findings() {
  // Honor deep-links from the assistant / console (e.g. `/findings?status=NEW`,
  // `?severity=CRITICAL`) so a suggested "review open findings" chip lands
  // pre-filtered instead of on the full inbox.
  const [params] = useSearchParams();
  const [severity, setSeverity] = React.useState(() => (params.get('severity') || 'ALL').toUpperCase());
  const [status, setStatus] = React.useState(() => (params.get('status') || 'ALL').toUpperCase());
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
    <div className="page" data-section="findings">
      <PageHead
        title="Findings"
        eyebrow="Vulnerabilities"
        icon={<BugIcon />}
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
          <span className="muted" style={{ fontSize: 12 }}>{loading ? '—' : `Highest severity first · ${rows.length} shown`}</span>
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
                    <ConfMark value={f.evidence?.confidence} />
                  </td>
                  <td>
                    {f.verified_by ? (
                      <span className="row-tight" style={{ gap: 6 }} title={`Re-checked and confirmed by ${f.verified_by}`}>
                        <CircleCheckIcon size={13} style={{ color: 'var(--ok)', flex: 'none' }} />
                        <span className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>{f.verified_by}</span>
                      </span>
                    ) : <span className="muted">—</span>}
                  </td>
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
