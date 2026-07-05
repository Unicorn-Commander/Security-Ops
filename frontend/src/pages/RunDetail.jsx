/* RunDetail — one authorized scan, live. Loads the run + its findings together and
 * auto-refreshes (~4s) while the run is PENDING or RUNNING so a live scan feels
 * alive. Stop control, gate/report affordances, and a severity-summarised findings
 * ledger. */
import React from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource, useMutation } from '../lib/hooks.js';
import {
  StatusBadge, Severity, Meter, EmptyState, SkeletonRows, ErrorBanner, Banner, CopyButton, useToast, useConfirm, SEV_VAR,
} from '../components/ui.jsx';
import {
  ChevronLeftIcon, PlayIcon, StopIcon, BugIcon, ActivityIcon, ClockIcon, ShieldIcon, FileIcon, ExternalIcon,
} from '../components/icons.jsx';
import { fmtDate, relTime, fmtMoney, titleCase, SEVERITY_ORDER, sortBySeverity } from '../lib/format.js';

const LIVE = new Set(['PENDING', 'RUNNING']);

function fmtDuration(start, end) {
  if (!start) return '—';
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const ms = e - s;
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const sec = Math.floor(ms / 1000);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const ss = sec % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${ss}s`;
  return `${ss}s`;
}

function Meta({ label, children }) {
  return (
    <div>
      <div className="label" style={{ marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 13, color: 'var(--text)', minWidth: 0, wordBreak: 'break-word' }}>{children}</div>
    </div>
  );
}

export default function RunDetail() {
  const { runId } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const { run: mutate, busy: stopping } = useMutation();

  const { data, loading, error, reload } = useResource(
    () => Promise.all([api(`/runs/${runId}`), api(`/runs/${runId}/findings?limit=200`)])
      .then(([r, f]) => ({ run: r, findings: f?.items || [] })),
    [runId],
    { pollWhile: (d) => LIVE.has(d?.run?.status) },
  );

  const run = data?.run;
  const findings = data?.findings || [];
  const live = run ? LIVE.has(run.status) : false;

  async function stop() {
    const ok = await confirm({
      title: 'Stop this run?',
      body: 'The Strix worker will be signalled to halt immediately. Findings collected so far are preserved; the run is marked stopped and cannot be resumed.',
      confirmLabel: 'Stop run',
      danger: true,
    });
    if (!ok) return;
    try {
      await mutate(`/runs/${runId}/stop`, { method: 'POST' });
      toast({ title: 'Stop signalled', detail: 'The run is winding down.' });
      reload();
    } catch (e) {
      toast({ kind: 'danger', title: e.message });
    }
  }

  // --- Severity roll-up for the findings summary ---
  const counts = SEVERITY_ORDER.reduce((a, s) => ({ ...a, [s]: 0 }), {});
  findings.forEach((f) => { if (counts[f.severity] != null) counts[f.severity] += 1; });
  const segments = SEVERITY_ORDER.map((s) => ({ label: titleCase(s), value: counts[s], color: SEV_VAR[s] }));
  const sorted = [...findings].sort(sortBySeverity);

  return (
    <div className="page">
      <div className="row between" style={{ marginBottom: 'var(--s-5)' }}>
        <div className="row-tight" style={{ minWidth: 0, flexWrap: 'wrap' }}>
          <Link to="/runs" className="btn btn--ghost btn--sm"><ChevronLeftIcon size={15} />Runs</Link>
          <span className="mono muted" style={{ fontSize: 12 }}>{runId}</span>
          <CopyButton text={runId} />
        </div>
        <Link to={run ? `/runs?engagement=${run.engagement_id}` : '/runs'} className="btn btn--sm"><PlayIcon size={12} />New run</Link>
      </div>

      <ErrorBanner error={error} />

      {loading && !run ? (
        <div className="card"><SkeletonRows rows={4} cols={3} /></div>
      ) : !run ? null : (
        <>
          {/* Run header */}
          <div className="card" style={{ marginBottom: 'var(--s-6)' }}>
            <div className="card__body">
              <div className="row between" style={{ marginBottom: 'var(--s-5)', alignItems: 'flex-start' }}>
                <div className="row-tight" style={{ gap: 'var(--s-3)', flexWrap: 'wrap' }}>
                  <StatusBadge value={run.status} />
                  <span className="chip">{titleCase(run.mode)}</span>
                  <span className="mono muted" style={{ fontSize: 12 }}>{run.model_profile}</span>
                  {live && (
                    <span className="statusdot"><i className="live" style={{ background: 'var(--info)' }} />auto-refreshing</span>
                  )}
                </div>
                {LIVE.has(run.status) && (
                  <button className="btn btn--danger" disabled={stopping} onClick={stop}><StopIcon size={13} />{stopping ? 'Stopping…' : 'Stop run'}</button>
                )}
              </div>

              {(run.targets || []).length > 0 && (
                <div style={{ marginBottom: 'var(--s-5)' }}>
                  <div className="label" style={{ marginBottom: 8 }}>Targets · {(run.targets || []).length}</div>
                  <div className="row" style={{ gap: 6 }}>
                    {run.targets.map((t, i) => <span key={i} className="chip">{t}</span>)}
                  </div>
                </div>
              )}

              <div className="grid grid-4" style={{ gap: 'var(--s-5)' }}>
                <Meta label="Engagement"><Link to="/engagements" className="mono" style={{ color: 'var(--accent-strong)', fontSize: 12 }}>{run.engagement_id}</Link></Meta>
                <Meta label="Strix run id"><span className="mono" style={{ fontSize: 12 }}>{run.strix_run_id || '—'}</span></Meta>
                <Meta label="Started">{run.started_at ? <span title={fmtDate(run.started_at)}>{relTime(run.started_at)}</span> : '—'}</Meta>
                <Meta label="Ended">{run.ended_at ? <span title={fmtDate(run.ended_at)}>{relTime(run.ended_at)}</span> : (live ? <span className="muted">in progress</span> : '—')}</Meta>
                <Meta label="Duration"><span className="row-tight"><ClockIcon size={14} style={{ color: 'var(--muted)' }} />{fmtDuration(run.started_at, run.ended_at)}</span></Meta>
                <Meta label="Cost"><span className="tnum">{fmtMoney(run.cost_usd)}</span></Meta>
                <Meta label="Created"><span title={fmtDate(run.created_at)}>{relTime(run.created_at)}</span></Meta>
                <Meta label="Findings"><span className="tnum">{findings.length}</span></Meta>
              </div>

              {run.error && <div style={{ marginTop: 'var(--s-5)' }}><Banner kind="danger"><b>Run error</b> — {run.error}</Banner></div>}

              {run.status === 'PENDING' && (
                <div style={{ marginTop: 'var(--s-5)' }}>
                  <Banner kind="info">
                    <b>Authorized — starting.</b> The gate cleared every target and created this run; the Strix worker is spinning up. Findings will stream in here as they're confirmed.
                  </Banner>
                </div>
              )}

              {run.report_path && (
                <div style={{ marginTop: 'var(--s-5)' }}>
                  <Banner kind="ok">
                    <div className="row between" style={{ width: '100%' }}>
                      <span className="row-tight"><FileIcon size={16} />Report available</span>
                      <span className="row-tight">
                        <span className="mono" style={{ fontSize: 12, color: 'var(--text-2)' }}>{run.report_path}</span>
                        <CopyButton text={run.report_path} />
                      </span>
                    </div>
                  </Banner>
                </div>
              )}
            </div>
          </div>

          {/* Findings */}
          <div className="card">
            <div className="card__head">
              <BugIcon size={16} style={{ color: 'var(--muted)' }} />
              <h2>Findings</h2>
              <div className="spacer" />
              <span className="muted" style={{ fontSize: 12 }}>{findings.length} total</span>
            </div>

            {findings.length > 0 && (
              <div className="card__body" style={{ borderBottom: '1px solid var(--border)' }}>
                <Meter segments={segments} />
                <div className="row" style={{ gap: 'var(--s-4)', marginTop: 12 }}>
                  {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
                    <span key={s} className="row-tight" style={{ fontSize: 12, color: 'var(--text-2)' }}>
                      <span style={{ width: 8, height: 8, borderRadius: 3, background: SEV_VAR[s], flex: 'none' }} />
                      {titleCase(s)} <b className="tnum" style={{ color: 'var(--text)' }}>{counts[s]}</b>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {findings.length === 0 ? (
              <div className="card__body">
                <EmptyState icon={<ActivityIcon />} title="No findings recorded yet">
                  <p className="muted">{live ? 'The scan is live — confirmed findings will appear here as the worker verifies them.' : 'This run produced no recorded findings.'}</p>
                </EmptyState>
              </div>
            ) : (
              <div className="tablewrap"><table className="tbl">
                <thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Endpoint</th><th>Verified by</th><th>Found</th></tr></thead>
                <tbody>
                  {sorted.map((f) => (
                    <tr key={f.id}>
                      <td style={{ width: 104 }}><Severity value={f.severity} /></td>
                      <td>
                        <div style={{ fontWeight: 540 }}>{f.title}</div>
                        {f.cwe && <div className="muted mono" style={{ fontSize: 11 }}>{f.cwe}</div>}
                      </td>
                      <td><StatusBadge value={f.status} /></td>
                      <td className="mono muted nowrap" style={{ fontSize: 12 }}>{f.endpoint || '—'}</td>
                      <td className="muted nowrap">{f.verified_by ? <span className="row-tight"><ShieldIcon size={13} style={{ color: 'var(--accent-strong)' }} />{f.verified_by}</span> : '—'}</td>
                      <td className="muted nowrap" title={fmtDate(f.created_at)}>{relTime(f.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
