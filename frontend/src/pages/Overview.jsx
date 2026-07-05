/* Overview — security posture at a glance. Hero posture line, KPI tiles, findings
 * by severity (heat ramp, always label + color), run status, attestation coverage,
 * recent activity. */
import React from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource } from '../lib/hooks.js';
import { Tile, Bars, Meter, Severity, StatusBadge, SkeletonRows, EmptyState, ErrorBanner, SEV_VAR } from '../components/ui.jsx';
import { ShieldIcon, TargetIcon, PlayIcon, BugIcon, PlusIcon, ArrowRightIcon, LockIcon, ActivityIcon } from '../components/icons.jsx';
import { fmtMoney, relTime, SEVERITY_ORDER, titleCase } from '../lib/format.js';

const RUN_STATUS_COLOR = { COMPLETED: 'var(--ok)', RUNNING: 'var(--info)', PENDING: 'var(--warn)', FAILED: 'var(--danger)', STOPPED: 'var(--danger)', DENIED: 'var(--danger)' };

export default function Overview() {
  const { data: ov, loading, error } = useResource(() => api('/overview'), [], { pollWhile: (d) => d?.runs?.running > 0 });
  const { data: runsPage } = useResource(() => api('/runs?limit=6'), []);
  const { data: findPage } = useResource(() => api('/findings?limit=6'), []);

  const sev = ov?.findings?.by_severity || {};
  const sevData = SEVERITY_ORDER.map((s) => ({ label: titleCase(s), value: sev[s] || 0, color: SEV_VAR[s], swatch: SEV_VAR[s], key: s }));
  const sevSegments = SEVERITY_ORDER.map((s) => ({ label: s, value: sev[s] || 0, color: SEV_VAR[s] }));
  const runStatus = ov?.runs?.by_status || {};
  const runData = Object.keys(runStatus).map((k) => ({ label: titleCase(k), value: runStatus[k], color: RUN_STATUS_COLOR[k] || 'var(--muted)', swatch: RUN_STATUS_COLOR[k] }));
  const attested = ov?.targets?.attested || 0;
  const totalTargets = ov?.targets?.total || 0;
  const coverage = totalTargets ? Math.round((attested / totalTargets) * 100) : 0;
  const critical = sev.CRITICAL || 0;
  const runs = runsPage?.items || [];
  const findings = findPage?.items || [];

  return (
    <div className="page">
      {error && <div style={{ marginBottom: 'var(--s-5)' }}><ErrorBanner error={{ ...error, message: `${error.message} — posture data is unavailable; figures below may be stale or unknown.` }} /></div>}

      {/* Hero posture */}
      <div className="card" style={{ overflow: 'hidden', marginBottom: 'var(--s-6)', boxShadow: 'var(--shadow-lg)' }}>
        <div className="card__body" style={{ display: 'flex', gap: 'var(--s-5)', alignItems: 'center', flexWrap: 'wrap', background: 'var(--aurora-soft)' }}>
          <div className="sidebar__logo" style={{ width: 48, height: 48, borderRadius: 14 }}><LockIcon size={25} strokeWidth={2} /></div>
          <div className="grow" style={{ minWidth: 240 }}>
            <div className="row-tight" style={{ marginBottom: 4 }}>
              <h1 className="display">Security posture</h1>
            </div>
            <p className="muted" style={{ maxWidth: '70ch' }}>
              The authorization gate is <b style={{ color: 'var(--ok)' }}>armed and server-enforced</b> — no scan runs without an active, attested, unexpired scope.
              {ov ? <> {ov.engagements.active} active engagement{ov.engagements.active === 1 ? '' : 's'}, {attested} attested target{attested === 1 ? '' : 's'}, {ov.findings.open} open finding{ov.findings.open === 1 ? '' : 's'}.</> : ''}
            </p>
          </div>
          <div className="row" style={{ flex: 'none' }}>
            <Link to="/engagements" className="btn"><ShieldIcon size={15} />New engagement</Link>
            <Link to="/runs" className="btn btn--primary"><PlayIcon size={13} />Start a run</Link>
          </div>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="grid grid-4" style={{ marginBottom: 'var(--s-6)' }}>
        <Tile accent label="Active engagements" icon={<ShieldIcon />} value={loading || error ? '—' : ov?.engagements?.active ?? 0}
          sub={<Link to="/engagements" className="row-tight" style={{ color: 'var(--accent-strong)' }}>Manage <ArrowRightIcon size={13} /></Link>} />
        <Tile label="Attested targets" icon={<TargetIcon />} value={loading || error ? '—' : attested}
          sub={<span>{coverage}% of {totalTargets} in registry attested</span>} />
        <Tile label="Runs" icon={<PlayIcon />} value={loading || error ? '—' : ov?.runs?.total ?? 0}
          sub={ov?.runs?.running ? <span className="statusdot"><i className="live" style={{ background: 'var(--info)' }} />{ov.runs.running} running now</span> : <span>none running</span>} />
        <Tile label="Open findings" icon={<BugIcon />} value={loading || error ? '—' : ov?.findings?.open ?? 0}
          sub={critical ? <span style={{ color: 'var(--sev-critical)' }}>{critical} critical unresolved</span> : <span>no criticals open</span>} />
      </div>

      {/* Distributions */}
      <div className="grid grid-2" style={{ marginBottom: 'var(--s-6)' }}>
        <div className="card">
          <div className="card__head"><BugIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Findings by severity</h2><div className="spacer" /><Link to="/findings" className="btn btn--sm btn--ghost">Inbox</Link></div>
          <div className="card__body">
            <Meter segments={sevSegments} />
            <div style={{ height: 16 }} />
            <Bars data={sevData} />
          </div>
        </div>
        <div className="card">
          <div className="card__head"><ActivityIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Runs by status</h2><div className="spacer" /><Link to="/runs" className="btn btn--sm btn--ghost">All runs</Link></div>
          <div className="card__body">
            {runData.length === 0 ? <EmptyState icon={<PlayIcon />} title="No runs yet">Start a run from an active engagement.</EmptyState> : <Bars data={runData} />}
          </div>
        </div>
      </div>

      {/* Recent activity */}
      <div className="grid grid-2">
        <div className="card">
          <div className="card__head"><PlayIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Recent runs</h2></div>
          {!runsPage ? <SkeletonRows rows={4} cols={3} /> : runs.length === 0 ? (
            <div className="card__body"><EmptyState icon={<PlayIcon />} title="No runs yet" /></div>
          ) : (
            <div className="tablewrap"><table className="tbl">
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td><Link to={`/runs/${r.id}`} className="mono" style={{ color: 'var(--text)' }}>{(r.targets && r.targets[0]) || r.id}</Link>
                      <div className="muted" style={{ fontSize: 11 }}>{r.mode} · {relTime(r.started_at || r.created_at)}</div></td>
                    <td className="col-actions"><StatusBadge value={r.status} /></td>
                    <td className="col-actions muted tnum" style={{ width: 70 }}>{fmtMoney(r.cost_usd)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </div>

        <div className="card">
          <div className="card__head"><BugIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Latest findings</h2></div>
          {!findPage ? <SkeletonRows rows={4} cols={2} /> : findings.length === 0 ? (
            <div className="card__body"><EmptyState icon={<BugIcon />} title="No findings yet" /></div>
          ) : (
            <div className="tablewrap"><table className="tbl">
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td style={{ width: 96 }}><Severity value={f.severity} /></td>
                    <td>{f.title}<div className="muted mono" style={{ fontSize: 11 }}>{f.endpoint || '—'}</div></td>
                    <td className="col-actions"><StatusBadge value={f.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </div>
      </div>
    </div>
  );
}
