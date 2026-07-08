/* Overview — security posture at a glance. Leads with the single highest-leverage
 * read (open critical exposure, degrading to a calm posture at zero), the engine's
 * validated-vs-unverified trust signal on the recent sample, findings by severity
 * (heat ramp — always label + color + signal-bars), run status, attestation
 * coverage, and real-timestamp recent activity. Every figure traces to live data:
 * no fabricated trends, no invented totals. */
import React from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource } from '../lib/hooks.js';
import { Tile, Bars, Meter, Severity, StatusBadge, Confidence, SkeletonRows, EmptyState, ErrorBanner, SEV_VAR } from '../components/ui.jsx';
import { ShieldIcon, TargetIcon, PlayIcon, BugIcon, ArrowRightIcon, LockIcon, ActivityIcon, AlertIcon, CircleCheckIcon } from '../components/icons.jsx';
import { fmtMoney, fmtNum, relTime, SEVERITY_ORDER, titleCase } from '../lib/format.js';
import { GettingStartedChecklist } from '../features/onboarding';

const RUN_STATUS_COLOR = { COMPLETED: 'var(--ok)', RUNNING: 'var(--info)', PENDING: 'var(--warn)', FAILED: 'var(--danger)', STOPPED: 'var(--danger)', DENIED: 'var(--danger)' };

/* The "one thing that matters most": open critical exposure when it exists,
 * degrading honestly to the next-worst open severity, then to a calm clean read.
 * Nothing here is invented — every branch reads a real count. */
function riskRead({ critical, high, open, ready }) {
  if (!ready) return { tone: 'muted', eyebrow: 'Exposure', icon: null, value: '—', context: 'Posture data is loading or unavailable.', cta: null };
  if (critical > 0) return {
    tone: 'danger', eyebrow: 'Open critical exposure', icon: <AlertIcon size={13} />, value: critical,
    context: `${critical} critical finding${critical === 1 ? '' : 's'} awaiting triage — the highest-leverage fix on the board right now.`,
    cta: { to: '/findings?severity=CRITICAL&status=NEW', label: 'Triage criticals' },
  };
  if (high > 0) return {
    tone: 'warn', eyebrow: 'No criticals open', icon: <ShieldIcon size={13} />, value: high,
    context: `No critical exposure — ${high} high-severity finding${high === 1 ? '' : 's'} next in line to review.`,
    cta: { to: '/findings?severity=HIGH', label: 'Review high findings' },
  };
  if (open > 0) return {
    tone: 'info', eyebrow: 'No criticals open', icon: <ShieldIcon size={13} />, value: open,
    context: 'No critical or high-severity findings open — only medium and below remain.',
    cta: { to: '/findings', label: 'Open findings inbox' },
  };
  return { tone: 'ok', eyebrow: 'No exposure open', icon: <CircleCheckIcon size={13} />, value: <CircleCheckIcon size={38} strokeWidth={2} />, context: 'No open findings across attested scope — a clean posture.', cta: null };
}

export default function Overview() {
  const { data: ov, loading, error } = useResource(() => api('/overview'), [], { pollWhile: (d) => d?.runs?.running > 0 });
  const { data: runsPage } = useResource(() => api('/runs?limit=6'), []);
  const { data: findPage } = useResource(() => api('/findings?limit=6'), []);

  const sev = ov?.findings?.by_severity || {};
  const sevData = SEVERITY_ORDER.map((s) => ({ label: titleCase(s), value: sev[s] || 0, color: SEV_VAR[s], swatch: SEV_VAR[s], key: s }));
  const sevSegments = SEVERITY_ORDER.map((s) => ({ label: s, value: sev[s] || 0, color: SEV_VAR[s] }));
  const sevTotal = SEVERITY_ORDER.reduce((n, s) => n + (sev[s] || 0), 0);
  const runStatus = ov?.runs?.by_status || {};
  const runData = Object.keys(runStatus).map((k) => ({ label: titleCase(k), value: runStatus[k], color: RUN_STATUS_COLOR[k] || 'var(--muted)', swatch: RUN_STATUS_COLOR[k] }));
  const attested = ov?.targets?.attested || 0;
  const totalTargets = ov?.targets?.total || 0;
  const coverage = totalTargets ? Math.round((attested / totalTargets) * 100) : 0;
  const critical = sev.CRITICAL || 0;
  const high = sev.HIGH || 0;
  const open = ov?.findings?.open || 0;
  const runs = runsPage?.items || [];
  const findings = findPage?.items || [];
  const lastRun = runs[0];

  const ready = !!ov && !loading && !error;
  const risk = riskRead({ critical, high, open, ready });

  /* Validated-vs-unverified trust signal — derived ONLY from the recent findings
   * sample /overview doesn't break down by status, so this is scoped "recent",
   * never presented as a total. VERIFIED = the engine re-checked it (the rare
   * validated signal); NEW = surfaced but not yet re-verified. */
  const recentVerified = findings.filter((f) => f.status === 'VERIFIED').length;
  const recentNew = findings.filter((f) => f.status === 'NEW').length;
  const recentTriaged = findings.filter((f) => ['HANDED_OFF', 'REMEDIATED', 'FALSE_POSITIVE'].includes(f.status)).length;

  return (
    <div className="page" data-section="overview">
      {error && <div style={{ marginBottom: 'var(--s-5)' }}><ErrorBanner error={{ ...error, message: `${error.message} — posture data is unavailable; figures below may be stale or unknown.` }} /></div>}

      {/* Hero posture — authorization gate on the left, the dominant risk read on the right */}
      <div className="card" style={{ overflow: 'hidden', marginBottom: 'var(--s-6)', boxShadow: 'var(--shadow-lg)' }}>
        <div className="card__body" style={{ display: 'flex', gap: 'var(--s-5)', alignItems: 'stretch', flexWrap: 'wrap', background: 'var(--aurora-soft)' }}>
          <div className="grow" style={{ display: 'flex', gap: 'var(--s-5)', alignItems: 'flex-start', minWidth: 280 }}>
            <div className="sidebar__logo" style={{ width: 48, height: 48, borderRadius: 14, flex: 'none' }}><LockIcon size={25} strokeWidth={2} /></div>
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="row-tight" style={{ marginBottom: 4 }}>
                <h1 className="display">Security posture</h1>
              </div>
              <p className="muted" style={{ maxWidth: '64ch' }}>
                The authorization gate is <b style={{ color: 'var(--ok)' }}>armed and server-enforced</b> — no scan runs without an active, attested, unexpired scope.
                {ready ? (
                  <> <span className="tnum">{fmtNum(ov.engagements.active)}</span> active engagement{ov.engagements.active === 1 ? '' : 's'}, <span className="tnum">{fmtNum(attested)}</span> attested target{attested === 1 ? '' : 's'}, <span className="tnum">{fmtNum(open)}</span> open finding{open === 1 ? '' : 's'}.{lastRun ? <> Last run {relTime(lastRun.started_at || lastRun.created_at)}.</> : ''}</>
                ) : ''}
              </p>
              <div className="row" style={{ marginTop: 'var(--s-4)' }}>
                <Link to="/engagements?new=1" className="btn"><ShieldIcon size={15} />New engagement</Link>
                <Link to="/runs?new=1" className="btn btn--primary"><PlayIcon size={13} />Start a run</Link>
              </div>
            </div>
          </div>

          <div className="hero-risk" data-tone={risk.tone}>
            <div className="row-tight" style={{ color: 'var(--tone-fg)', fontSize: 11, fontWeight: 680, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
              {risk.icon}{risk.eyebrow}
            </div>
            <div className="tnum" style={{ fontSize: 44, fontWeight: 720, lineHeight: 1, letterSpacing: '-0.03em', color: 'var(--tone-fg)', display: 'flex', alignItems: 'center', minHeight: 44 }}>
              {typeof risk.value === 'number' ? fmtNum(risk.value) : risk.value}
            </div>
            <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.45 }}>{risk.context}</div>
            {risk.cta && (
              <Link to={risk.cta.to} className="row-tight" style={{ color: 'var(--tone-fg)', fontWeight: 620, fontSize: 12.5, marginTop: 2 }}>
                {risk.cta.label}<ArrowRightIcon size={13} />
              </Link>
            )}
          </div>
        </div>
      </div>

      {ov && ov.engagements.total === 0 && ov.targets.total === 0 && ov.runs.total === 0 && (
        <div style={{ marginBottom: 'var(--s-6)' }}><GettingStartedChecklist /></div>
      )}

      {/* KPI tiles */}
      <div className="grid grid-4" style={{ marginBottom: 'var(--s-6)' }}>
        <Tile section="engagements" label="Active engagements" icon={<ShieldIcon />} value={loading || error ? '—' : ov?.engagements?.active ?? 0}
          sub={<Link to="/engagements" className="row-tight" style={{ color: 'var(--sec-engagements)' }}>Manage <ArrowRightIcon size={13} /></Link>} />
        <Tile section="targets" label="Attested targets" icon={<TargetIcon />} value={loading || error ? '—' : attested}
          sub={<span><span className="tnum">{coverage}%</span> of <span className="tnum">{fmtNum(totalTargets)}</span> in registry attested</span>} />
        <Tile section="runs" label="Runs" icon={<PlayIcon />} value={loading || error ? '—' : ov?.runs?.total ?? 0}
          sub={ov?.runs?.running
            ? <span className="statusdot"><i className="live" style={{ background: 'var(--info)' }} /><span className="tnum">{ov.runs.running}</span> running now</span>
            : lastRun ? <span>last run {relTime(lastRun.started_at || lastRun.created_at)}</span> : <span>none running</span>} />
        <Tile section="findings" label="Open findings" icon={<BugIcon />} value={loading || error ? '—' : open}
          sub={critical
            ? <Link to="/findings?severity=CRITICAL&status=NEW" className="row-tight" style={{ color: 'var(--sev-critical)' }}><span className="tnum">{critical}</span> critical unresolved <ArrowRightIcon size={12} /></Link>
            : <span>no criticals open</span>} />
      </div>

      {/* Distributions */}
      <div className="grid grid-2" style={{ marginBottom: 'var(--s-6)' }}>
        <div className="card">
          <div className="card__head"><BugIcon size={16} style={{ color: 'var(--sec-findings)' }} /><h2>Findings by severity</h2><div className="spacer" /><span className="muted tnum" style={{ fontSize: 12 }}>{fmtNum(sevTotal)} open</span><Link to="/findings" className="btn btn--sm btn--ghost">Inbox</Link></div>
          <div className="card__body">
            <Meter segments={sevSegments} />
            <div style={{ height: 16 }} />
            <Bars data={sevData} />
          </div>
        </div>
        <div className="card">
          <div className="card__head"><ActivityIcon size={16} style={{ color: 'var(--sec-runs)' }} /><h2>Runs by status</h2><div className="spacer" /><Link to="/runs" className="btn btn--sm btn--ghost">All runs</Link></div>
          <div className="card__body">
            {runData.length === 0 ? <EmptyState icon={<PlayIcon />} title="No runs yet">Start a run from an active engagement.</EmptyState> : <Bars data={runData} />}
          </div>
        </div>
      </div>

      {/* Recent activity */}
      <div className="grid grid-2">
        <div className="card">
          <div className="card__head"><PlayIcon size={16} style={{ color: 'var(--sec-runs)' }} /><h2>Recent runs</h2></div>
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
          <div className="card__head"><BugIcon size={16} style={{ color: 'var(--sec-findings)' }} /><h2>Latest findings</h2></div>
          {!findPage ? <SkeletonRows rows={4} cols={2} /> : findings.length === 0 ? (
            <div className="card__body"><EmptyState icon={<BugIcon />} title="No findings yet" /></div>
          ) : (
            <>
              {/* Validation trust signal — scoped to the sample shown, not a total. */}
              <div className="card__strip">
                <span className="muted nowrap">Among these {findings.length}:</span>
                <span className="statusdot" title="Re-checked and confirmed real by the engine — the validated signal an autonomous pentester earns."><i style={{ background: 'var(--accent-strong)' }} /><span className="tnum">{recentVerified}</span> engine-validated</span>
                <span className="statusdot" title="Surfaced by a scan but not yet re-verified."><i style={{ background: 'var(--info)' }} /><span className="tnum">{recentNew}</span> unverified</span>
                {recentTriaged > 0 && <span className="statusdot"><i style={{ background: 'var(--muted)' }} /><span className="tnum">{recentTriaged}</span> triaged</span>}
              </div>
              <div className="tablewrap"><table className="tbl">
                <tbody>
                  {findings.map((f) => {
                    const conf = f.evidence?.confidence;
                    return (
                      <tr key={f.id}>
                        <td style={{ width: 96 }}><Severity value={f.severity} /></td>
                        <td>
                          <div style={{ fontWeight: 540 }}>{f.title}</div>
                          {(f.endpoint || conf) ? (
                            <div className="row-tight" style={{ marginTop: 3, gap: 8 }}>
                              {f.endpoint && <span className="muted mono nowrap" style={{ fontSize: 11 }}>{f.endpoint}</span>}
                              {conf && <Confidence value={conf} />}
                            </div>
                          ) : <div className="muted" style={{ fontSize: 11 }}>—</div>}
                        </td>
                        <td className="col-actions"><StatusBadge value={f.status} /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table></div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
