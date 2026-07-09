/* Attack path — the exposure graph derived from an engagement's findings.
 * Layered left-to-right: engagement root -> affected host -> finding leaf, with
 * severity rolled up per host. Rendered as a hand-rolled inline SVG (no graph
 * library, per the console's zero-heavy-dep budget) using the shared severity
 * ramp. Severity is never encoded by colour alone: every host/finding node
 * carries the severity WORD plus rank-bars (shape), so the graph survives
 * colourblindness and grayscale — the same triple-encoding the rest of the console
 * uses. Read-only: it derives purely from stored findings, adds no new state. */
import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useResource } from '../lib/hooks.js';
import {
  PageHead, Severity, SEV_VAR, Meter, EmptyState, ErrorBanner, SkeletonRows,
} from '../components/ui.jsx';
import { GitIcon, ShieldIcon, ServerIcon, BugIcon, ArrowRightIcon } from '../components/icons.jsx';
import { SEVERITY_ORDER, titleCase } from '../lib/format.js';

/* Ordinal rank (1..5) → fills the SVG rank-bars, mirroring the <Severity> meter. */
const SEV_RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
const sevColor = (s) => SEV_VAR[s] || 'var(--border-strong)';
const trunc = (s, n) => { const t = String(s || ''); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

/* Layout geometry — three columns, one row per finding leaf. */
const PAD = 18;
const NODE_H = 48;
const ROW_GAP = 14;
const COL_W = { engagement: 196, host: 188, finding: 256 };
const GAP_X = 72;

/* Rank-bars glyph (shape encoding of severity), drawn inline in SVG. */
function SevBars({ severity, x, y }) {
  const rank = SEV_RANK[severity] || 1;
  const color = sevColor(severity);
  return (
    <g transform={`translate(${x},${y})`} aria-hidden="true">
      {[0, 1, 2, 3, 4].map((i) => (
        <rect key={i} x={i * 4} y={-(3 + i * 2)} width={2.6} height={3 + i * 2} rx={1}
          opacity={i < rank ? 1 : 0.26} style={{ fill: color }} />
      ))}
    </g>
  );
}

/* A cubic bezier from a parent's right edge to a child's left edge. */
function edgePath(a, b) {
  const x1 = a.x + a.w, y1 = a.y + NODE_H / 2;
  const x2 = b.x, y2 = b.y + NODE_H / 2;
  const mx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}

/* Deterministic layout: findings stacked in graph order; hosts at the vertical
 * centroid of their children; the engagement root at the centroid of the hosts. */
function computeLayout(graph) {
  const root = graph.nodes.find((n) => n.type === 'engagement');
  const hosts = graph.nodes.filter((n) => n.type === 'host');
  const findings = graph.nodes.filter((n) => n.type === 'finding');
  if (!findings.length) return null;

  const xEng = PAD;
  const xHost = xEng + COL_W.engagement + GAP_X;
  const xFinding = xHost + COL_W.host + GAP_X;

  const pos = {};
  findings.forEach((f, i) => { pos[f.id] = { x: xFinding, y: PAD + i * (NODE_H + ROW_GAP), w: COL_W.finding }; });

  const childrenOf = {};
  for (const e of graph.edges) {
    if (e.kind === 'host-finding') (childrenOf[e.source] = childrenOf[e.source] || []).push(e.target);
  }
  const centroid = (ys) => (ys.length ? (Math.min(...ys) + Math.max(...ys)) / 2 : PAD);
  hosts.forEach((h) => {
    const ys = (childrenOf[h.id] || []).map((k) => pos[k].y);
    pos[h.id] = { x: xHost, y: centroid(ys), w: COL_W.host };
  });
  pos[root.id] = { x: xEng, y: centroid(hosts.map((h) => pos[h.id].y)), w: COL_W.engagement };

  const height = PAD * 2 + findings.length * NODE_H + Math.max(0, findings.length - 1) * ROW_GAP;
  const width = xFinding + COL_W.finding + PAD;
  return { pos, width, height, root, hosts, findings };
}

/* One node box. `kind` selects styling; findings are focusable links into the
 * findings inbox filtered by their severity. */
function Node({ node, p, onOpen }) {
  const color = sevColor(node.severity);
  const isEng = node.type === 'engagement';
  const stripe = isEng ? 'var(--accent-strong)' : color;
  const Icon = isEng ? ShieldIcon : node.type === 'host' ? ServerIcon : BugIcon;
  const sub = isEng
    ? `${node.finding_count} finding${node.finding_count === 1 ? '' : 's'} · ${node.host_count} host${node.host_count === 1 ? '' : 's'}`
    : node.type === 'host'
      ? `${node.finding_count} finding${node.finding_count === 1 ? '' : 's'}`
      : (node.cwe || node.endpoint || '');
  const interactive = node.type === 'finding';

  const handlers = interactive ? {
    role: 'link', tabIndex: 0, style: { cursor: 'pointer' },
    'aria-label': `${node.label} — ${titleCase(node.severity || '')} severity. Open in findings inbox.`,
    onClick: () => onOpen(node),
    onKeyDown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(node); } },
  } : { 'aria-hidden': isEng ? undefined : 'true' };

  return (
    <g transform={`translate(${p.x},${p.y})`} className="apnode" {...handlers}>
      <title>{node.label}{node.severity ? ` · ${titleCase(node.severity)}` : ''}</title>
      <rect width={p.w} height={NODE_H} rx={11}
        strokeOpacity={isEng ? 0.6 : 0.5} strokeWidth={isEng ? 1.4 : 1.1}
        style={{ fill: 'var(--surface-2)', stroke: isEng ? 'var(--accent-strong)' : color }} />
      <rect x={0} y={7} width={4} height={NODE_H - 14} rx={2} style={{ fill: stripe }} />
      <Icon size={14} x={14} y={9} style={{ color: isEng ? 'var(--accent-strong)' : color }} />
      <text x={36} y={20} fontSize={12.5} fontWeight={600} style={{ fill: 'var(--text)' }}>{trunc(node.label, node.type === 'finding' ? 30 : 24)}</text>
      {node.type !== 'engagement' && node.severity && (
        <>
          <SevBars severity={node.severity} x={36} y={39} />
          <text x={62} y={39} fontSize={10.5} fontWeight={640} style={{ fill: color, letterSpacing: '0.02em' }}>{titleCase(node.severity)}</text>
        </>
      )}
      {sub && (
        <text x={node.type === 'engagement' ? 36 : 132} y={39} fontSize={10.5} style={{ fill: 'var(--muted)', fontFamily: 'var(--mono)' }}>
          {trunc(sub, node.type === 'engagement' ? 30 : 16)}
        </text>
      )}
    </g>
  );
}

function Graph({ graph }) {
  const navigate = useNavigate();
  const layout = React.useMemo(() => computeLayout(graph), [graph]);
  if (!layout) return null;

  const { pos, width, height } = layout;
  const openFinding = (n) => navigate(`/findings?severity=${encodeURIComponent(n.severity || 'ALL')}`);
  const aria = `Attack path for ${graph.engagement_name}: ${graph.summary.finding_count} findings across ${graph.summary.host_count} hosts. Worst severity ${titleCase(graph.summary.max_severity || 'none')}.`;

  return (
    <div className="tablewrap" style={{ overflow: 'auto', maxHeight: 640 }}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={aria} style={{ display: 'block', minWidth: width }}>
        <g>
          {graph.edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target];
            if (!a || !b) return null;
            const sw = e.kind === 'engagement-host' ? Math.min(1.6 + e.weight * 0.5, 5) : 1.4;
            return <path key={i} d={edgePath(a, b)} fill="none" strokeWidth={sw} strokeOpacity={0.45} strokeLinecap="round" style={{ stroke: sevColor(e.severity) }} />;
          })}
        </g>
        {graph.nodes.map((n) => pos[n.id] && <Node key={n.id} node={n} p={pos[n.id]} onOpen={openFinding} />)}
      </svg>
    </div>
  );
}

export default function AttackPath() {
  const [params, setParams] = useSearchParams();
  const { data: engPage, loading: engLoading, error: engError } = useResource(() => api('/engagements?limit=200'), []);
  const engagements = engPage?.items || [];

  const urlEng = params.get('engagement');
  const [engId, setEngId] = React.useState(urlEng || '');
  React.useEffect(() => {
    if (engId || !engagements.length) return;
    const pick = engagements.find((e) => e.status === 'ACTIVE') || engagements[0];
    setEngId(pick.id);
  }, [engagements, engId]);

  const selectEng = (id) => { setEngId(id); setParams(id ? { engagement: id } : {}, { replace: true }); };

  const { data: graph, loading, error } = useResource(
    () => (engId ? api(`/engagements/${engId}/attack-path`) : Promise.resolve(null)),
    [engId],
  );

  const summary = graph?.summary;
  const sevSegments = SEVERITY_ORDER.map((s) => ({ label: s, value: (summary?.by_severity?.[s]) || 0, color: SEV_VAR[s] }));
  const presentSevs = SEVERITY_ORDER.filter((s) => (summary?.by_severity?.[s] || 0) > 0);

  return (
    <div className="page" data-section="findings">
      <PageHead
        title="Attack path"
        eyebrow="Exposure"
        icon={<GitIcon />}
        subtitle="The exposure graph derived from an engagement's findings — engagement root, the affected hosts, and each finding — with severity rolled up per host. Derived live from stored findings; nothing here is fabricated."
      />

      <ErrorBanner error={engError} />

      {/* Controls + summary */}
      <div className="card" style={{ marginBottom: 'var(--s-6)' }}>
        <div className="card__body" style={{ display: 'flex', gap: 'var(--s-6)', alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="field" style={{ minWidth: 240, maxWidth: 340, flex: '1 1 240px' }}>
            <label className="label" htmlFor="ap-eng">Engagement</label>
            <select id="ap-eng" className="select" value={engId} onChange={(e) => selectEng(e.target.value)} disabled={engLoading || !engagements.length}>
              {!engagements.length && <option value="">No engagements</option>}
              {engagements.map((e) => <option key={e.id} value={e.id}>{e.name} · {titleCase(e.status)}</option>)}
            </select>
          </div>
          {summary && (
            <>
              <div className="row" style={{ gap: 'var(--s-7)', flex: 'none' }}>
                <div>
                  <div className="tile__label"><ServerIcon />Hosts</div>
                  <div className="tnum" style={{ fontSize: 26, fontWeight: 680, letterSpacing: '-0.03em', marginTop: 4 }}>{summary.host_count}</div>
                </div>
                <div>
                  <div className="tile__label"><BugIcon />Findings</div>
                  <div className="tnum" style={{ fontSize: 26, fontWeight: 680, letterSpacing: '-0.03em', marginTop: 4 }}>{summary.finding_count}</div>
                </div>
                <div>
                  <div className="tile__label">Worst exposure</div>
                  <div style={{ marginTop: 8 }}>{summary.max_severity ? <Severity value={summary.max_severity} /> : <span className="muted">—</span>}</div>
                </div>
              </div>
              <div className="grow" style={{ minWidth: 240 }}>
                <Meter segments={sevSegments} />
                <div className="row" style={{ gap: 'var(--s-4)', marginTop: 12, rowGap: 8 }}>
                  {presentSevs.length ? presentSevs.map((s) => (
                    <span key={s} className="row-tight" style={{ gap: 7 }}>
                      <Severity value={s} /><b className="tnum" style={{ fontSize: 13 }}>{summary.by_severity[s]}</b>
                    </span>
                  )) : <span className="muted" style={{ fontSize: 12 }}>No findings in scope yet.</span>}
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <ErrorBanner error={error} />

      {/* Graph */}
      <div className="card">
        <div className="card__head">
          <GitIcon size={16} style={{ color: 'var(--muted)' }} />
          <h2>Exposure graph</h2>
          <div className="spacer" />
          <span className="muted" style={{ fontSize: 12 }}>engagement → host → finding</span>
        </div>
        {loading ? (
          <SkeletonRows rows={6} cols={3} />
        ) : !graph || summary?.finding_count === 0 ? (
          <div className="card__body">
            <EmptyState icon={<GitIcon />} title={graph ? 'No findings to map yet' : 'Select an engagement'}>
              <p className="muted">{graph
                ? 'This engagement has no findings, so there is no attack path to draw. The graph fills in as runs complete and findings land.'
                : 'Pick an engagement above to see its exposure graph.'}</p>
            </EmptyState>
          </div>
        ) : (
          <div className="card__body" style={{ paddingTop: 'var(--s-4)' }}>
            <Graph graph={graph} />
            <p className="muted" style={{ fontSize: 12, marginTop: 'var(--s-4)', marginBottom: 0 }}>
              Node severity is triple-encoded (colour, rank-bars, and the label) so it reads without relying on colour. Select a finding to open it in the inbox.
              <span className="row-tight" style={{ gap: 6, marginLeft: 6, display: 'inline-flex' }}>Highest exposure first <ArrowRightIcon size={12} /></span>
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
