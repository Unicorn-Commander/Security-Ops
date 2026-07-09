/* In-memory demo backend — mirrors the /api/v1 surface with realistic fixtures so
 * the console is fully interactive (create, attest, start runs, hand off) with no
 * server. Enabled via ?demo=1 or localStorage('secops_demo'). Purely client-side. */

const now = Date.now();
const iso = (ms) => new Date(now + ms).toISOString();
const uid = (() => { let n = 1000; return (p = 'id') => `${p}-${(n++).toString(36)}-${Math.floor(now % 1e6).toString(36)}`; })();
const H = 3600e3;
const D = 24 * H;

function seed() {
  const targets = [
    { id: 'tgt-brigade', kind: 'DOMAIN', value: 'brigade.unicorncommander.ai', label: 'Own suite — Brigade', owner_principal: 'demo@example.invalid', attestation_status: 'ATTESTED', attestation_method: 'OWNED', attested_by: 'demo@example.invalid', attested_at: iso(-12 * D), attestation_evidence: null, expires_at: null, revoked_at: null, created_at: iso(-12 * D) },
    { id: 'tgt-ops', kind: 'DOMAIN', value: 'ops.unicorncommander.ai', label: 'Own suite — Ops-Center', owner_principal: 'demo@example.invalid', attestation_status: 'ATTESTED', attestation_method: 'OWNED', attested_by: 'demo@example.invalid', attested_at: iso(-9 * D), expires_at: null, revoked_at: null, created_at: iso(-9 * D) },
    { id: 'tgt-acme', kind: 'URL', value: 'https://app.acme-client.com', label: 'ACME — Q3 engagement', owner_principal: 'demo@example.invalid', attestation_status: 'ATTESTED', attestation_method: 'DNS_TXT', attested_by: 'demo@example.invalid', attested_at: iso(-4 * D), attestation_evidence: { ownership_proof: { verified: true, method: 'DNS_TXT', location: '_security-ops-authz.app.acme-client.com' } }, expires_at: iso(86 * D), revoked_at: null, created_at: iso(-5 * D) },
    { id: 'tgt-net', kind: 'IP_RANGE', value: '10.20.0.0/24', label: 'ACME — internal subnet', owner_principal: 'demo@example.invalid', attestation_status: 'ATTESTED', attestation_method: 'FILE_DROP', attested_by: 'demo@example.invalid', attested_at: iso(-3 * D), expires_at: iso(87 * D), revoked_at: null, created_at: iso(-4 * D) },
    { id: 'tgt-repo', kind: 'REPO', value: 'github.com/unicorncommander/brigade', label: 'Source — Brigade', owner_principal: 'demo@example.invalid', attestation_status: 'ATTESTED', attestation_method: 'OWNED', attested_by: 'demo@example.invalid', attested_at: iso(-8 * D), expires_at: null, revoked_at: null, created_at: iso(-8 * D) },
    { id: 'tgt-partner', kind: 'DOMAIN', value: 'staging.partner-co.io', label: 'Partner — pending proof', owner_principal: null, attestation_status: 'UNATTESTED', attestation_method: null, attested_by: null, attested_at: null, expires_at: null, revoked_at: null, created_at: iso(-1 * D) },
    { id: 'tgt-expired', kind: 'DOMAIN', value: 'legacy.acme-client.com', label: 'ACME — lapsed', owner_principal: 'demo@example.invalid', attestation_status: 'EXPIRED', attestation_method: 'DNS_TXT', attested_by: 'demo@example.invalid', attested_at: iso(-120 * D), expires_at: iso(-3 * D), revoked_at: null, created_at: iso(-121 * D) },
  ];

  const scope = (inScope, excl = []) => ({ in_scope: inScope, exclusions: excl });
  const engagements = [
    { id: 'eng-suite', name: 'UC Suite — self-owned pilot', status: 'ACTIVE', model_profile: 'hybrid-local-sweep-verify', created_by: 'demo@example.invalid', created_at: iso(-11 * D), starts_at: iso(-11 * D), expires_at: iso(30 * D), emergency_stopped: false, scope: scope([{ kind: 'DOMAIN', value: 'brigade.unicorncommander.ai' }, { kind: 'DOMAIN', value: 'ops.unicorncommander.ai' }], [{ kind: 'URL', value: 'brigade.unicorncommander.ai/admin' }]), rules_of_engagement: { intensity: 'STANDARD', allowed_vuln_classes: [], max_concurrency: 1 } },
    { id: 'eng-acme', name: 'ACME Corp — Q3 external', status: 'ACTIVE', model_profile: 'frontier-verify', created_by: 'demo@example.invalid', created_at: iso(-5 * D), starts_at: iso(-4 * D), expires_at: iso(25 * D), emergency_stopped: false, scope: scope([{ kind: 'URL', value: 'https://app.acme-client.com' }, { kind: 'IP_RANGE', value: '10.20.0.0/24' }]), rules_of_engagement: { intensity: 'DEEP', allowed_vuln_classes: [], max_concurrency: 2 } },
    { id: 'eng-draft', name: 'Partner Co — scoping', status: 'DRAFT', model_profile: 'hybrid-local-sweep-verify', created_by: 'demo@example.invalid', created_at: iso(-1 * D), starts_at: null, expires_at: null, emergency_stopped: false, scope: scope([{ kind: 'DOMAIN', value: 'staging.partner-co.io' }]), rules_of_engagement: { intensity: 'QUICK', allowed_vuln_classes: [], max_concurrency: 1 } },
  ];

  const runs = [
    { id: 'run-1', engagement_id: 'eng-suite', engine: 'strix', status: 'COMPLETED', mode: 'STANDARD', model_profile: 'hybrid-local-sweep-verify', targets: ['https://brigade.unicorncommander.ai/login', 'brigade.unicorncommander.ai/api'], strix_run_id: 'strix-9f2c', started_at: iso(-2 * D), ended_at: iso(-2 * D + 41 * 60e3), cost_usd: 0, usage: { total_tokens: 512000 }, report_path: 'strix_runs/run-1/penetration_test_report.md', error: null, created_at: iso(-2 * D) },
    { id: 'run-2', engagement_id: 'eng-acme', engine: 'nuclei', status: 'RUNNING', mode: 'DEEP', model_profile: 'frontier-verify', targets: ['https://app.acme-client.com'], strix_run_id: 'strix-a13b', started_at: iso(-22 * 60e3), ended_at: null, cost_usd: 1.84, usage: null, report_path: null, error: null, created_at: iso(-22 * 60e3) },
    { id: 'run-3', engagement_id: 'eng-acme', engine: 'trivy', status: 'COMPLETED', mode: 'STANDARD', model_profile: 'frontier-verify', targets: ['10.20.0.0/24'], strix_run_id: 'strix-77de', started_at: iso(-1 * D), ended_at: iso(-1 * D + 58 * 60e3), cost_usd: 2.53, usage: { total_tokens: 978000 }, report_path: 'strix_runs/run-3/penetration_test_report.md', error: null, created_at: iso(-1 * D) },
    { id: 'run-4', engagement_id: 'eng-suite', engine: 'gitleaks', status: 'FAILED', mode: 'QUICK', model_profile: 'local-sweep', targets: ['ops.unicorncommander.ai'], strix_run_id: null, started_at: iso(-6 * H), ended_at: iso(-6 * H + 3 * 60e3), cost_usd: 0, usage: null, report_path: null, error: 'strix sandbox image pull timed out', created_at: iso(-6 * H) },
  ];

  const f = (o) => ({ status: 'NEW', cwe: null, endpoint: null, payload: null, poc: null, evidence: {}, verified_by: null, handoff_ref: null, ...o });
  const findings = [
    f({ id: 'fnd-1', run_id: 'run-1', engagement_id: 'eng-suite', severity: 'HIGH', title: 'Open redirect in OIDC callback', cwe: 'CWE-601', endpoint: 'https://brigade.unicorncommander.ai/auth/oidc/callback', payload: 'redirect_after=https://evil.example', poc: 'GET /auth/oidc/callback?redirect_after=https://evil.example → 302 Location: https://evil.example', evidence: { remediation: 'Allowlist redirect targets to same-origin paths; reject absolute external URLs.', confidence: 'high' }, status: 'HANDED_OFF', verified_by: 'strix-qwen3.5-122b', handoff_ref: 'BRIG-482', closure_reason: 'handed off to Brigade', closed_by: 'demo@example.invalid', closed_at: iso(-2 * D + 30 * 60e3), created_at: iso(-2 * D + 30 * 60e3) }),
    f({ id: 'fnd-2', run_id: 'run-1', engagement_id: 'eng-suite', severity: 'MEDIUM', title: 'Refresh token persisted in localStorage', cwe: 'CWE-522', endpoint: 'https://brigade.unicorncommander.ai/', poc: 'window.localStorage.getItem("refresh_token") returns a valid JWT', evidence: { remediation: 'Store refresh token in an HttpOnly cookie only; remove the localStorage path.' }, status: 'VERIFIED', verified_by: 'strix-qwen3.5-122b', created_at: iso(-2 * D + 33 * 60e3) }),
    f({ id: 'fnd-3', run_id: 'run-1', engagement_id: 'eng-suite', severity: 'LOW', title: 'Timing-unsafe master key comparison', cwe: 'CWE-208', endpoint: 'middleware.py:113', evidence: { remediation: 'Use hmac.compare_digest for constant-time comparison.' }, status: 'NEW', verified_by: 'strix-qwen3.6-35b', created_at: iso(-2 * D + 35 * 60e3) }),
    f({ id: 'fnd-4', run_id: 'run-3', engagement_id: 'eng-acme', severity: 'CRITICAL', title: 'SQL injection → admin authentication bypass', cwe: 'CWE-89', endpoint: 'https://app.acme-client.com/rest/user/login', payload: "email=' OR 1=1--", poc: "POST /rest/user/login {email: \"' OR 1=1--\"} → returns admin JWT; GET /api/Users/1 with that token → 200 full admin record", evidence: { remediation: 'Use parameterized queries / an ORM; never interpolate credentials into SQL.', confidence: 'confirmed', chain: ['login bypass', 'admin JWT minted', 'admin API reachable'] }, status: 'VERIFIED', verified_by: 'gpt-5.4', created_at: iso(-1 * D + 40 * 60e3) }),
    f({ id: 'fnd-5', run_id: 'run-3', engagement_id: 'eng-acme', severity: 'HIGH', title: 'IDOR on basket retrieval', cwe: 'CWE-639', endpoint: 'https://app.acme-client.com/rest/basket/{id}', poc: 'GET /rest/basket/2 while authenticated as user 1 → 200 with another user’s basket contents', evidence: { remediation: 'Enforce object-level authorization: verify the basket belongs to the authenticated user.' }, status: 'NEW', verified_by: 'gpt-5.4', created_at: iso(-1 * D + 44 * 60e3) }),
    f({ id: 'fnd-6', run_id: 'run-3', engagement_id: 'eng-acme', severity: 'MEDIUM', title: 'Sensitive files exposed under /ftp', cwe: 'CWE-548', endpoint: 'https://app.acme-client.com/ftp', poc: 'GET /ftp/ lists downloadable backup + coupon files', evidence: { remediation: 'Remove directory listing; restrict /ftp; move backups out of the web root.' }, status: 'NEW', verified_by: 'strix-qwen3.6-35b', created_at: iso(-1 * D + 47 * 60e3) }),
    f({ id: 'fnd-7', run_id: 'run-3', engagement_id: 'eng-acme', severity: 'LOW', title: 'Verbose error discloses stack trace', cwe: 'CWE-209', endpoint: 'https://app.acme-client.com/rest/products/search', evidence: { remediation: 'Return generic errors to clients; log details server-side only.' }, status: 'FALSE_POSITIVE', verified_by: 'gpt-5.4', closure_reason: 'Verified as a safe test-only error path', closed_by: 'demo@example.invalid', closed_at: iso(-1 * D + 50 * 60e3), created_at: iso(-1 * D + 50 * 60e3) }),
    f({ id: 'fnd-8', run_id: 'run-1', engagement_id: 'eng-suite', severity: 'INFO', title: 'Missing HSTS header', cwe: 'CWE-319', endpoint: 'https://brigade.unicorncommander.ai/', evidence: { remediation: 'Add Strict-Transport-Security with a long max-age.' }, status: 'NEW', verified_by: 'strix-qwen3.6-35b', created_at: iso(-2 * D + 37 * 60e3) }),
  ];

  return { targets, engagements, runs, findings };
}

let db = seed();
export function resetDemo() { db = seed(); }

const clone = (x) => JSON.parse(JSON.stringify(x));
const page = (items, limit, offset) => ({ items: clone(items.slice(offset, offset + limit)), total: items.length, limit, offset });
function counts(items, key) { const m = {}; for (const it of items) { const k = it[key]; m[k] = (m[k] || 0) + 1; } return m; }

function overview() {
  const { engagements, targets, runs, findings } = db;
  return {
    engagements: { total: engagements.length, by_status: counts(engagements, 'status'), active: engagements.filter((e) => e.status === 'ACTIVE').length },
    targets: { total: targets.length, attested: targets.filter((t) => t.attestation_status === 'ATTESTED').length, by_status: counts(targets, 'attestation_status') },
    runs: { total: runs.length, by_status: counts(runs, 'status'), running: runs.filter((r) => r.status === 'RUNNING').length },
    findings: { total: findings.length, by_severity: counts(findings, 'severity'), open: findings.filter((f) => f.status === 'NEW' || f.status === 'VERIFIED').length },
  };
}

/* Host extraction — mirrors app.services.attack_path._host_of (URL / host:port /
 * bare host / bracketed IPv6). Returns null when no host can be parsed. */
function hostOf(endpoint) {
  const text = String(endpoint || '').trim();
  if (!text) return null;
  let netloc = text.includes('://') ? text.split('://')[1] || '' : text;
  if (!netloc) netloc = text;
  netloc = netloc.split('@').pop();
  netloc = netloc.split('/')[0];
  let host;
  if (netloc.startsWith('[')) host = netloc.slice(1).split(']')[0];
  else if ((netloc.match(/:/g) || []).length === 1) host = netloc.split(':')[0];
  else host = netloc;
  host = host.trim().replace(/\.+$/, '').toLowerCase();
  return host || null;
}

const AP_SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
function maxSeverity(items) {
  let best = null, bestRank = -1;
  for (const f of items) { const r = AP_SEV_RANK[f.severity] ?? -1; if (r > bestRank) { bestRank = r; best = f.severity; } }
  return best;
}

/* Attack-path / exposure graph — client mirror of
 * app.services.attack_path.build_attack_path_graph (engagement root -> host ->
 * finding leaf, severity rolled up, deterministic ordering). */
function attackPath(engId) {
  const eng = db.engagements.find((e) => e.id === engId);
  if (!eng) { const err = new Error('Engagement not found'); err.code = 'not_found'; err.status = 404; throw err; }
  const findings = db.findings.filter((f) => f.engagement_id === engId);

  const byHost = new Map();
  for (const f of findings) {
    const h = hostOf(f.endpoint);
    const key = h === null ? ' ' : h;
    if (!byHost.has(key)) byHost.set(key, { host: h, items: [] });
    byHost.get(key).items.push(f);
  }
  const buckets = [...byHost.values()].sort((a, b) => {
    const au = a.host === null, bu = b.host === null;
    if (au !== bu) return au ? 1 : -1; // unspecified bucket always last
    const ar = AP_SEV_RANK[maxSeverity(a.items)] ?? -1, br = AP_SEV_RANK[maxSeverity(b.items)] ?? -1;
    if (ar !== br) return br - ar; // most-severe host first
    return (a.host || '').localeCompare(b.host || '');
  });

  const nodes = [], edges = [];
  const engNodeId = `engagement:${eng.id}`;
  const rootSev = maxSeverity(findings);
  nodes.push({ id: engNodeId, type: 'engagement', label: eng.name, severity: rootSev, finding_count: findings.length, host_count: buckets.length });

  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

  for (const b of buckets) {
    const hostId = b.host === null ? 'host:__unspecified__' : `host:${b.host}`;
    const hostLabel = b.host === null ? '(unspecified host)' : b.host;
    const hostSev = maxSeverity(b.items);
    nodes.push({ id: hostId, type: 'host', label: hostLabel, severity: hostSev, finding_count: b.items.length });
    edges.push({ source: engNodeId, target: hostId, kind: 'engagement-host', severity: hostSev, weight: b.items.length });
    const sorted = [...b.items].sort((x, y) => {
      const xr = AP_SEV_RANK[x.severity] ?? -1, yr = AP_SEV_RANK[y.severity] ?? -1;
      if (xr !== yr) return yr - xr;
      return String(x.title).localeCompare(String(y.title)) || String(x.id).localeCompare(String(y.id));
    });
    for (const f of sorted) {
      const fid = `finding:${f.id}`;
      nodes.push({ id: fid, type: 'finding', label: f.title, severity: f.severity, cwe: f.cwe, status: f.status, endpoint: f.endpoint, finding_id: f.id });
      edges.push({ source: hostId, target: fid, kind: 'host-finding', severity: f.severity, weight: 1 });
    }
  }

  return {
    engagement_id: eng.id, engagement_name: eng.name, nodes, edges,
    summary: { node_count: nodes.length, edge_count: edges.length, host_count: buckets.length, finding_count: findings.length, by_severity: bySeverity, max_severity: rootSev },
  };
}

function scopeCheck(engId, target) {
  const eng = db.engagements.find((e) => e.id === engId);
  if (!eng) return { allowed: false, code: 'engagement_inactive', reason: 'engagement not found', target, violations: ['engagement_not_found'] };
  const host = String(target).replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  const rule = (eng.scope.in_scope || []).find((r) => host.includes(String(r.value).replace(/^https?:\/\//, '').split('/')[0].toLowerCase()));
  const excluded = (eng.scope.exclusions || []).some((r) => String(target).toLowerCase().includes(String(r.value).toLowerCase()));
  if (excluded) return { allowed: false, code: 'target_excluded', reason: 'target matches an explicit scope exclusion', target, violations: ['excluded'] };
  if (!rule) return { allowed: false, code: 'scope_violation', reason: 'target is not within the engagement in-scope rules', target, violations: ['not_in_scope'] };
  const attested = db.targets.some((t) => t.attestation_status === 'ATTESTED' && host.includes(t.value.replace(/^https?:\/\//, '').split('/')[0].toLowerCase()));
  if (!attested) return { allowed: false, code: 'target_not_attested', reason: 'no valid attested target covers this target', target, violations: ['target_not_attested'] };
  return { allowed: true, code: 'allowed', reason: 'target is in scope and covered by a valid attestation', target, violations: [] };
}

async function delay(ms = 260) { return new Promise((r) => setTimeout(r, ms + Math.random() * 180)); }

export async function demoHandle(method, path, body) {
  await delay();
  const [p, q = ''] = path.split('?');
  const params = new URLSearchParams(q);
  const seg = p.replace(/^\/api\/v1/, '').split('/').filter(Boolean);
  const limit = Number(params.get('limit') || 50);
  const offset = Number(params.get('offset') || 0);

  // /overview
  if (seg[0] === 'overview') return overview();

  // /engagements ...
  if (seg[0] === 'engagements') {
    if (seg.length === 1 && method === 'GET') return page(db.engagements, limit, offset);
    if (seg.length === 1 && method === 'POST') {
      const e = { id: uid('eng'), name: body.name, status: 'DRAFT', model_profile: body.model_profile || 'hybrid-local-sweep-verify', created_by: 'you@demo', created_at: new Date().toISOString(), starts_at: null, expires_at: null, emergency_stopped: false, scope: { in_scope: body.scope?.in_scope || [], exclusions: body.scope?.exclusions || [] }, rules_of_engagement: body.scope?.rules_of_engagement || {} };
      db.engagements = [e, ...db.engagements]; return clone(e);
    }
    const id = seg[1];
    const eng = db.engagements.find((e) => e.id === id);
    if (seg[2] === 'activate' && method === 'POST') { if (eng) eng.status = 'ACTIVE'; return clone(eng); }
    if (seg[2] === 'stop' && method === 'POST') { if (eng) { eng.status = 'STOPPED'; eng.emergency_stopped = true; } return clone(eng); }
    if (seg[2] === 'scope' && seg[3] === 'check' && method === 'POST') return scopeCheck(id, body.target);
    if (seg[2] === 'attack-path' && method === 'GET') return attackPath(id);
    if (seg[2] === 'report') {
      const md = demoReport(eng);
      return params.get('format') === 'json' ? { engagement_id: id, report_markdown: md } : md;
    }
    if (seg.length === 2 && method === 'GET') return clone(eng);
  }

  // /targets ...
  if (seg[0] === 'targets') {
    if (seg.length === 1 && method === 'GET') return page(db.targets, limit, offset);
    if (seg.length === 1 && method === 'POST') {
      const t = { id: uid('tgt'), kind: body.kind, value: body.value, label: body.label || null, owner_principal: body.owner_principal || null, attestation_status: 'UNATTESTED', attestation_method: null, attested_by: null, attested_at: null, attestation_evidence: null, expires_at: null, revoked_at: null, created_at: new Date().toISOString() };
      db.targets = [t, ...db.targets]; return clone(t);
    }
    const id = seg[1];
    const t = db.targets.find((x) => x.id === id);
    if (seg[2] === 'attestation-challenge' && method === 'GET') {
      const token = `security-ops-site-verification=${id}`;
      const host = (t?.value || 'example.com').replace(/^https?:\/\//, '').split('/')[0];
      return { token, target: t?.value, methods: {
        DNS_TXT: { record_type: 'TXT', name: `_security-ops-authz.${host}`, value: token, how: `Publish a TXT record at '_security-ops-authz.${host}' whose value is the token.` },
        FILE_DROP: { url: `https://${host}/.well-known/security-ops-authorization.txt`, body: token, how: `Serve the token as the body of https://${host}/.well-known/security-ops-authorization.txt.` },
        HTTP_HEADER: { url: `https://${host}`, header: 'Strix-Authorization', value: token, how: `Return the token in the 'Strix-Authorization' response header from https://${host}.` },
      } };
    }
    if (seg[2] === 'attest' && method === 'POST') {
      if (t) { t.attestation_status = 'ATTESTED'; t.attestation_method = body.method; t.attested_by = 'you@demo'; t.attested_at = new Date().toISOString(); t.expires_at = body.expires_at || (['DNS_TXT', 'FILE_DROP', 'HTTP_HEADER'].includes(body.method) ? iso(90 * D) : null); t.revoked_at = null; }
      return clone(t);
    }
    if (seg.length === 2 && method === 'GET') return clone(t);
  }

  // /runs ...
  if (seg[0] === 'runs') {
    if (seg.length === 1 && method === 'GET') {
      let items = db.runs; const st = params.get('status'); if (st) items = items.filter((r) => r.status === st);
      return page(items, limit, offset);
    }
    const id = seg[1];
    const run = db.runs.find((r) => r.id === id);
    if (seg[2] === 'stop' && method === 'POST') { if (run) { run.status = 'STOPPED'; run.ended_at = new Date().toISOString(); } return clone(run); }
    if (seg[2] === 'findings' && method === 'GET') return page(db.findings.filter((f) => f.run_id === id), limit, offset);
    if (seg.length === 2 && method === 'GET') return clone(run);
  }

  // POST /engagements/:id/runs handled above under engagements? No — path is /engagements/:id/runs
  if (seg[0] === 'engagements' && seg[2] === 'runs' && method === 'POST') {
    const run = { id: uid('run'), engagement_id: seg[1], engine: body.engine || 'strix', status: 'PENDING', mode: body.mode || 'STANDARD', model_profile: body.model_profile || 'hybrid-local-sweep-verify', targets: body.targets || [], strix_run_id: null, started_at: null, ended_at: null, cost_usd: null, usage: null, report_path: null, error: null, created_at: new Date().toISOString() };
    db.runs = [run, ...db.runs];
    // simulate the run going live then completing
    setTimeout(() => { const r = db.runs.find((x) => x.id === run.id); if (r && r.status === 'PENDING') { r.status = 'RUNNING'; r.started_at = new Date().toISOString(); r.strix_run_id = 'strix-' + Math.random().toString(16).slice(2, 6); } }, 2500);
    return clone(run);
  }

  // /findings ...
  if (seg[0] === 'findings') {
    if (seg.length === 1 && method === 'GET') {
      let items = db.findings; const sev = params.get('severity'); const st = params.get('status');
      if (sev) items = items.filter((f) => f.severity === sev);
      if (st) items = items.filter((f) => f.status === st);
      return page(items, limit, offset);
    }
    const id = seg[1];
    const fnd = db.findings.find((f) => f.id === id);
    if (seg[2] === 'handoff' && method === 'POST') { if (fnd) { fnd.status = 'HANDED_OFF'; fnd.handoff_ref = 'BRIG-' + Math.floor(100 + Math.random() * 900); } return clone(fnd); }
    if (seg.length === 2 && method === 'GET') return clone(fnd);
  }

  const err = new Error('Demo: unhandled route ' + method + ' ' + p);
  err.code = 'not_found'; err.status = 404; throw err;
}

function demoReport(eng) {
  const fs = db.findings.filter((f) => f.engagement_id === eng?.id);
  const bySev = counts(fs, 'severity');
  return `# Security-Ops — Engagement Report

**${eng?.name || 'Engagement'}**  ·  generated by Security-Ops · Autonomous authorized penetration testing

## Executive summary

- Runs: ${db.runs.filter((r) => r.engagement_id === eng?.id).length}
- Findings: ${fs.length}  (Critical ${bySev.CRITICAL || 0}, High ${bySev.HIGH || 0}, Medium ${bySev.MEDIUM || 0}, Low ${bySev.LOW || 0}, Info ${bySev.INFO || 0})

${fs.map((f) => `### [${f.severity}] ${f.title}\n\n- **Endpoint:** ${f.endpoint || '—'}\n- **CWE:** ${f.cwe || '—'}\n- **PoC:** ${f.poc || '—'}\n- **Remediation:** ${f.evidence?.remediation || '—'}`).join('\n\n')}
`;
}
