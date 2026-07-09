/* Targets — the authorized-target registry the authorization gate consults.
 * A target is only scannable once it passes attestation (valid, unexpired,
 * not revoked). External assets need ownership proof (DNS_TXT / FILE_DROP /
 * HTTP_HEADER); self-owned assets use OWNED. Register + attest live here. */
import React from 'react';
import { api } from '../lib/api.js';
import { useResource, useMutation } from '../lib/hooks.js';
import { useSearchParams } from 'react-router-dom';
import { PageHead, StatusBadge, EmptyState, SkeletonRows, ErrorBanner, Banner, Drawer, useToast, CopyButton, rowActivate } from '../components/ui.jsx';
import {
  TargetIcon, GlobeIcon, ServerIcon, GitIcon, PlusIcon, KeyIcon, CheckIcon,
  ChevronRightIcon, ClockIcon, LockIcon,
} from '../components/icons.jsx';
import { fmtDate } from '../lib/format.js';

const KINDS = ['DOMAIN', 'URL', 'IP_RANGE', 'REPO', 'IMAGE', 'CLOUD_ACCOUNT'];
const KIND_ICON = { DOMAIN: GlobeIcon, URL: GlobeIcon, IP_RANGE: ServerIcon, REPO: GitIcon, IMAGE: ServerIcon, CLOUD_ACCOUNT: ServerIcon };
// OWNED first — the self-owned escape hatch (your own suite). Proof methods are verified live by the server.
const METHODS = ['OWNED', 'CHECKBOX', 'TYPED_CONFIRMATION', 'DNS_TXT', 'FILE_DROP', 'HTTP_HEADER'];
const PROOF_METHODS = ['DNS_TXT', 'FILE_DROP', 'HTTP_HEADER'];
// Cloud-account possession proof: assume a role granted with our per-target external
// ID (not admin-only — the assumption IS the authorization). Offered for CLOUD_ACCOUNT
// targets when /me capabilities say the install switch is on.
const CLOUD_METHODS = ['CLOUD_ROLE'];
// Admin-only "authorized-operator" methods that skip live ownership proof for a
// recorded human authorization. Appended to the picker only when /me capabilities
// say the caller may use them (admin + install-switch). Justification-required.
const PRIVILEGED_METHODS = ['SELF_ATTESTED', 'BREAK_GLASS'];
const METHOD_LABEL = {
  OWNED: 'Owned', CHECKBOX: 'Checkbox', TYPED_CONFIRMATION: 'Typed',
  DNS_TXT: 'DNS TXT', FILE_DROP: 'File drop', HTTP_HEADER: 'HTTP header',
  CLOUD_ROLE: 'Cloud role', SELF_ATTESTED: 'Self-attest (admin)', BREAK_GLASS: 'Break-glass (admin)',
};

function KindIcon({ kind, ...rest }) {
  const Icon = KIND_ICON[kind] || TargetIcon;
  return <Icon {...rest} />;
}

/* ------------------------------------------------------------------ Register */
function RegisterDrawer({ onClose, onCreated }) {
  const toast = useToast();
  const [kind, setKind] = React.useState('DOMAIN');
  const [value, setValue] = React.useState('');
  const [label, setLabel] = React.useState('');
  const [owner, setOwner] = React.useState('');
  const { run, busy, error } = useMutation();

  async function submit(e) {
    e.preventDefault();
    if (!value.trim()) return;
    const body = {
      kind, value: value.trim(),
      label: label.trim() || undefined,
      owner_principal: owner.trim() || undefined,
    };
    try {
      const created = await run('/targets', { method: 'POST', body });
      toast({ title: `Registered ${created.kind} ${created.value}`, detail: 'UNATTESTED — attest it before it becomes scannable.' });
      onCreated();
    } catch { /* surfaced inline */ }
  }

  return (
    <Drawer title="Register target" subtitle="Adds an UNATTESTED entry to the registry"
      onClose={onClose}
      footer={<>
        <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn--primary" form="target-form" disabled={busy || !value.trim()}>{busy ? 'Registering…' : 'Register'}</button>
      </>}>
      <ErrorBanner error={error} />
      <Banner kind="info">Registering only records the asset. It stays <b>unscannable</b> until you attest it and it sits in an active engagement.</Banner>
      <form id="target-form" onSubmit={submit} className="stack">
        <div className="grid grid-2">
          <div className="field">
            <label className="label">Kind</label>
            <select className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
              {KINDS.map((k) => <option key={k}>{k}</option>)}
            </select>
          </div>
          <div className="field">
            <label className="label">Owner principal</label>
            <input className="input" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="demo@example.invalid" />
          </div>
        </div>
        <div className="field">
          <label className="label">Value</label>
          <input className="input mono" autoFocus value={value} onChange={(e) => setValue(e.target.value)}
            placeholder="brigade.unicorncommander.ai · https://app… · 10.0.0.0/24 · repo · image · aws:123456789012" />
          <span className="hint">Domain, URL, CIDR, repository, image, or cloud account (aws:&lt;id&gt; / gcp:&lt;project&gt; / azure:&lt;sub&gt;) — matched against engagement scope.</span>
        </div>
        <div className="field">
          <label className="label">Label</label>
          <input className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Own suite — Brigade" />
        </div>
      </form>
    </Drawer>
  );
}

/* -------------------------------------------------------------- Proof block */
function ProofRow({ label, value }) {
  return (
    <div className="field" style={{ gap: 4 }}>
      <label className="label">{label}</label>
      <div className="codebox">
        <div className="code" style={{ paddingRight: 44, wordBreak: 'break-all' }}>{value}</div>
        <div className="copy"><CopyButton text={value} /></div>
      </div>
    </div>
  );
}

function ProofBlock({ method, challenge, loading, error }) {
  if (loading) return <div className="hint" style={{ padding: '4px 0' }}>Loading proof instructions…</div>;
  if (error) return <ErrorBanner error={error} />;
  if (!challenge) return null;
  const spec = challenge.methods?.[method];
  if (!spec) return <div className="hint">No instructions available for this method.</div>;

  return (
    <div className="card" style={{ background: 'var(--surface-inset)' }}>
      <div className="card__head"><KeyIcon size={15} style={{ color: 'var(--accent-strong)' }} /><h2>Publish this proof</h2></div>
      <div className="card__body stack" style={{ gap: 'var(--s-4)' }}>
        <p className="hint" style={{ margin: 0 }}>{spec.how || 'Publish the record below, then attest — the server verifies it live.'}</p>
        <ProofRow label="Authorization token" value={challenge.token} />
        {method === 'DNS_TXT' && (<>
          <div className="grid grid-2">
            <ProofRow label={`Record type`} value={spec.record_type || 'TXT'} />
            <ProofRow label="Record name" value={spec.name} />
          </div>
          <ProofRow label="Record value" value={spec.value} />
        </>)}
        {method === 'FILE_DROP' && (<>
          <ProofRow label="Well-known URL" value={spec.url} />
          <ProofRow label="File body" value={spec.body} />
        </>)}
        {method === 'HTTP_HEADER' && (<>
          <ProofRow label="Request URL" value={spec.url} />
          <div className="grid grid-2">
            <ProofRow label="Header" value={spec.header} />
            <ProofRow label="Header value" value={spec.value} />
          </div>
        </>)}
      </div>
    </div>
  );
}

/* ----------------------------------------------------- Cloud proof block */
function CloudProofBlock({ challenge, loading, error }) {
  if (loading) return <div className="hint" style={{ padding: '4px 0' }}>Loading role-grant instructions…</div>;
  if (error) return <ErrorBanner error={error} />;
  if (!challenge || !challenge.external_id) return null;
  const policy = challenge.aws_trust_policy ? JSON.stringify(challenge.aws_trust_policy, null, 2) : null;
  return (
    <div className="card" style={{ background: 'var(--surface-inset)' }}>
      <div className="card__head"><KeyIcon size={15} style={{ color: 'var(--accent-strong)' }} /><h2>Grant the scanner role</h2></div>
      <div className="card__body stack" style={{ gap: 'var(--s-4)' }}>
        <p className="hint" style={{ margin: 0 }}>{challenge.how || 'Create a role trusting our scanner principal and requiring this external ID, then attest with the role ARN.'}</p>
        <ProofRow label="External ID (require in trust policy)" value={challenge.external_id} />
        <ProofRow label="Scanner principal (trust this)" value={challenge.scanner_principal} />
        {policy && <ProofRow label="AWS trust policy" value={policy} />}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- Attest */
function AttestDrawer({ target, onClose, onAttested }) {
  const toast = useToast();
  const [method, setMethod] = React.useState(target.attestation_method || 'OWNED');
  const [ack, setAck] = React.useState(false);
  const [typed, setTyped] = React.useState('');
  const [justification, setJustification] = React.useState('');
  const [roleArn, setRoleArn] = React.useState('');
  const [expiresAt, setExpiresAt] = React.useState('');
  const { run, busy, error } = useMutation();

  // Admin-only methods are offered only when the deployment + role permit them.
  const [caps, setCaps] = React.useState(null);
  React.useEffect(() => {
    let live = true;
    api('/me').then((m) => { if (live) setCaps(m.capabilities || {}); }).catch(() => {});
    return () => { live = false; };
  }, []);
  // Cloud accounts prove authorization by a role grant; other kinds use the standard
  // methods. CLOUD_ROLE is offered only for a CLOUD_ACCOUNT target with the switch on.
  const isCloudAccount = target.kind === 'CLOUD_ACCOUNT';
  const methods = isCloudAccount
    ? [...(caps?.cloud_role ? CLOUD_METHODS : []), 'OWNED', 'CHECKBOX', 'TYPED_CONFIRMATION',
       ...(caps?.self_attest ? ['SELF_ATTESTED'] : []), ...(caps?.break_glass ? ['BREAK_GLASS'] : [])]
    : [...METHODS, ...(caps?.self_attest ? ['SELF_ATTESTED'] : []), ...(caps?.break_glass ? ['BREAK_GLASS'] : [])];

  const isProof = PROOF_METHODS.includes(method);
  const isCloud = CLOUD_METHODS.includes(method);
  const isTyped = method === 'TYPED_CONFIRMATION';
  const isPrivileged = PRIVILEGED_METHODS.includes(method);
  const isBreakGlass = method === 'BREAK_GLASS';

  // Lazily fetch the per-target challenge the first time a proof method is picked.
  const [challenge, setChallenge] = React.useState(null);
  const [chLoading, setChLoading] = React.useState(false);
  const [chError, setChError] = React.useState(null);
  React.useEffect(() => {
    if (!(isProof || isCloud) || challenge || chLoading) return undefined;
    let live = true;
    setChLoading(true); setChError(null);
    api(`/targets/${target.id}/attestation-challenge`)
      .then((c) => { if (live) setChallenge(c); })
      .catch((e) => { if (live) setChError(e); })
      .finally(() => { if (live) setChLoading(false); });
    return () => { live = false; };
  }, [isProof, isCloud, challenge, chLoading, target.id]);

  const typedOk = !isTyped || typed.trim() === target.value;
  const justOk = !isPrivileged || justification.trim().length >= 8;
  const roleOk = !isCloud || roleArn.trim().length > 0;
  const canSubmit = ack && typedOk && justOk && roleOk && !busy;

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    const body = { method, checkbox_ack: ack };
    if (typed.trim()) body.typed_confirmation = typed.trim();
    if (isPrivileged && justification.trim()) body.justification = justification.trim();
    // CLOUD_ROLE carries the role to assume in evidence; the server assumes it with
    // the target's external ID to prove authorization.
    if (isCloud && roleArn.trim()) body.evidence = { role_arn: roleArn.trim() };
    if (expiresAt) body.expires_at = new Date(expiresAt).toISOString();
    try {
      await run(`/targets/${target.id}/attest`, { method: 'POST', body });
      toast({ title: 'Target attested', detail: `${target.value} is now scannable within an active engagement.` });
      onAttested();
    } catch { /* surfaced inline */ }
  }

  const KIcon = KIND_ICON[target.kind] || TargetIcon;
  return (
    <Drawer title="Attest target" subtitle={target.id} onClose={onClose}
      footer={<>
        <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn--primary" form="attest-form" disabled={!canSubmit}><LockIcon size={14} />{busy ? 'Attesting…' : 'Attest target'}</button>
      </>}>
      <ErrorBanner error={error} />

      {/* Target identity */}
      <div className="card" style={{ background: 'var(--surface-inset)' }}>
        <div className="card__body row" style={{ gap: 'var(--s-3)' }}>
          <div className="empty__icon" style={{ margin: 0, width: 38, height: 38, borderRadius: 11 }}><KIcon size={18} /></div>
          <div className="grow">
            <div className="mono" style={{ fontSize: 13, wordBreak: 'break-all' }}>{target.value}</div>
            <div className="row-tight" style={{ marginTop: 5 }}>
              <span className="chip">{target.kind}</span>
              <StatusBadge value={target.attestation_status} />
              {target.label && <span className="muted" style={{ fontSize: 12 }}>{target.label}</span>}
            </div>
          </div>
        </div>
      </div>

      <form id="attest-form" onSubmit={submit} className="stack">
        <div className="field">
          <label className="label">Attestation method</label>
          <select className="select" value={method} onChange={(e) => setMethod(e.target.value)}>
            {methods.map((m) => <option key={m} value={m}>{METHOD_LABEL[m]} — {m}</option>)}
          </select>
          <span className="hint">
            {isBreakGlass
              ? 'Break-glass — authorizes this target with NO ownership proof. For authorized red-team / DFIR only. Admin-only, short-lived, and recorded to the immutable audit log.'
              : isPrivileged
                ? 'Self-attest — skips live ownership proof for a recorded admin authorization. Time-boxed and audited.'
                : isCloud
                  ? 'Cloud account — grant the scanner role below, then attest. The server proves authorization by assuming it with your external ID.'
                  : isProof
                    ? 'External asset — publish the proof below, then attest. The server verifies ownership live.'
                    : 'Self-owned attestation — acknowledge authorization to record it.'}
          </span>
        </div>

        {isBreakGlass && (
          <Banner kind="warn">
            <b>Break-glass bypasses the ownership proof.</b> Only authorize targets you are
            lawfully permitted to test (owned infra, signed engagement, or an active
            incident-response mandate). This grant is logged under its own audit action
            with your justification and expires automatically.
          </Banner>
        )}

        {isPrivileged && (
          <div className="field">
            <label className="label">Authorization justification <span className="muted" style={{ textTransform: 'none', letterSpacing: 0, color: 'var(--warn-strong, var(--warn))' }}>· required</span></label>
            <textarea
              className="input" rows={3} value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder={isBreakGlass
                ? 'e.g. DFIR: contain compromised host per incident IR-77 — authorized by CISO'
                : 'e.g. Owned infra: internal staging cluster; engagement SOW-2231'}
            />
            <span className="hint">
              {justification.trim().length < 8
                ? 'Recorded verbatim in the audit trail. Minimum 8 characters.'
                : 'Recorded verbatim in the audit trail as the basis for this authorization.'}
            </span>
          </div>
        )}

        {isProof && <ProofBlock method={method} challenge={challenge} loading={chLoading} error={chError} />}

        {isCloud && (<>
          <CloudProofBlock challenge={challenge} loading={chLoading} error={chError} />
          <div className="field">
            <label className="label">Role ARN to assume <span className="muted" style={{ textTransform: 'none', letterSpacing: 0 }}>· required</span></label>
            <input className="input mono" value={roleArn} onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/SecurityOpsScanner" />
            <span className="hint">The server assumes this role with the external ID above; being able to assume it proves you granted us scoped access to this account.</span>
          </div>
        </>)}

        {isTyped && (
          <div className="field">
            <label className="label">Typed confirmation</label>
            <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={target.value} />
            {typed && !typedOk && <span className="hint" style={{ color: 'var(--danger-strong)' }}>Must match the target value exactly.</span>}
          </div>
        )}

        <label className="checkbox">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span className="box"><CheckIcon /></span>
          <span>I am authorized to test <span className="mono">{target.value}</span> and accept responsibility for scans against it.</span>
        </label>

        <div className="field">
          <label className="label">Expires at <span className="muted" style={{ textTransform: 'none', letterSpacing: 0 }}>· optional</span></label>
          <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
          <span className="hint">Leave blank for no expiry. Attestations lapse to EXPIRED after this time.</span>
        </div>
      </form>
    </Drawer>
  );
}

/* --------------------------------------------------------------- Page */
export default function Targets() {
  const { data, loading, error, reload } = useResource(() => api('/targets?limit=200'), []);
  const [params, setParams] = useSearchParams();
  const [registering, setRegistering] = React.useState(() => params.has('new'));
  const [selected, setSelected] = React.useState(null);
  const items = data?.items || [];
  const attested = items.filter((t) => t.attestation_status === 'ATTESTED').length;

  // Onboarding deep-links: ?new=1 opens the register drawer; ?attest=1 opens the
  // first not-yet-attested target's drawer (or register if none exist yet).
  const deepLinked = React.useRef(false);
  React.useEffect(() => {
    if (deepLinked.current) return;
    if (params.has('new')) { deepLinked.current = true; setRegistering(true); params.delete('new'); setParams(params, { replace: true }); return; }
    if (params.has('attest') && data) {
      deepLinked.current = true;
      const pending = items.find((t) => t.attestation_status !== 'ATTESTED');
      if (pending) setSelected(pending); else setRegistering(true);
      params.delete('attest'); setParams(params, { replace: true });
    }
  }, [data, items, params, setParams]);

  return (
    <div className="page" data-section="targets">
      <PageHead title="Authorized targets" eyebrow="Assets" icon={<TargetIcon />}
        subtitle="The registry the authorization gate consults. A target is only scannable once it passes attestation — valid, unexpired, and not revoked. External domains, URLs and IP ranges need ownership proof; self-owned assets use OWNED."
        actions={<button className="btn btn--primary" onClick={() => setRegistering(true)}><PlusIcon size={15} />Register target</button>} />

      <ErrorBanner error={error} />

      <div className="card">
        <div className="card__head">
          <TargetIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Registry</h2>
          <div className="spacer" />
          <span className="muted" style={{ fontSize: 12 }}>{attested} attested · {items.length} total</span>
        </div>
        {loading ? <SkeletonRows rows={5} cols={5} /> : items.length === 0 ? (
          <div className="card__body">
            <EmptyState icon={<TargetIcon />} title="No targets registered">
              <p className="muted">Register an asset, prove you own it, then it becomes scannable inside an active engagement.</p>
            </EmptyState>
          </div>
        ) : (
          <div className="tablewrap"><table className="tbl tbl--rows">
            <thead><tr><th>Target</th><th>Attestation</th><th>Method</th><th>Attested by</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id} {...rowActivate(() => setSelected(t), `Attest or view target ${t.value}`)}>
                  <td>
                    <div className="row-tight">
                      <KindIcon kind={t.kind} size={15} style={{ color: 'var(--faint)', flex: 'none' }} />
                      <span className="mono" style={{ wordBreak: 'break-all' }}>{t.value}</span>
                    </div>
                    <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>{t.label || t.kind}</div>
                  </td>
                  <td><StatusBadge value={t.attestation_status} /></td>
                  <td className="mono muted" style={{ fontSize: 12 }}>{t.attestation_method || '—'}</td>
                  <td className="muted" style={{ fontSize: 12 }}>{t.attested_by || '—'}</td>
                  <td className="muted" style={{ fontSize: 12 }}>
                    {t.expires_at
                      ? <span className="row-tight"><ClockIcon size={13} style={{ color: 'var(--faint)' }} />{fmtDate(t.expires_at, { time: false })}</span>
                      : '—'}
                  </td>
                  <td className="col-actions"><ChevronRightIcon size={16} style={{ color: 'var(--faint)' }} /></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>

      {registering && <RegisterDrawer onClose={() => setRegistering(false)} onCreated={() => { setRegistering(false); reload(); }} />}
      {selected && <AttestDrawer target={selected} onClose={() => setSelected(null)} onAttested={() => { setSelected(null); reload(); }} />}
    </div>
  );
}
