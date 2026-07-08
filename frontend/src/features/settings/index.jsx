/* Settings — a single scrollable page of console preferences and account tools.
 * Sections: Appearance (theme), Account (identity from /me), Agent access
 * (Personal Access Tokens — the credentials agents use against the MCP server),
 * Guides, Developer (bearer token / demo), and About. Everything is theme-safe:
 * colors come from CSS variables only, never raw hex. */
import React from 'react';
import { Link } from 'react-router-dom';
import { api, isDemo, getToken, setToken } from '../../lib/api.js';
import { useResource, useMutation } from '../../lib/hooks.js';
import { useTheme } from '../../lib/theme.js';
import { useOnboardingState } from '../onboarding';
import {
  PageHead, StatusBadge, EmptyState, SkeletonRows, ErrorBanner, Banner,
  Drawer, CopyButton, useToast, useConfirm, rowActivate,
} from '../../components/ui.jsx';
import {
  SettingsIcon, MonitorIcon, SunIcon, MoonIcon, UserIcon, KeyIcon, PlusIcon,
  LogOutIcon, HelpCircleIcon, SparkIcon, ShieldIcon, ClockIcon, ChevronRightIcon,
} from '../../components/icons.jsx';
import { fmtDate, relTime } from '../../lib/format.js';
import './settings.css';

const DEMO_ME = {
  name: 'Demo operator',
  email: 'demo@example.invalid',
  role: 'OPERATOR',
  apps: ['security-ops'],
  org: { slug: 'demo', name: 'Demo Organization' },
};

/* ------------------------------------------------------------ Appearance */
const THEME_OPTS = [
  { v: 'system', label: 'System', icon: MonitorIcon },
  { v: 'light', label: 'Light', icon: SunIcon },
  { v: 'dark', label: 'Dark', icon: MoonIcon },
];

function ThemeSegment({ value, onChange }) {
  const refs = React.useRef([]);
  const idx = THEME_OPTS.findIndex((o) => o.v === value);

  function onKey(e) {
    let next = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (idx + 1) % THEME_OPTS.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (idx - 1 + THEME_OPTS.length) % THEME_OPTS.length;
    if (next == null) return;
    e.preventDefault();
    onChange(THEME_OPTS[next].v);
    refs.current[next]?.focus();
  }

  return (
    <div className="segmented set-seg" role="radiogroup" aria-label="Theme preference" onKeyDown={onKey}>
      {THEME_OPTS.map((o, i) => {
        const active = o.v === value;
        const Icon = o.icon;
        return (
          <button
            key={o.v}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            ref={(el) => { refs.current[i] = el; }}
            className={active ? 'is-active' : ''}
            onClick={() => onChange(o.v)}
          >
            <Icon size={14} />{o.label}
          </button>
        );
      })}
    </div>
  );
}

function AppearanceSection() {
  const { preference, effective, setPreference } = useTheme();
  return (
    <section className="card">
      <div className="card__head"><SunIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Appearance</h2></div>
      <div className="card__body stack" style={{ gap: 'var(--s-4)' }}>
        <div className="field">
          <label className="label">Theme</label>
          <ThemeSegment value={preference} onChange={setPreference} />
          <span className="hint">System follows your device. Currently: <b>{effective}</b>.</span>
        </div>
      </div>
    </section>
  );
}

/* --------------------------------------------------------------- Account */
function signOut(demo) {
  if (demo) {
    try { localStorage.removeItem('secops_demo'); } catch { /* ignore */ }
    window.location.href = '/';
    return;
  }
  // oauth2-proxy clears its session cookie; the next request re-triggers SSO.
  window.location.href = '/oauth2/sign_out?rd=%2F';
}

function IdRow({ label, children }) {
  return (
    <div className="set-idrow">
      <div className="set-idrow__k">{label}</div>
      <div className="set-idrow__v">{children}</div>
    </div>
  );
}

function AccountSection() {
  const demo = isDemo();
  const { data, loading, error } = useResource(
    () => (demo ? Promise.resolve(DEMO_ME) : api('/me')),
    [demo],
  );
  const me = data;

  return (
    <section className="card">
      <div className="card__head"><UserIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Account</h2></div>
      <div className="card__body stack" style={{ gap: 'var(--s-4)' }}>
        {loading ? (
          <SkeletonRows rows={4} cols={2} />
        ) : error ? (
          <ErrorBanner error={error} />
        ) : (
          <>
            <div className="set-dl">
              <IdRow label="Name">{me?.name || '—'}</IdRow>
              <IdRow label="Email"><span className="mono">{me?.email || '—'}</span></IdRow>
              <IdRow label="Organization">
                {me?.org?.name || me?.org?.slug || '—'}
                {me?.org?.slug && <span className="muted mono" style={{ marginLeft: 8, fontSize: 12 }}>{me.org.slug}</span>}
              </IdRow>
              <IdRow label="Role">
                {me?.role ? <span className="badge badge--soft">{me.role}</span> : '—'}
              </IdRow>
              <IdRow label="Entitlements">
                {me?.apps?.length ? (
                  <div className="row-tight set-chips">
                    {me.apps.map((a) => <span key={a} className="chip">{a}</span>)}
                  </div>
                ) : <span className="muted">—</span>}
              </IdRow>
              {me?.auth_source && (
                <IdRow label="Auth source"><span className="muted mono" style={{ fontSize: 12 }}>{me.auth_source}</span></IdRow>
              )}
            </div>
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <button className="btn btn--ghost" onClick={() => signOut(demo)}>
                <LogOutIcon size={15} />{demo ? 'Exit demo mode' : 'Sign out'}
              </button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

/* -------------------------------------------------- Agent access (PATs) */
const EXPIRY_OPTS = [
  { label: 'No expiry', days: null },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
];

// Active / Revoked / Expired — derived from the token's lifecycle fields.
function patStatus(t) {
  if (t.revoked_at) return 'REVOKED';
  if (t.expires_at && new Date(t.expires_at).getTime() < Date.now()) return 'EXPIRED';
  return 'ACTIVE';
}

function NewTokenDrawer({ onClose, onDone }) {
  const toast = useToast();
  const [name, setName] = React.useState('');
  const [expiryIdx, setExpiryIdx] = React.useState(0);
  const [created, setCreated] = React.useState(null); // response incl. plaintext `token`
  const { run, busy, error } = useMutation();

  async function submit(e) {
    e.preventDefault();
    if (!name.trim() || created) return;
    const days = EXPIRY_OPTS[expiryIdx].days;
    const expires_at = days != null ? new Date(Date.now() + days * 86400000).toISOString() : null;
    try {
      const res = await run('/pats', { method: 'POST', body: { name: name.trim(), expires_at } });
      setCreated(res);
      toast({ title: 'Token created', detail: 'Copy it now — it is shown only once.' });
    } catch { /* surfaced inline */ }
  }

  function finish() { onDone(); }

  return (
    <Drawer
      title="New agent token"
      subtitle={created ? created.name : 'Personal Access Token'}
      onClose={created ? finish : onClose}
      footer={created ? (
        <button className="btn btn--primary" onClick={finish}>Done</button>
      ) : (
        <>
          <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" form="pat-form" disabled={busy || !name.trim()}>{busy ? 'Creating…' : 'Create token'}</button>
        </>
      )}
    >
      <ErrorBanner error={error} />

      {created ? (
        <div className="stack" style={{ gap: 'var(--s-4)' }}>
          <Banner kind="warn"><b>Copy it now — you won&apos;t see it again.</b> This is the only time the full token is shown. Store it in your agent&apos;s secret manager.</Banner>
          <div className="field">
            <label className="label">Token</label>
            <div className="codebox">
              <div className="code set-token" style={{ paddingRight: 44, wordBreak: 'break-all' }}>{created.token}</div>
              <div className="copy"><CopyButton text={created.token} /></div>
            </div>
          </div>
          <div className="row" style={{ justifyContent: 'flex-start' }}>
            <CopyButton text={created.token} label="Copy token" className="btn btn--primary" />
          </div>
        </div>
      ) : (
        <>
          <Banner kind="info">Agents authenticate to the MCP server with this token. It inherits <b>your</b> organization and entitlements — treat it like a password.</Banner>
          <form id="pat-form" onSubmit={submit} className="stack">
            <div className="field">
              <label className="label">Name</label>
              <input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Claude Code · CI runner · research agent" />
              <span className="hint">A label so you can recognize and revoke it later.</span>
            </div>
            <div className="field">
              <label className="label">Expiry</label>
              <select className="select" value={expiryIdx} onChange={(e) => setExpiryIdx(Number(e.target.value))}>
                {EXPIRY_OPTS.map((o, i) => <option key={o.label} value={i}>{o.label}</option>)}
              </select>
              <span className="hint">Expired tokens are rejected automatically. Leave as “No expiry” for long-lived agents.</span>
            </div>
          </form>
        </>
      )}
    </Drawer>
  );
}

function PatSection() {
  const demo = isDemo();
  const toast = useToast();
  const confirm = useConfirm();
  const { data, loading, error, reload } = useResource(
    () => (demo ? Promise.resolve({ items: [], total: 0 }) : api('/pats')),
    [demo],
  );
  const [minting, setMinting] = React.useState(false);
  const [revokingId, setRevokingId] = React.useState(null);
  const items = data?.items || [];

  async function revoke(t) {
    const ok = await confirm({
      title: 'Revoke token?',
      body: `“${t.name}” will stop working immediately. Any agent using it loses access to the MCP server. This cannot be undone.`,
      confirmLabel: 'Revoke token',
      danger: true,
    });
    if (!ok) return;
    setRevokingId(t.id);
    try {
      await api(`/pats/${t.id}`, { method: 'DELETE' });
      toast({ title: 'Token revoked', detail: `“${t.name}” can no longer authenticate.` });
      reload();
    } catch (e) {
      toast({ kind: 'danger', title: 'Could not revoke token', detail: e.message });
    } finally {
      setRevokingId(null);
    }
  }

  return (
    <section className="card">
      <div className="card__head">
        <KeyIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Agent access</h2>
        <div className="spacer" />
        {!demo && (
          <button className="btn btn--primary btn--sm" onClick={() => setMinting(true)}><PlusIcon size={14} />New token</button>
        )}
      </div>

      {demo ? (
        <div className="card__body">
          <Banner kind="info">Personal Access Tokens require a signed-in operator session. Sign in to mint tokens that agents can use against the MCP server.</Banner>
        </div>
      ) : (
        <>
          <div className="card__body" style={{ paddingBottom: items.length || loading ? 'var(--s-3)' : 'var(--s-5)' }}>
            <p className="hint" style={{ margin: 0 }}>
              These are the credentials agents present to the <b>MCP server</b>. Each token inherits your organization and entitlements — server-side gate and RLS still apply.
            </p>
          </div>
          <ErrorBanner error={error} />
          {loading ? (
            <SkeletonRows rows={3} cols={4} />
          ) : items.length === 0 ? (
            <div className="card__body" style={{ paddingTop: 0 }}>
              <EmptyState icon={<KeyIcon />} title="No agent tokens yet">
                <p className="muted">Mint a token so an agent can authenticate to the MCP server on your behalf — it inherits your org and entitlements.</p>
                <button className="btn btn--primary" style={{ marginTop: 'var(--s-4)' }} onClick={() => setMinting(true)}><PlusIcon size={14} />New token</button>
              </EmptyState>
            </div>
          ) : (
            <div className="tablewrap"><table className="tbl tbl--rows">
              <thead><tr><th>Name</th><th>Token</th><th>Scopes</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {items.map((t) => {
                  const status = patStatus(t);
                  const active = status === 'ACTIVE';
                  return (
                    <tr key={t.id}>
                      <td><div className="nowrap">{t.name}</div></td>
                      <td className="mono muted" style={{ fontSize: 12 }}>{t.token_prefix || 'secops_pat_'}…</td>
                      <td>
                        {t.scopes?.length ? (
                          <div className="row-tight set-chips">{t.scopes.map((s) => <span key={s} className="chip" style={{ fontSize: 10 }}>{s}</span>)}</div>
                        ) : <span className="muted">—</span>}
                      </td>
                      <td className="muted" style={{ fontSize: 12 }}>{fmtDate(t.created_at, { time: false })}</td>
                      <td className="muted" style={{ fontSize: 12 }}>
                        {t.last_used_at
                          ? <span className="row-tight"><ClockIcon size={13} style={{ color: 'var(--faint)' }} />{relTime(t.last_used_at)}</span>
                          : 'Never'}
                      </td>
                      <td><StatusBadge value={status} /></td>
                      <td className="col-actions">
                        {active ? (
                          <button className="btn btn--ghost btn--sm" disabled={revokingId === t.id} onClick={() => revoke(t)}>
                            {revokingId === t.id ? 'Revoking…' : 'Revoke'}
                          </button>
                        ) : <span className="muted" style={{ fontSize: 12 }}>—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table></div>
          )}
        </>
      )}

      {minting && (
        <NewTokenDrawer
          onClose={() => setMinting(false)}
          onDone={() => { setMinting(false); reload(); }}
        />
      )}
    </section>
  );
}

/* ---------------------------------------------------------------- Guides */
function GuidesSection() {
  const { reopen } = useOnboardingState();
  return (
    <section className="card">
      <div className="card__head"><SparkIcon size={16} style={{ color: 'var(--muted)' }} /><h2>Guides</h2></div>
      <div className="card__body stack" style={{ gap: 'var(--s-4)' }}>
        <p className="hint" style={{ margin: 0 }}>New here, or want a refresher on registering targets and launching runs?</p>
        <div className="row" style={{ gap: 'var(--s-3)' }}>
          <button className="btn" onClick={reopen}><SparkIcon size={14} />Replay setup guide</button>
          <Link to="/help" className="btn btn--ghost"><HelpCircleIcon size={14} />Help center</Link>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- Developer */
function DeveloperSection() {
  const toast = useToast();
  const demo = isDemo();
  const [open, setOpen] = React.useState(false);
  const [token, setTok] = React.useState(() => getToken());
  const saved = getToken();
  const dirty = token.trim() !== saved;

  function save() {
    setToken(token);
    toast({ title: token.trim() ? 'Bearer token saved' : 'Bearer token cleared', detail: 'Reloading to refetch with the new credentials…' });
    setTimeout(() => window.location.reload(), 400);
  }

  function exitDemo() {
    try { localStorage.removeItem('secops_demo'); } catch { /* ignore */ }
    window.location.href = '/';
  }

  return (
    <section className="card set-dev">
      <button className="set-dev__toggle" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <SettingsIcon size={15} style={{ color: 'var(--faint)' }} />
        <span className="grow">Developer</span>
        <ChevronRightIcon size={16} style={{ color: 'var(--faint)', transform: open ? 'rotate(90deg)' : 'none', transition: 'transform var(--dur-1)' }} />
      </button>
      {open && (
        <div className="card__body stack" style={{ gap: 'var(--s-5)', borderTop: '1px solid var(--border)' }}>
          <div className="field">
            <label className="label">Bearer token</label>
            <input
              className="input mono"
              type="password"
              value={token}
              onChange={(e) => setTok(e.target.value)}
              placeholder="eyJ… — for local dev / non-SSO access"
              autoComplete="off"
            />
            <span className="hint">Only for local development or non-SSO access. Stored in this browser&apos;s localStorage and sent as <span className="mono">Authorization: Bearer</span>. Behind SSO you don&apos;t need this.</span>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <button className="btn btn--primary" disabled={!dirty} onClick={save}>{token.trim() ? 'Save & reload' : 'Clear & reload'}</button>
          </div>

          <div className="set-idrow" style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--s-4)' }}>
            <div className="set-idrow__k">Demo mode</div>
            <div className="set-idrow__v row" style={{ justifyContent: 'space-between' }}>
              {demo
                ? <span className="badge badge--warn"><span className="dot" style={{ color: 'var(--warn)' }} />On</span>
                : <span className="muted">Off</span>}
              {demo && <button className="btn btn--ghost btn--sm" onClick={exitDemo}>Exit demo</button>}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

/* ----------------------------------------------------------------- About */
function AboutSection() {
  return (
    <section className="card">
      <div className="card__head"><ShieldIcon size={16} style={{ color: 'var(--muted)' }} /><h2>About</h2></div>
      <div className="card__body stack" style={{ gap: 6 }}>
        <div className="row-tight"><b style={{ fontSize: 15 }}>Security-Ops</b></div>
        <p className="text-2" style={{ margin: 0 }}>Autonomous authorized penetration testing — Unicorn Commander.</p>
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>The authorization gate is server-enforced: no scan runs against a target that hasn&apos;t passed attestation, regardless of what the console shows.</p>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ Page */
export default function Settings() {
  return (
    <div className="page set-page" data-section="settings">
      <PageHead
        title="Settings"
        eyebrow="Console"
        icon={<SettingsIcon />}
        subtitle="Appearance, your account and organization, agent access tokens, and developer options."
      />
      <div className="stack set-stack">
        <AppearanceSection />
        <AccountSection />
        <PatSection />
        <GuidesSection />
        <DeveloperSection />
        <AboutSection />
      </div>
    </div>
  );
}
