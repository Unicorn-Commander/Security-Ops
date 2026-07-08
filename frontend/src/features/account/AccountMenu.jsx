/* Topbar account menu: who am I / which org / entitlement, plus links to Settings
 * and Help, and Sign out. Identity comes from GET /api/v1/me (the browser only
 * holds an opaque session cookie — the ID token is server-side). In demo mode it
 * shows a demo persona and "Exit demo" instead of a real SSO sign-out. */
import React from 'react';
import { Link } from 'react-router-dom';
import { api, isDemo } from '../../lib/api.js';
import { useResource } from '../../lib/hooks.js';
import { UserIcon, SettingsIcon, HelpCircleIcon, LogOutIcon, ChevronRightIcon } from '../../components/icons.jsx';

const DEMO_ME = {
  name: 'Demo operator',
  email: 'demo@example.invalid',
  role: 'OPERATOR',
  apps: ['security-ops'],
  org: { slug: 'demo', name: 'Demo Organization' },
};

function initials(name, email) {
  const src = (name || email || '?').trim();
  const parts = src.split(/[\s@._-]+/).filter(Boolean);
  const chars = parts.length >= 2 ? parts[0][0] + parts[1][0] : src.slice(0, 2);
  return chars.toUpperCase();
}

function signOut() {
  if (isDemo()) {
    try { localStorage.removeItem('secops_demo'); } catch { /* ignore */ }
    window.location.href = '/';
    return;
  }
  // oauth2-proxy clears its session cookie; the next request re-triggers SSO.
  window.location.href = '/oauth2/sign_out?rd=%2F';
}

export default function AccountMenu() {
  const demo = isDemo();
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  const btnRef = React.useRef(null);

  // Fetch identity only outside demo mode (demo has no /me backend).
  const { data, error } = useResource(() => (demo ? Promise.resolve(DEMO_ME) : api('/me')), [demo]);
  const me = data || (demo ? DEMO_ME : null);

  React.useEffect(() => {
    if (!open) return undefined;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === 'Escape') { setOpen(false); btnRef.current?.focus(); } };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); };
  }, [open]);

  const name = me?.name || (me?.email ? me.email.split('@')[0] : 'Account');
  const email = me?.email || (error ? 'Signed in' : '—');

  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <button
        ref={btnRef}
        className="acct__btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="acct__avatar" aria-hidden="true">{initials(me?.name, me?.email)}</span>
        <span className="acct__name">{name}</span>
        <ChevronRightIcon size={14} style={{ transform: 'rotate(90deg)', opacity: 0.6 }} />
      </button>

      {open && (
        <div className="acct__menu card" role="menu" aria-label="Account">
          <div className="acct__head">
            <span className="acct__avatar acct__avatar--lg" aria-hidden="true">{initials(me?.name, me?.email)}</span>
            <div style={{ minWidth: 0 }}>
              <div className="acct__head-name">{name}</div>
              <div className="acct__head-mail" title={email}>{email}</div>
            </div>
          </div>
          <div className="acct__org">
            <div className="row-tight" style={{ justifyContent: 'space-between' }}>
              <span className="muted" style={{ fontSize: 11 }}>Organization</span>
              {me?.role && <span className="badge badge--soft" style={{ fontSize: 10 }}>{me.role}</span>}
            </div>
            <div className="acct__org-name">{me?.org?.name || me?.org?.slug || '—'}</div>
            {me?.apps?.length ? (
              <div className="row-tight" style={{ flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                {me.apps.map((a) => <span key={a} className="chip" style={{ fontSize: 10 }}>{a}</span>)}
              </div>
            ) : null}
          </div>
          <div className="acct__sep" />
          <Link to="/settings" role="menuitem" className="acct__item" onClick={() => setOpen(false)}>
            <SettingsIcon size={15} /><span className="grow">Settings</span>
          </Link>
          <Link to="/help" role="menuitem" className="acct__item" onClick={() => setOpen(false)}>
            <HelpCircleIcon size={15} /><span className="grow">Help &amp; docs</span>
          </Link>
          <div className="acct__sep" />
          <button role="menuitem" className="acct__item acct__item--danger" onClick={signOut}>
            <LogOutIcon size={15} /><span className="grow">{demo ? 'Exit demo mode' : 'Sign out'}</span>
          </button>
        </div>
      )}
    </div>
  );
}
