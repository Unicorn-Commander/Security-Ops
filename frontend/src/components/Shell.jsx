/* App shell: sidebar navigation + topbar. The sidebar carries live section counts
 * and the signature "authorization gate armed" indicator — the product's identity. */
import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { GridIcon, ShieldIcon, TargetIcon, PlayIcon, BugIcon, LockIcon, MenuIcon, KeyIcon } from './icons.jsx';
import { isDemo, getToken, setToken } from '../lib/api.js';
import { useResource } from '../lib/hooks.js';
import { api } from '../lib/api.js';

const NAV = [
  { to: '/overview', label: 'Overview', icon: GridIcon, key: null },
  { to: '/engagements', label: 'Engagements', icon: ShieldIcon, key: 'engagements' },
  { to: '/targets', label: 'Targets', icon: TargetIcon, key: 'targets' },
  { to: '/runs', label: 'Runs', icon: PlayIcon, key: 'runs' },
  { to: '/findings', label: 'Findings', icon: BugIcon, key: 'findings' },
];

function GateBadge() {
  return (
    <div style={{ position: 'relative', overflow: 'hidden', border: '1px solid var(--border-2)', borderRadius: 'var(--r)', padding: '11px 12px', background: 'linear-gradient(180deg, rgba(47,206,143,0.06), transparent)' }}>
      <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}>
        <div style={{ position: 'absolute', left: 0, right: 0, height: 40, background: 'linear-gradient(180deg, transparent, rgba(47,206,143,0.10), transparent)', animation: 'so-scan 3.4s var(--ease) infinite' }} />
      </div>
      <div className="row-tight" style={{ position: 'relative' }}>
        <LockIcon size={15} style={{ color: 'var(--ok)' }} />
        <div style={{ lineHeight: 1.25 }}>
          <div style={{ fontSize: 12, fontWeight: 620, color: 'var(--text)' }}>Authorization gate</div>
          <div className="statusdot" style={{ fontSize: 11 }}><i className="live" style={{ background: 'var(--ok)', boxShadow: '0 0 0 3px var(--ok-soft)' }} />Armed · server-enforced</div>
        </div>
      </div>
    </div>
  );
}

function TokenControl() {
  const [open, setOpen] = React.useState(false);
  const [val, setVal] = React.useState(getToken());
  const demo = isDemo();
  return (
    <div style={{ position: 'relative' }}>
      <button className="btn btn--sm btn--ghost" onClick={() => setOpen((o) => !o)} title="API auth">
        <KeyIcon size={14} />{demo ? 'Demo mode' : getToken() ? 'Token set' : 'Auth'}
      </button>
      {open && (
        <div className="card" style={{ position: 'absolute', right: 0, top: 40, width: 300, zIndex: 40, padding: 14 }}>
          <div className="field">
            <label className="label">Bearer token</label>
            <input className="input mono" type="password" placeholder="Optional in dev / demo" value={val} onChange={(e) => setVal(e.target.value)} />
            <div className="hint">Keycloak (realm uchub) JWT with the <span className="mono">security-ops</span> entitlement. Left blank in dev auth-bypass or demo mode.</div>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end', marginTop: 10 }}>
            <button className="btn btn--sm btn--primary" onClick={() => { setToken(val); setOpen(false); }}>Save</button>
          </div>
        </div>
      )}
    </div>
  );
}

export function Sidebar({ open, onNavigate }) {
  const { data } = useResource(() => api('/overview'), []);
  const counts = {
    engagements: data?.engagements?.total,
    targets: data?.targets?.total,
    runs: data?.runs?.total,
    findings: data?.findings?.open,
  };
  return (
    <aside className={`sidebar ${open ? 'is-open' : ''}`}>
      <div className="sidebar__brand">
        <div className="sidebar__logo"><ShieldIcon size={19} strokeWidth={2} /></div>
        <div className="sidebar__title">Security-Ops<small>Authorized pentest console</small></div>
      </div>
      <nav className="nav" aria-label="Primary">
        <div className="nav__label">Operations</div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} onClick={onNavigate} className={({ isActive }) => `nav__link ${isActive ? 'is-active' : ''}`}>
            <n.icon />
            <span className="grow">{n.label}</span>
            {n.key && counts[n.key] != null && <span className="nav__count">{counts[n.key]}</span>}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar__foot"><GateBadge /></div>
    </aside>
  );
}

export function Topbar({ onMenu }) {
  const loc = useLocation();
  const section = NAV.find((n) => loc.pathname.startsWith(n.to));
  return (
    <header className="topbar">
      <button className="iconbtn topbar__menu" onClick={onMenu} aria-label="Menu"><MenuIcon /></button>
      <div className="topbar__crumbs">
        <span>Security-Ops</span>
        <span className="faint">/</span>
        <b>{section ? section.label : 'Console'}</b>
      </div>
      <div className="topbar__spacer" />
      {isDemo() && <span className="badge badge--accent"><span className="dot" />Demo data</span>}
      <TokenControl />
    </header>
  );
}
