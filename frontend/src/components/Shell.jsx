/* App shell: sidebar navigation + topbar. The sidebar carries live section counts
 * and the signature "authorization gate armed" indicator — the product's identity. */
import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { GridIcon, ShieldIcon, TargetIcon, PlayIcon, BugIcon, LockIcon, MenuIcon, AlertIcon, XIcon } from './icons.jsx';
import { isDemo } from '../lib/api.js';
import { useResource } from '../lib/hooks.js';
import { api } from '../lib/api.js';
import { Tooltip } from './ui.jsx';
import { HelpButton } from '../features/help';
import { AccountMenu, ThemeToggle } from '../features/account';

const NAV = [
  { to: '/overview', label: 'Overview', icon: GridIcon, key: null, section: 'overview', hint: 'Live posture across the console' },
  { to: '/engagements', label: 'Engagements', icon: ShieldIcon, key: 'engagements', section: 'engagements', hint: 'Authorized scopes' },
  { to: '/targets', label: 'Targets', icon: TargetIcon, key: 'targets', section: 'targets', hint: 'Registered & attested assets' },
  { to: '/runs', label: 'Runs', icon: PlayIcon, key: 'runs', section: 'runs', hint: 'Engine executions' },
  { to: '/findings', label: 'Findings', icon: BugIcon, key: 'findings', section: 'findings', hint: 'Open findings' },
];

function GateBadge() {
  return (
    <Tooltip
      place="right"
      label="The authorization gate is enforced on the server."
      sub="No scan runs without an active, attested, unexpired scope. Every decision is written to an immutable, hash-chained audit log."
    >
      <div tabIndex={0} style={{ position: 'relative', overflow: 'hidden', border: '1px solid var(--border-2)', borderRadius: 'var(--r)', padding: '11px 12px', background: 'linear-gradient(180deg, rgba(47,206,143,0.06), transparent)', width: '100%', cursor: 'help' }}>
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
    </Tooltip>
  );
}

/* Demo-mode boundary. When the in-memory demo backend is serving fabricated data,
 * an unmistakable strip below the topbar makes clear nothing on screen is real —
 * a hard trust requirement for a security product. Theme-safe (CSS-var) colors. */
function exitDemo() {
  try { localStorage.removeItem('secops_demo'); } catch { /* ignore */ }
  window.location.assign('/');
}

export function DemoBanner() {
  if (!isDemo()) return null;
  return (
    <div className="demobar" role="status" style={{
      display: 'flex', alignItems: 'center', gap: 'var(--s-3)',
      padding: '8px var(--s-6)', fontSize: 13, color: 'var(--text)',
      background: 'var(--warn-soft)', borderBottom: '1px solid var(--warn)',
    }}>
      <AlertIcon size={15} style={{ color: 'var(--warn)', flex: 'none' }} />
      <span style={{ minWidth: 0 }}><b>Demo mode</b> — data on screen is simulated, not real.</span>
      <div style={{ flex: 1 }} />
      <button className="btn btn--sm btn--ghost" onClick={exitDemo} type="button" style={{ flex: 'none' }}><XIcon size={13} />Exit demo</button>
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
          <NavLink key={n.to} to={n.to} data-section={n.section} onClick={onNavigate} title={n.hint} className={({ isActive }) => `nav__link ${isActive ? 'is-active' : ''}`}>
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
    <>
      <header className="topbar">
        <button className="iconbtn topbar__menu" onClick={onMenu} aria-label="Menu"><MenuIcon /></button>
        <div className="topbar__crumbs">
          <span>Security-Ops</span>
          <span className="faint">/</span>
          <b>{section ? section.label : 'Console'}</b>
        </div>
        <div className="topbar__spacer" />
        {isDemo() && <span className="badge badge--accent"><span className="dot" />Demo data</span>}
        <ThemeToggle />
        <Tooltip label="Help & documentation" place="below"><HelpButton /></Tooltip>
        <AccountMenu />
      </header>
      <DemoBanner />
    </>
  );
}
