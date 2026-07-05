import React from 'react';
import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Engagements from './pages/Engagements.jsx';
import Targets from './pages/Targets.jsx';
import RunView from './pages/RunView.jsx';

// The backend validates a Keycloak Bearer JWT (realm `uchub`) + the
// `security-ops` entitlement SKU. In dev, the backend honors SECOPS_AUTH_BYPASS
// (environment=development) so no token is required. This control lets an
// operator paste a real Bearer token when pointing at an auth-enforcing backend;
// pages read it from localStorage('secops_token') for the Authorization header.
function TokenControl() {
  const [token, setToken] = React.useState(() => localStorage.getItem('secops_token') || '');
  const [saved, setSaved] = React.useState(false);

  function save() {
    const t = token.trim();
    if (t) localStorage.setItem('secops_token', t);
    else localStorage.removeItem('secops_token');
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1500);
  }

  return (
    <div className="row" title="Bearer token for the Security-Ops API. Leave empty when the backend runs in dev auth-bypass mode.">
      <input
        className="input token-input"
        type="password"
        placeholder="Bearer token (optional in dev)"
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />
      <button className="btn btn-ghost btn-sm" onClick={save}>{saved ? 'Saved' : 'Set'}</button>
    </div>
  );
}

const linkClass = ({ isActive }) => (isActive ? 'nav-link active' : 'nav-link');

export default function App() {
  return (
    <div>
      <header className="app-header">
        <div className="brand">Security-Ops <small>authorized pentest gate</small></div>
        <nav className="nav">
          <NavLink to="/engagements" className={linkClass}>Engagements</NavLink>
          <NavLink to="/targets" className={linkClass}>Targets</NavLink>
          <NavLink to="/runs" className={linkClass}>Runs</NavLink>
        </nav>
        <div className="spacer" />
        <TokenControl />
      </header>

      <main className="container">
        <Routes>
          <Route path="/" element={<Navigate to="/engagements" replace />} />
          <Route path="/engagements" element={<Engagements />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/runs" element={<RunView />} />
          <Route path="/runs/:runId" element={<RunView />} />
          <Route path="*" element={<div className="card">Not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}
