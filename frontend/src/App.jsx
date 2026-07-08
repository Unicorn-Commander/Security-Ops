import React from 'react';
import { Routes, Route, Navigate, useLocation, Link } from 'react-router-dom';
import { Sidebar, Topbar } from './components/Shell.jsx';
import { ToastProvider, ConfirmProvider, EmptyState } from './components/ui.jsx';
import { SearchIcon, GridIcon } from './components/icons.jsx';
import Overview from './pages/Overview.jsx';
import Engagements from './pages/Engagements.jsx';
import Targets from './pages/Targets.jsx';
import Runs from './pages/Runs.jsx';
import RunDetail from './pages/RunDetail.jsx';
import Findings from './pages/Findings.jsx';
import Help from './features/help';
import Settings from './features/settings';
import AssistantDock from './features/assistant';
import OnboardingFlow, { useOnboardingState } from './features/onboarding';
import { useKeyboardShortcuts } from './lib/shortcuts.js';

function NotFound() {
  return (
    <div className="page">
      <div className="card"><div className="card__body" style={{ padding: 'var(--s-8) var(--s-6)' }}>
        <EmptyState icon={<SearchIcon />} title="Page not found">
          That route doesn’t exist in the console.
          <div style={{ marginTop: 'var(--s-4)' }}>
            <Link to="/overview" className="btn btn--primary"><GridIcon size={14} />Back to Overview</Link>
          </div>
        </EmptyState>
      </div></div>
    </div>
  );
}

export default function App() {
  const [menuOpen, setMenuOpen] = React.useState(false);
  const loc = useLocation();
  React.useEffect(() => { setMenuOpen(false); }, [loc.pathname]);
  useKeyboardShortcuts();
  const { shouldShow, dismiss } = useOnboardingState();

  return (
    <ToastProvider>
      <ConfirmProvider>
      <div className="shell">
        {menuOpen && <div className="shell__scrim" onClick={() => setMenuOpen(false)} aria-hidden="true" />}
        <Sidebar open={menuOpen} onNavigate={() => setMenuOpen(false)} />
        <div className="content">
          <Topbar onMenu={() => setMenuOpen((o) => !o)} />
          <main>
            <Routes>
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/engagements" element={<Engagements />} />
              <Route path="/targets" element={<Targets />} />
              <Route path="/runs" element={<Runs />} />
              <Route path="/runs/:runId" element={<RunDetail />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/help" element={<Help />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
      </div>
      {shouldShow && <OnboardingFlow onClose={dismiss} />}
      <AssistantDock />
      </ConfirmProvider>
    </ToastProvider>
  );
}
