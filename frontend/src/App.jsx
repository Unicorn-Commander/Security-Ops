import React from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Sidebar, Topbar } from './components/Shell.jsx';
import { ToastProvider, ConfirmProvider } from './components/ui.jsx';
import Overview from './pages/Overview.jsx';
import Engagements from './pages/Engagements.jsx';
import Targets from './pages/Targets.jsx';
import Runs from './pages/Runs.jsx';
import RunDetail from './pages/RunDetail.jsx';
import Findings from './pages/Findings.jsx';

export default function App() {
  const [menuOpen, setMenuOpen] = React.useState(false);
  const loc = useLocation();
  React.useEffect(() => { setMenuOpen(false); }, [loc.pathname]);

  return (
    <ToastProvider>
      <ConfirmProvider>
      <div className="shell">
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
              <Route path="*" element={<div className="page"><div className="card"><div className="card__body">Not found.</div></div></div>} />
            </Routes>
          </main>
        </div>
      </div>
      </ConfirmProvider>
    </ToastProvider>
  );
}
