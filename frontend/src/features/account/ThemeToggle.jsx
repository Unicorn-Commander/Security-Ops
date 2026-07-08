/* Topbar one-click light/dark toggle. The full three-way choice (incl. System)
 * lives in Settings › Appearance; this is the fast path. */
import React from 'react';
import { useTheme } from '../../lib/theme.js';
import { SunIcon, MoonIcon } from '../../components/icons.jsx';
import { Tooltip } from '../../components/ui.jsx';

export default function ThemeToggle() {
  const { effective, setPreference } = useTheme();
  const toLight = effective === 'dark';
  return (
    <Tooltip label={toLight ? 'Switch to light theme' : 'Switch to dark theme'} place="below">
      <button
        className="iconbtn"
        aria-label={toLight ? 'Switch to light theme' : 'Switch to dark theme'}
        onClick={() => setPreference(toLight ? 'light' : 'dark')}
      >
        {toLight ? <SunIcon size={17} /> : <MoonIcon size={17} />}
      </button>
    </Tooltip>
  );
}
