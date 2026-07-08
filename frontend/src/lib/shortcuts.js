/* Global keyboard shortcuts — the set documented in the Help center.
 *
 *   ?            open Help
 *   g then o/e/t/r/f   go to Overview / Engagements / Targets / Runs / Findings
 *   /            focus the search/filter box on the current view, if it has one
 *
 * (Enter to open a focused row, and Esc/Tab inside drawers, are handled locally
 * by the row/drawer components.) Shortcuts are ignored while typing in an input,
 * textarea, select, or contenteditable, and when a modifier (⌘/Ctrl/Alt) is held. */
import React from 'react';
import { useNavigate } from 'react-router-dom';

const GO = { o: '/overview', e: '/engagements', t: '/targets', r: '/runs', f: '/findings' };
const CHORD_MS = 900;

function isTypingTarget(el) {
  if (!el) return false;
  const tag = el.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
}

export function useKeyboardShortcuts() {
  const navigate = useNavigate();
  const lastG = React.useRef(0);

  React.useEffect(() => {
    function onKey(e) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(document.activeElement)) return;
      const k = e.key;

      // `g` arms a navigation chord; the next key within CHORD_MS selects a view.
      if (lastG.current && Date.now() - lastG.current < CHORD_MS) {
        lastG.current = 0;
        const dest = GO[k.toLowerCase()];
        if (dest) { e.preventDefault(); navigate(dest); return; }
      }
      if (k === 'g') { lastG.current = Date.now(); return; }
      lastG.current = 0;

      if (k === '?') { e.preventDefault(); navigate('/help'); return; }
      if (k === '/') {
        const box = document.querySelector('input[data-search], input[type="search"]');
        if (box) { e.preventDefault(); box.focus(); }
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate]);
}
