/* Theme controller — light / dark / system, persisted, no flash.
 *
 * The user's PREFERENCE is one of 'system' | 'light' | 'dark' (default 'system').
 * The EFFECTIVE theme (what actually paints) resolves 'system' against the OS via
 * matchMedia. We stamp `data-theme="light|dark"` + `color-scheme` on <html> so the
 * CSS in tokens.css swaps; an inline script in index.html does the same before
 * first paint (no dark→light flash). The <html> attribute is always an explicit
 * 'light'/'dark', so tokens.css only needs a `[data-theme="light"]` block. */
import React from 'react';

const KEY = 'secops_theme';
const VALID = new Set(['system', 'light', 'dark']);

function media() {
  try { return window.matchMedia('(prefers-color-scheme: light)'); } catch { return null; }
}

export function getPreference() {
  try {
    const v = localStorage.getItem(KEY);
    return VALID.has(v) ? v : 'system';
  } catch { return 'system'; }
}

export function resolveTheme(pref) {
  if (pref === 'light' || pref === 'dark') return pref;
  const m = media();
  return m && m.matches ? 'light' : 'dark';
}

export function applyTheme(pref) {
  const effective = resolveTheme(pref);
  const el = document.documentElement;
  el.dataset.theme = effective;
  el.style.colorScheme = effective;
  return effective;
}

/** React hook: `{ preference, effective, setPreference }`. */
export function useTheme() {
  const [preference, setPref] = React.useState(getPreference);
  const [effective, setEffective] = React.useState(() => resolveTheme(getPreference()));

  React.useEffect(() => {
    setEffective(applyTheme(preference));
    try { localStorage.setItem(KEY, preference); } catch { /* ignore */ }
    if (preference !== 'system') return undefined;
    // Follow the OS while on 'system'.
    const m = media();
    if (!m) return undefined;
    const onChange = () => setEffective(applyTheme('system'));
    m.addEventListener('change', onChange);
    return () => m.removeEventListener('change', onChange);
  }, [preference]);

  const setPreference = React.useCallback((p) => setPref(VALID.has(p) ? p : 'system'), []);
  return { preference, effective, setPreference };
}
