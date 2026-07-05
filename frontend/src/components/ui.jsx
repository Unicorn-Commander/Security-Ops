/* Shared UI primitives for the Security-Ops console. */
import React from 'react';
import { CheckIcon, XIcon, CopyIcon, AlertIcon, CircleCheckIcon, InfoIcon, SearchIcon } from './icons.jsx';
import { titleCase } from '../lib/format.js';

/* ---- Status → visual mapping (engagements, runs, attestation, findings) ---- */
const STATUS_META = {
  // engagement
  DRAFT: { cls: 'badge--neutral', dot: 'var(--muted)' },
  ACTIVE: { cls: 'badge--ok', dot: 'var(--ok)', live: false },
  PAUSED: { cls: 'badge--warn', dot: 'var(--warn)' },
  COMPLETED: { cls: 'badge--info', dot: 'var(--info)' },
  STOPPED: { cls: 'badge--danger', dot: 'var(--danger)' },
  EXPIRED: { cls: 'badge--neutral', dot: 'var(--muted)' },
  // run
  PENDING: { cls: 'badge--warn', dot: 'var(--warn)' },
  RUNNING: { cls: 'badge--info', dot: 'var(--info)', live: true },
  FAILED: { cls: 'badge--danger', dot: 'var(--danger)' },
  DENIED: { cls: 'badge--danger', dot: 'var(--danger)' },
  // attestation
  ATTESTED: { cls: 'badge--ok', dot: 'var(--ok)' },
  UNATTESTED: { cls: 'badge--neutral', dot: 'var(--muted)' },
  REVOKED: { cls: 'badge--danger', dot: 'var(--danger)' },
  // finding status
  NEW: { cls: 'badge--info', dot: 'var(--info)' },
  VERIFIED: { cls: 'badge--accent', dot: 'var(--accent-strong)' },
  HANDED_OFF: { cls: 'badge--ok', dot: 'var(--ok)' },
  REMEDIATED: { cls: 'badge--ok', dot: 'var(--ok)' },
  FALSE_POSITIVE: { cls: 'badge--neutral', dot: 'var(--muted)' },
};

export function StatusBadge({ value }) {
  const m = STATUS_META[value] || { cls: 'badge--neutral', dot: 'var(--muted)' };
  return (
    <span className={`badge ${m.cls} ${m.live ? 'badge--live' : ''}`}>
      <span className="dot" style={{ color: m.dot }} />
      {titleCase(value)}
    </span>
  );
}

const SEV_CLS = { INFO: 'sev--info', LOW: 'sev--low', MEDIUM: 'sev--medium', HIGH: 'sev--high', CRITICAL: 'sev--critical' };
export function Severity({ value }) {
  return <span className={`sev ${SEV_CLS[value] || 'sev--info'}`}><span className="bar" />{titleCase(value)}</span>;
}
export const SEV_VAR = { INFO: 'var(--sev-info)', LOW: 'var(--sev-low)', MEDIUM: 'var(--sev-medium)', HIGH: 'var(--sev-high)', CRITICAL: 'var(--sev-critical)' };

/* ---- Copy button ---- */
export function CopyButton({ text, label, className = 'iconbtn' }) {
  const [done, setDone] = React.useState(false);
  async function copy() {
    try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
    setDone(true); setTimeout(() => setDone(false), 1400);
  }
  return (
    <button className={className} onClick={copy} title="Copy" type="button" aria-label={done ? 'Copied' : `Copy${label ? ' ' + label : ''}`}>
      {done ? <CheckIcon size={15} style={{ color: 'var(--ok)' }} /> : <CopyIcon size={15} />}
      {label && <span style={{ marginLeft: 6, fontSize: 12 }}>{done ? 'Copied' : label}</span>}
      <span aria-live="polite" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>{done ? 'Copied to clipboard' : ''}</span>
    </button>
  );
}

/* ---- Banner ---- */
export function Banner({ kind = 'info', children }) {
  const Icon = kind === 'danger' ? AlertIcon : kind === 'ok' ? CircleCheckIcon : InfoIcon;
  return <div className={`banner banner--${kind}`}><Icon /><div className="grow">{children}</div></div>;
}
export function ErrorBanner({ error }) {
  if (!error) return null;
  return (
    <Banner kind="danger">
      <div><b>{titleCase(error.code || 'error')}</b> — {error.message}</div>
      {error.detail && <pre className="code" style={{ marginTop: 8 }}>{typeof error.detail === 'string' ? error.detail : JSON.stringify(error.detail, null, 2)}</pre>}
    </Banner>
  );
}

/* ---- Empty state ---- */
export function EmptyState({ icon, title, children }) {
  return (
    <div className="empty">
      <div className="empty__icon">{icon || <SearchIcon />}</div>
      <h3>{title}</h3>
      {children && <div style={{ maxWidth: '42ch', margin: '0 auto' }}>{children}</div>}
    </div>
  );
}

/* ---- Skeleton table rows ---- */
export function SkeletonRows({ rows = 5, cols = 5 }) {
  return (
    <div style={{ padding: 'var(--s-2) 0' }}>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="row" style={{ padding: '12px 14px', gap: 24, borderBottom: '1px solid var(--border)' }}>
          {Array.from({ length: cols }).map((__, c) => (
            <div key={c} className="skel" style={{ height: 12, flex: c === 0 ? 2 : 1, borderRadius: 6 }} />
          ))}
        </div>
      ))}
    </div>
  );
}

/* ---- Stat tile ---- */
export function Tile({ label, icon, value, sub, accent, children }) {
  return (
    <div className={`tile ${accent ? 'tile--accent' : ''}`}>
      <div className="tile__label">{icon}{label}</div>
      {value != null && <div className="tile__value">{value}</div>}
      {children}
      {sub && <div className="tile__foot">{sub}</div>}
    </div>
  );
}

/* ---- Horizontal distribution bars ---- */
export function Bars({ data }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="bars">
      {data.map((d) => (
        <div className="bars__row" key={d.label}>
          <div className="row-tight" style={{ color: 'var(--text-2)' }}>
            {d.swatch && <span style={{ width: 8, height: 8, borderRadius: 3, background: d.swatch, flex: 'none' }} />}
            <span className="nowrap">{d.label}</span>
          </div>
          <div className="bars__track"><div className="bars__fill" style={{ width: `${(d.value / max) * 100}%`, background: d.color || 'var(--accent)' }} /></div>
          <div className="bars__val tnum">{d.value}</div>
        </div>
      ))}
    </div>
  );
}

/* ---- Stacked meter ---- */
export function Meter({ segments }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const label = segments.filter((s) => s.value > 0).map((s) => `${s.value} ${s.label.toLowerCase()}`).join(', ') || 'no data';
  return (
    <div className="meter" role="img" aria-label={`Distribution: ${label}`}>
      {segments.filter((s) => s.value > 0).map((s) => (
        <span key={s.label} title={`${s.label}: ${s.value}`} style={{ width: `${(s.value / total) * 100}%`, background: s.color }} />
      ))}
    </div>
  );
}

/* ---- Drawer (focus-trapped, focus-returning, labelled dialog) ---- */
let _drawerSeq = 0;
export function Drawer({ title, subtitle, onClose, children, footer }) {
  const panelRef = React.useRef(null);
  const titleRef = React.useRef(null);
  const titleId = React.useMemo(() => `drawer-title-${++_drawerSeq}`, []);

  React.useEffect(() => {
    const restoreTo = document.activeElement;
    document.body.style.overflow = 'hidden';
    // Move focus into the dialog (its heading) on open.
    const t = setTimeout(() => { titleRef.current?.focus(); }, 0);

    const onKey = (e) => {
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key !== 'Tab') return;
      // Trap Tab within the panel.
      const panel = panelRef.current;
      if (!panel) return;
      const items = panel.querySelectorAll('a[href], button:not([disabled]), textarea, input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])');
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(t);
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
      // Return focus to whatever opened the drawer.
      if (restoreTo && typeof restoreTo.focus === 'function') restoreTo.focus();
    };
  }, [onClose]);

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" ref={panelRef} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="drawer__head">
          <div className="drawer__head-main">
            <div className="drawer__title" id={titleId} ref={titleRef} tabIndex={-1} style={{ outline: 'none' }}>{title}</div>
            {subtitle && <div className="muted mono" style={{ marginTop: 4, fontSize: 12 }}>{subtitle}</div>}
          </div>
          <button className="iconbtn" onClick={onClose} aria-label="Close panel"><XIcon /></button>
        </div>
        <div className="drawer__body">{children}</div>
        {footer && <div className="drawer__foot">{footer}</div>}
      </aside>
    </>
  );
}

/* ---- Keyboard-operable table row: spread onto a clickable <tr> ---- */
export function rowActivate(onClick, label) {
  return {
    onClick,
    role: 'button',
    tabIndex: 0,
    'aria-label': label,
    onKeyDown: (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(e); }
    },
  };
}

/* ---- Toasts ---- */
const ToastCtx = React.createContext(() => {});
export const useToast = () => React.useContext(ToastCtx);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = React.useState([]);
  const push = React.useCallback((t) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((xs) => [...xs, { id, kind: 'ok', ...t }]);
    setTimeout(() => setToasts((xs) => xs.filter((x) => x.id !== id)), t.duration || 4200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toaster">
        {toasts.map((t) => {
          const Icon = t.kind === 'danger' ? AlertIcon : t.kind === 'info' ? InfoIcon : CircleCheckIcon;
          return (
            <div key={t.id} className={`toast toast--${t.kind}`}>
              <Icon className="toast__icon" />
              <div className="toast__msg">{t.title}{t.detail && <small>{t.detail}</small>}</div>
            </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}

/* ---- Confirm dialog (in-app; for destructive / high-stakes actions) ---- */
const ConfirmCtx = React.createContext(async () => true);
export const useConfirm = () => React.useContext(ConfirmCtx);

export function ConfirmProvider({ children }) {
  const [state, setState] = React.useState(null);
  const resolver = React.useRef(null);
  const confirm = React.useCallback((opts) => new Promise((resolve) => { resolver.current = resolve; setState(opts || {}); }), []);
  const close = React.useCallback((val) => { setState(null); if (resolver.current) { resolver.current(val); resolver.current = null; } }, []);

  React.useEffect(() => {
    if (!state) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') close(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [state, close]);

  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      {state && (
        <>
          <div className="scrim" onClick={() => close(false)} />
          <div className="modal" role="alertdialog" aria-modal="true" aria-label={state.title || 'Confirm'}>
            <div style={{ padding: 'var(--s-5)' }}>
              <div className="row-tight" style={{ marginBottom: 12 }}>
                <div style={{ width: 34, height: 34, borderRadius: 10, display: 'grid', placeItems: 'center', flex: 'none', background: state.danger ? 'var(--danger-soft)' : 'var(--accent-soft)', color: state.danger ? 'var(--danger-strong)' : 'var(--accent-strong)' }}>
                  {state.danger ? <AlertIcon size={18} /> : <CircleCheckIcon size={18} />}
                </div>
                <div className="drawer__title">{state.title}</div>
              </div>
              {state.body && <p className="text-2" style={{ lineHeight: 1.6 }}>{state.body}</p>}
              <div className="row" style={{ justifyContent: 'flex-end', marginTop: 'var(--s-6)' }}>
                <button className="btn btn--ghost" onClick={() => close(false)}>{state.cancelLabel || 'Cancel'}</button>
                <button className={`btn ${state.danger ? 'btn--danger' : 'btn--primary'}`} autoFocus onClick={() => close(true)}>{state.confirmLabel || 'Confirm'}</button>
              </div>
            </div>
          </div>
        </>
      )}
    </ConfirmCtx.Provider>
  );
}

/* ---- Page header ---- */
export function PageHead({ title, badge, subtitle, actions }) {
  return (
    <div className="page__head">
      <div className="page__head-main">
        <div className="page__title"><h1 className="display" style={{ fontSize: 24 }}>{title}</h1>{badge}</div>
        {subtitle && <p className="page__sub">{subtitle}</p>}
      </div>
      {actions && <div className="page__actions">{actions}</div>}
    </div>
  );
}
