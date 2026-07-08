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
/* Ordinal rank drives the signal-bars meter: severity is encoded three ways at
 * once — hue, filled-bar count (shape), and the text label — so it survives
 * colorblindness, grayscale printing, and forced-colors mode. */
const SEV_RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
export function Severity({ value }) {
  const rank = SEV_RANK[value] || 1;
  return (
    <span className={`sev ${SEV_CLS[value] || 'sev--info'}`}>
      <span className="sevbars" aria-hidden="true">
        {[1, 2, 3, 4, 5].map((i) => <i key={i} className={i <= rank ? 'on' : ''} />)}
      </span>
      {titleCase(value)}
    </span>
  );
}
export const SEV_VAR = { INFO: 'var(--sev-info)', LOW: 'var(--sev-low)', MEDIUM: 'var(--sev-medium)', HIGH: 'var(--sev-high)', CRITICAL: 'var(--sev-critical)' };

/* ---- Confidence: how SURE the engine is, orthogonal to how BAD (severity) ----
 * The category-leading consoles split these two axes (Burp's Certain/Firm/Tentative;
 * XBOW's separate validator badge). Our verify pass writes evidence.confidence, and a
 * VERIFIED status means the finding was re-checked — that's the rare "validated" signal
 * only an autonomous engine earns. Visual grammar: severity = signal bars, status =
 * round dot, confidence = diamond — three shapes so the three axes never blur. */
const CONF_META = {
  confirmed: { label: 'Confirmed', cls: 'conf--strong' },
  high:      { label: 'High confidence', cls: 'conf--strong' },
  medium:    { label: 'Medium confidence', cls: 'conf--mid' },
  low:       { label: 'Tentative', cls: 'conf--low' },
  uncertain: { label: 'Uncertain', cls: 'conf--low' },
};
export function Confidence({ value }) {
  if (value == null || value === '') return null;
  const m = CONF_META[String(value).toLowerCase()] || { label: titleCase(String(value)), cls: 'conf--mid' };
  return (
    <span className={`conf ${m.cls}`} title="How sure the engine is this is real — separate from how severe it is.">
      <span className="conf__mark" aria-hidden="true" />{m.label}
    </span>
  );
}

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
/* `showDetail` (default false) opts a caller into rendering the raw error.detail
 * block. Keep it off for ordinary API errors — the raw JSON is meaningless and
 * alarming to customers. Turn it on only where the detail IS the message the user
 * needs (e.g. an authorization-gate / scope-denial verdict). */
export function ErrorBanner({ error, showDetail = false }) {
  if (!error) return null;
  return (
    <Banner kind="danger">
      <div><b>{titleCase(error.code || 'error')}</b> — {error.message}</div>
      {showDetail && error.detail && <pre className="code" style={{ marginTop: 8 }}>{typeof error.detail === 'string' ? error.detail : JSON.stringify(error.detail, null, 2)}</pre>}
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
export function Tile({ label, icon, value, sub, accent, section, children }) {
  return (
    <div className={`tile ${accent ? 'tile--accent' : ''} ${section ? 'tile--section' : ''}`} data-section={section || undefined}>
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

/* ---- Freshness stamp for live/streaming surfaces ----
 * A live scan should say when it last refreshed and let the analyst freeze the
 * stream to read it (benchmark: real-time-dashboard best practice — never a
 * silently-mutating list with no "as of" and no pause). `at` = last refresh
 * time; when `live`, a ticking "updated Ns ago" + a Pause/Resume toggle. */
export function FreshnessStamp({ at, live, paused, onTogglePause }) {
  const [, tick] = React.useState(0);
  React.useEffect(() => {
    if (!live || paused) return undefined;
    const id = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [live, paused]);
  const ago = at ? Math.max(0, Math.round((Date.now() - new Date(at).getTime()) / 1000)) : null;
  const agoText = ago == null ? '—' : ago < 2 ? 'just now' : ago < 60 ? `${ago}s ago` : `${Math.floor(ago / 60)}m ago`;
  return (
    <span className="freshness">
      <span className="statusdot">
        <i className={live && !paused ? 'live' : ''} style={{ background: paused ? 'var(--muted)' : live ? 'var(--info)' : 'var(--faint)' }} />
        {paused ? 'Paused' : live ? `updated ${agoText}` : `as of ${agoText}`}
      </span>
      {live && onTogglePause && (
        <button className="iconbtn freshness__toggle" onClick={onTogglePause} type="button"
          aria-pressed={paused} title={paused ? 'Resume live updates' : 'Pause live updates to read'}>
          {paused ? 'Resume' : 'Pause'}
        </button>
      )}
    </span>
  );
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

/* ---- Tooltip (hover + keyboard-focus; accessible via aria-describedby) ----
 * Wrap any focusable trigger: <Tooltip label="…"><button/></Tooltip>. Purely
 * CSS-driven show/hide (see .tt in components.css); `place` = top|right|below. */
export function Tooltip({ label, sub, place = 'top', className = '', children }) {
  const id = React.useId();
  if (label == null || label === '') return children;
  const cls = `tt ${place === 'right' ? 'tt--right' : place === 'below' ? 'tt--below' : ''} ${className}`.trim();
  const child = React.isValidElement(children)
    ? React.cloneElement(children, { 'aria-describedby': id })
    : children;
  return (
    <span className={cls}>
      {child}
      <span className="tt__pop" role="tooltip" id={id}>{label}{sub && <small>{sub}</small>}</span>
    </span>
  );
}

/* Small "?" help affordance carrying a tooltip — for inline term explanations. */
export function HelpDot({ label, sub, place = 'top' }) {
  return (
    <Tooltip label={label} sub={sub} place={place}>
      <span className="help-dot" tabIndex={0} role="button" aria-label={typeof label === 'string' ? label : 'More info'}>?</span>
    </Tooltip>
  );
}

/* ---- Page header (section-aware: optional hue icon chip + eyebrow) ---- */
export function PageHead({ title, icon, eyebrow, badge, subtitle, actions }) {
  return (
    <div className="page__head">
      {icon && <div className="page__ic">{icon}</div>}
      <div className="page__head-main">
        {eyebrow && <div className="page__eyebrow">{eyebrow}</div>}
        <div className="page__title"><h1 className="display" style={{ fontSize: 24 }}>{title}</h1>{badge}</div>
        {subtitle && <p className="page__sub">{subtitle}</p>}
      </div>
      {actions && <div className="page__actions">{actions}</div>}
    </div>
  );
}
