/* OnboardingFlow — polished first-run overlay that walks a new user from an
 * empty account to their first *authorized* run.
 *
 * Sequence: Welcome → Create engagement → Register target → Attest ownership →
 * Start first run → Done. Each workflow step's primary CTA deep-links into the
 * real page/action (and closes the overlay). Steps whose data already exists
 * show a live green check, derived from /overview. Skippable + resumable: the
 * last-viewed step is persisted so re-opening lands where you left off.
 *
 * Dialog semantics with a manual focus trap + focus return, Esc to skip/close,
 * and reduced-motion respected (globally in tokens.css and locally here). */
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { useResource } from '../../lib/hooks.js';
import { XIcon, CheckIcon, ChevronLeftIcon, ChevronRightIcon, ArrowRightIcon, LockIcon, ShieldIcon } from '../../components/icons.jsx';
import { WORKFLOW_STEPS, ArtWelcome } from './steps.jsx';
import { deriveProgress, STEP_KEY } from './useOnboardingState.js';
import './onboarding.css';

const LAST = WORKFLOW_STEPS.length + 1; // welcome(0) + 4 workflow(1..4) + done(5)

function clampStep(n) { const v = Number(n); return Number.isFinite(v) ? Math.min(LAST, Math.max(0, v)) : 0; }

export default function OnboardingFlow({ onClose }) {
  const navigate = useNavigate();
  const { data: ov } = useResource(() => api('/overview'), []);
  const progress = deriveProgress(ov);

  const [step, setStep] = React.useState(() => {
    try { return clampStep(localStorage.getItem(STEP_KEY) || 0); } catch { return 0; }
  });
  React.useEffect(() => { try { localStorage.setItem(STEP_KEY, String(step)); } catch { /* ignore */ } }, [step]);

  const panelRef = React.useRef(null);
  const headingRef = React.useRef(null);
  const titleId = React.useId();

  // Focus trap + focus return + Esc, matching the app's Drawer primitive.
  React.useEffect(() => {
    const restoreTo = document.activeElement;
    document.body.style.overflow = 'hidden';
    const t = setTimeout(() => headingRef.current?.focus(), 0);
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); onClose?.(); return; }
      if (e.key !== 'Tab') return;
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
      if (restoreTo && typeof restoreTo.focus === 'function') restoreTo.focus();
    };
  }, [onClose]);

  // Move focus to the heading when the visible step changes (announces new step).
  React.useEffect(() => { headingRef.current?.focus(); }, [step]);

  const isWelcome = step === 0;
  const isDone = step === LAST;
  const workflow = !isWelcome && !isDone ? WORKFLOW_STEPS[step - 1] : null;

  function go(delta) { setStep((s) => clampStep(s + delta)); }
  function launch(to) { onClose?.(); navigate(to); }

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div
        className="ob"
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        {/* Left progress rail — the four workflow milestones */}
        <nav className="ob__rail" aria-label="Onboarding progress">
          <div className="ob__brand">
            <span className="ob__brand-mark"><ShieldIcon size={16} strokeWidth={2} /></span>
            <span className="ob__brand-name">Security-Ops</span>
          </div>
          <ol className="ob__steps">
            {WORKFLOW_STEPS.map((ws, i) => {
              const idx = i + 1;
              const done = ws.done(progress);
              const active = idx === step;
              return (
                <li key={ws.key} className={`ob__step ${active ? 'is-active' : ''} ${done ? 'is-done' : ''} ${idx < step ? 'is-past' : ''}`}>
                  <button
                    type="button"
                    className="ob__step-btn"
                    aria-current={active ? 'step' : undefined}
                    onClick={() => setStep(idx)}
                  >
                    <span className="ob__step-node">
                      {done ? <CheckIcon size={13} /> : <span className="ob__step-num">{idx}</span>}
                    </span>
                    <span className="ob__step-label">
                      {ws.rail}
                      {done && <span className="ob__step-tag">Done</span>}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
          <div className="ob__rail-foot">
            <div className="ob__mini-track"><span style={{ width: `${progress.percent}%` }} /></div>
            <span className="ob__mini-label">{progress.done} of {progress.total} complete</span>
          </div>
        </nav>

        {/* Right content pane */}
        <div className="ob__main">
          <button className="ob__close" onClick={onClose} aria-label="Skip onboarding" type="button"><XIcon size={16} /></button>

          {isWelcome && (
            <div className="ob__panel">
              <div className="ob__hero">
                <div className="ob__hero-art"><ArtWelcome /></div>
                <span className="ob__eyebrow"><LockIcon size={12} strokeWidth={2} />Authorized offensive security</span>
                <h2 className="ob__title" id={titleId} ref={headingRef} tabIndex={-1}>Welcome to Security-Ops</h2>
                <p className="ob__lede">
                  This is an authorized pentest console. Nothing scans until you’ve proven the right to test it —
                  the <b className="ob__gate">authorization gate</b> is server-enforced and blocks any run without an
                  active, attested, unexpired scope. Four quick steps get you legitimately to your first run.
                </p>
              </div>
              <ul className="ob__gatelist">
                <li><span className="ob__dot" />Define an <b>engagement</b> — the scope you’re allowed to touch</li>
                <li><span className="ob__dot" />Register &amp; <b>attest</b> each target — prove you own it</li>
                <li><span className="ob__dot" />Launch a run — the gate re-checks authorization at start</li>
              </ul>
              <div className="ob__actions">
                <button className="btn btn--ghost" onClick={onClose} type="button">Skip for now</button>
                <div className="spacer" />
                <button className="btn btn--primary" onClick={() => go(1)} type="button">
                  Get started<ArrowRightIcon size={14} />
                </button>
              </div>
            </div>
          )}

          {workflow && (
            <div className="ob__panel" key={workflow.key}>
              <div className="ob__step-head">
                <span className="ob__step-index">Step {step} of {WORKFLOW_STEPS.length}</span>
                {workflow.done(progress) && <span className="ob__done-badge"><CheckIcon size={12} />Already done</span>}
              </div>
              <div className="ob__step-art"><workflow.Art /></div>
              <h2 className="ob__title" id={titleId} ref={headingRef} tabIndex={-1}>{workflow.title}</h2>
              <p className="ob__lede">{workflow.lede}</p>

              {workflow.key === 'attest' && (
                <div className="ob__methods" role="list">
                  <span role="listitem" className="ob__method"><b>DNS TXT</b>publish a token record</span>
                  <span role="listitem" className="ob__method"><b>File drop</b>host a proof file</span>
                  <span role="listitem" className="ob__method"><b>HTTP header</b>return a response header</span>
                </div>
              )}

              <div className="ob__cta">
                <button className="btn btn--primary btn--block" onClick={() => launch(workflow.to)} type="button">
                  <workflow.Icon size={15} />{workflow.cta}<ArrowRightIcon size={14} />
                </button>
                <span className="ob__cta-note">Opens the real page — we’ll close this and take you there.</span>
              </div>

              <div className="ob__actions">
                <button className="btn btn--ghost" onClick={() => go(-1)} type="button">
                  <ChevronLeftIcon size={14} />Back
                </button>
                <div className="spacer" />
                <button className="btn btn--ghost" onClick={onClose} type="button">Skip</button>
                <button className="btn" onClick={() => go(1)} type="button">
                  Next<ChevronRightIcon size={14} />
                </button>
              </div>
            </div>
          )}

          {isDone && (
            <div className="ob__panel">
              <div className="ob__hero">
                <div className="ob__done-ring"><CheckIcon size={30} strokeWidth={2.4} /></div>
                <h2 className="ob__title" id={titleId} ref={headingRef} tabIndex={-1}>You’re set up to run — authorized.</h2>
                <p className="ob__lede">
                  {progress.complete
                    ? 'All four milestones are green. Your scope is live, attested and enforced — every run you start is provably authorized.'
                    : 'You know the whole flow now. Complete any remaining steps from the Overview checklist whenever you’re ready — the authorization gate will keep every run honest.'}
                </p>
              </div>
              <div className="ob__recap">
                {WORKFLOW_STEPS.map((ws, i) => (
                  <div key={ws.key} className={`ob__recap-row ${ws.done(progress) ? 'is-done' : ''}`}>
                    <span className="ob__recap-node">{ws.done(progress) ? <CheckIcon size={12} /> : (i + 1)}</span>
                    {ws.rail}
                  </div>
                ))}
              </div>
              <div className="ob__actions">
                <button className="btn btn--ghost" onClick={() => go(-1)} type="button"><ChevronLeftIcon size={14} />Back</button>
                <div className="spacer" />
                <button className="btn btn--primary" onClick={onClose} type="button">Go to console<ArrowRightIcon size={14} /></button>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
