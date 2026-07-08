/* GettingStartedChecklist — compact card variant of the onboarding, meant for
 * the Overview page when the account is empty. Same four workflow steps as the
 * full flow, with live check state from /overview and a per-row CTA deep-link.
 *
 * Self-contained: fetches its own /overview, but accepts an optional `progress`
 * prop (from useOnboardingState) to avoid a duplicate request when the host
 * already has it. */
import React from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { useResource } from '../../lib/hooks.js';
import { CheckIcon, ArrowRightIcon, SparkIcon } from '../../components/icons.jsx';
import { WORKFLOW_STEPS } from './steps.jsx';
import { deriveProgress } from './useOnboardingState.js';
import './onboarding.css';

export function GettingStartedChecklist({ progress: progressProp, onDismiss }) {
  // Only hit the network when the host didn't already hand us progress.
  const { data: ov } = useResource(
    () => (progressProp ? Promise.resolve(null) : api('/overview')),
    [!!progressProp],
  );
  const progress = progressProp || deriveProgress(ov);

  return (
    <div className="card ob-check">
      <div className="card__head">
        <span className="ob-check__spark"><SparkIcon size={16} /></span>
        <h2>Get started</h2>
        <div className="spacer" />
        <span className="ob-check__count">{progress.done}/{progress.total}</span>
        {onDismiss && (
          <button className="btn btn--sm btn--ghost" onClick={onDismiss} type="button">Dismiss</button>
        )}
      </div>
      <div className="card__body ob-check__body">
        <div className="ob-check__track"><span style={{ width: `${progress.percent}%` }} /></div>
        <ol className="ob-check__list">
          {WORKFLOW_STEPS.map((ws, i) => {
            const done = ws.done(progress);
            return (
              <li key={ws.key} className={`ob-check__row ${done ? 'is-done' : ''}`}>
                <span className="ob-check__node" aria-hidden="true">
                  {done ? <CheckIcon size={13} /> : <span className="ob-check__num">{i + 1}</span>}
                </span>
                <span className="ob-check__text">
                  <span className="ob-check__title">{ws.title}</span>
                  <span className="ob-check__lede">{ws.rail} — {done ? 'complete' : 'not yet done'}</span>
                </span>
                <Link
                  to={ws.to}
                  className="btn btn--sm ob-check__cta"
                  aria-label={`${ws.cta}${done ? ' (done)' : ''}`}
                >
                  {done ? 'Review' : ws.cta}<ArrowRightIcon size={13} />
                </Link>
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}

export default GettingStartedChecklist;
