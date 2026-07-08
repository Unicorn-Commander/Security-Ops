/* useOnboardingState — decides whether first-run onboarding should surface, and
 * derives live step-completion from /overview so checkmarks light up on their
 * own as the user completes real work.
 *
 * localStorage:
 *   secops_onboarded          '1' once dismissed (canonical "don't show me")
 *   secops_onboarding_step    last-viewed flow step index (resumable)
 */
import React from 'react';
import { api } from '../../lib/api.js';
import { useResource } from '../../lib/hooks.js';

export const DISMISS_KEY = 'secops_onboarded';
export const STEP_KEY = 'secops_onboarding_step';

function lsGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } }
function lsDel(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } }

/* Map an /overview envelope to the four workflow milestones. Missing data →
 * everything "not done" (which, combined with the empty check, keeps the flow
 * visible rather than hiding it on a transient error). */
export function deriveProgress(ov) {
  const engagements = ov?.engagements?.total || 0;
  const targets = ov?.targets?.total || 0;
  const attested = ov?.targets?.attested || 0;
  const runs = ov?.runs?.total || 0;
  const steps = {
    engagement: engagements > 0,
    target: targets > 0,
    attest: attested > 0,
    run: runs > 0,
  };
  const done = Object.values(steps).filter(Boolean).length;
  return {
    steps,
    counts: { engagements, targets, attested, runs },
    done,
    total: 4,
    percent: Math.round((done / 4) * 100),
    complete: done === 4,
  };
}

export function useOnboardingState() {
  const { data, error } = useResource(() => api('/overview'), []);
  const [dismissed, setDismissed] = React.useState(() => lsGet(DISMISS_KEY) === '1');

  const dismiss = React.useCallback(() => { lsSet(DISMISS_KEY, '1'); setDismissed(true); }, []);
  const reopen = React.useCallback(() => { lsDel(DISMISS_KEY); lsDel(STEP_KEY); setDismissed(false); }, []);

  const progress = React.useMemo(() => deriveProgress(data), [data]);

  // "Empty" ONLY when overview loaded cleanly and there is genuinely nothing yet.
  // An error must NOT count as empty: a signed-out / unentitled customer would
  // otherwise get the first-run overlay thrown on top of a broken console
  // (the error state itself is surfaced by the page). So gate on a successful load.
  const empty = !!data && !error
    && progress.counts.engagements === 0
    && progress.counts.targets === 0
    && progress.counts.runs === 0;

  const shouldShow = !dismissed && !error && empty;

  return { shouldShow, dismiss, reopen, progress, loading: !data && !error };
}
