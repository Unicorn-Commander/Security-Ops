import React from 'react';
import './landing.css';

const SEEN_KEY = 'secops_landing_seen';
const hasCallback = (params) => params.has('code') && params.has('state');

function LandingGate() {
  React.useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    if (hasCallback(query) || hasCallback(fragment)) {
      const callback = hasCallback(fragment) ? fragment : query;
      window.location.replace(`/oauth2/callback?${callback.toString()}`);
      return;
    }
    if (query.has('app')) {
      window.localStorage.setItem(SEEN_KEY, '1');
      window.location.replace('/overview');
      return;
    }
    if (window.localStorage.getItem(SEEN_KEY) === '1') {
      window.location.replace('/overview');
    }
  }, []);
  return null;
}

const outcomes = [
  'A reproduced exploit chain, not a wall of maybe-vulnerabilities to triage.',
  'No scan starts until the engagement, scope, and target ownership all pass server-side checks.',
  'A second model verifies every finding before it reaches your team.',
];

export default function Landing() {
  return (
    <div className="so-landing">
      <LandingGate />
      <nav className="so-landing__nav" aria-label="Primary navigation">
        <a className="so-landing__brand" href="/" aria-label="Security-Ops home"><span>SO</span>Security-Ops</a>
        <a className="so-landing__button" href="/?app=1">Open the console <b>→</b></a>
      </nav>
      <main>
        <section className="so-landing__hero">
          <div>
            <p className="so-landing__eyebrow">AI employee · Penetration tester</p>
            <h1>Prove the scope. <em>Then exploit it.</em></h1>
            <p className="so-landing__lede">An autonomous AI pentester that only fires on targets you can prove you own, then exploits, verifies, and hands off.</p>
            <div className="so-landing__badges"><span>Private beta</span><span>Authorized targets only</span></div>
            <div className="so-landing__actions"><a className="so-landing__button" href="/?app=1">Open the console <b>→</b></a><a className="so-landing__secondary" href="mailto:demo@example.invalid?subject=Security-Ops%20walkthrough">Book a walkthrough</a></div>
            <p className="so-landing__note">Every scan is gated by engagement scope and target attestation.</p>
          </div>
          <aside className="so-landing__panel">
            <div className="so-landing__panel-head"><span>✓</span><div><strong>Authorization gate</strong><small>Armed · server-enforced</small></div></div>
            {outcomes.map((outcome) => <p key={outcome}><i>✓</i>{outcome}</p>)}
          </aside>
        </section>
        <section className="so-landing__steps">
          <article><small>01 · SCOPE</small><h2>Create the engagement.</h2><p>Register the target and define exactly what the autonomous team may touch.</p></article>
          <article><small>02 · ATTEST</small><h2>Prove ownership.</h2><p>Use a DNS record, file drop, or HTTP header. If ownership is not proven, nothing fires.</p></article>
          <article><small>03 · HAND OFF</small><h2>Exploit and reproduce.</h2><p>The run sweeps, verifies, and hands your team findings with reproduced proof.</p></article>
        </section>
      </main>
    </div>
  );
}
