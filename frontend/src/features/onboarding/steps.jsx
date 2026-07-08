/* Shared onboarding step model + inline illustrations.
 *
 * The four workflow steps below are the single source of truth for BOTH the
 * full-screen OnboardingFlow and the compact GettingStartedChecklist, so the
 * rail, the checklist and the deep-links never drift apart. Each step maps to a
 * real page/action via a react-router deep-link the target page can honor. */
import React from 'react';
import { ShieldIcon, TargetIcon, LockIcon, PlayIcon } from '../../components/icons.jsx';

/* Live-completion predicates read the /overview envelope shape (see Overview.jsx):
 *   engagements.total · targets.total · targets.attested · runs.total          */
export const WORKFLOW_STEPS = [
  {
    key: 'engagement',
    rail: 'Engagement',
    title: 'Create an engagement',
    lede: 'An engagement defines the authorized scope — which hosts you may test, for how long. Everything you run lives inside one.',
    cta: 'New engagement',
    to: '/engagements?new=1',
    Icon: ShieldIcon,
    done: (p) => p.steps.engagement,
    Art: ArtEngagement,
  },
  {
    key: 'target',
    rail: 'Target',
    title: 'Register a target',
    lede: 'Add the host, URL or CIDR you intend to assess into the target registry. Targets must fall inside an engagement’s scope to ever be reachable.',
    cta: 'Register target',
    to: '/targets?new=1',
    Icon: TargetIcon,
    done: (p) => p.steps.target,
    Art: ArtTarget,
  },
  {
    key: 'attest',
    rail: 'Attest',
    title: 'Attest ownership',
    lede: 'Prove you control the target before it can be scanned. Choose one of three methods — a DNS TXT record, a hosted file drop, or an HTTP response header — and the platform verifies it for you.',
    cta: 'Attest ownership',
    to: '/targets?attest=1',
    Icon: LockIcon,
    done: (p) => p.steps.attest,
    Art: ArtAttest,
  },
  {
    key: 'run',
    rail: 'First run',
    title: 'Start your first run',
    lede: 'Activate the engagement and launch a run. The authorization gate re-checks scope + attestation + expiry at start time — a green light here means you’re fully, provably authorized.',
    cta: 'Start a run',
    to: '/runs?new=1',
    Icon: PlayIcon,
    done: (p) => p.steps.run,
    Art: ArtRun,
  },
];

/* ---------------------------------------------------------------------------
 * Illustrations — small, self-contained SVGs. They reference the theme via
 * CSS variables (currentColor + gradient stops set to accent tokens) so they
 * read correctly on the dark console with zero external assets.
 * ------------------------------------------------------------------------- */
function ArtFrame({ children, label }) {
  return (
    <svg viewBox="0 0 200 132" className="ob-art" role="img" aria-label={label} preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="obAurora" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--accent)" />
          <stop offset="0.5" stopColor="var(--accent-strong)" />
          <stop offset="1" stopColor="var(--accent-2)" />
        </linearGradient>
      </defs>
      {children}
    </svg>
  );
}

export function ArtWelcome() {
  return (
    <ArtFrame label="Authorized offensive security">
      <circle cx="100" cy="66" r="46" fill="var(--accent-soft)" />
      <path d="M100 30l30 11v19c0 20-14 30-30 36-16-6-30-16-30-36V41z" fill="none" stroke="url(#obAurora)" strokeWidth="3" strokeLinejoin="round" />
      <path d="M88 66l8 8 18-19" fill="none" stroke="var(--ok)" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      <g stroke="var(--accent-2)" strokeWidth="2" opacity="0.7" strokeLinecap="round">
        <path d="M30 30l10 6M30 42l14 3M170 30l-10 6M170 42l-14 3" />
      </g>
    </ArtFrame>
  );
}

function ArtEngagement() {
  return (
    <ArtFrame label="Engagement scope">
      <rect x="40" y="30" width="120" height="74" rx="10" fill="var(--surface-3)" stroke="var(--border-2)" strokeWidth="2" />
      <path d="M40 40h120" stroke="var(--border-2)" strokeWidth="2" />
      <circle cx="52" cy="35" r="2.4" fill="var(--muted)" /><circle cx="60" cy="35" r="2.4" fill="var(--muted)" /><circle cx="68" cy="35" r="2.4" fill="var(--muted)" />
      <rect x="54" y="54" width="60" height="6" rx="3" fill="url(#obAurora)" />
      <rect x="54" y="68" width="92" height="5" rx="2.5" fill="var(--border-strong)" />
      <rect x="54" y="80" width="72" height="5" rx="2.5" fill="var(--border-strong)" />
      <path d="M100 30l24 9v14c0 15-11 23-24 28" fill="var(--accent-soft)" stroke="url(#obAurora)" strokeWidth="2.4" strokeLinejoin="round" opacity="0.9" transform="translate(38 44) scale(0.42)" />
    </ArtFrame>
  );
}

function ArtTarget() {
  return (
    <ArtFrame label="Target registry">
      <circle cx="100" cy="66" r="42" fill="none" stroke="var(--border-2)" strokeWidth="2" />
      <circle cx="100" cy="66" r="27" fill="none" stroke="var(--accent-soft)" strokeWidth="10" />
      <circle cx="100" cy="66" r="27" fill="none" stroke="url(#obAurora)" strokeWidth="3" />
      <circle cx="100" cy="66" r="6" fill="var(--accent-2)" />
      <path d="M100 12v14M100 106v14M42 66h14M144 66h14" stroke="var(--accent)" strokeWidth="2.4" strokeLinecap="round" />
    </ArtFrame>
  );
}

function ArtAttest() {
  return (
    <ArtFrame label="Ownership attestation">
      <g transform="translate(0 6)">
        <rect x="26" y="40" width="44" height="30" rx="6" fill="var(--surface-3)" stroke="var(--border-2)" strokeWidth="2" />
        <text x="48" y="59" textAnchor="middle" fontFamily="var(--mono)" fontSize="11" fill="var(--accent-2)">TXT</text>
        <rect x="78" y="40" width="44" height="30" rx="6" fill="var(--surface-3)" stroke="var(--border-2)" strokeWidth="2" />
        <path d="M92 47h16M92 53h16M92 59h10" stroke="var(--accent-strong)" strokeWidth="2" strokeLinecap="round" />
        <rect x="130" y="40" width="44" height="30" rx="6" fill="var(--surface-3)" stroke="var(--border-2)" strokeWidth="2" />
        <text x="152" y="59" textAnchor="middle" fontFamily="var(--mono)" fontSize="9" fill="var(--accent)">HDR</text>
        <path d="M48 70v14h104V70" fill="none" stroke="var(--border-strong)" strokeWidth="2" />
        <path d="M100 84v10" stroke="var(--border-strong)" strokeWidth="2" />
        <g transform="translate(100 104)">
          <circle r="14" fill="var(--ok-soft)" stroke="var(--ok)" strokeWidth="2" />
          <path d="M-6 0l4 4 8-9" fill="none" stroke="var(--ok)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        </g>
      </g>
    </ArtFrame>
  );
}

function ArtRun() {
  return (
    <ArtFrame label="Authorized run">
      <rect x="34" y="34" width="132" height="64" rx="10" fill="var(--surface-inset)" stroke="var(--border-2)" strokeWidth="2" />
      <path d="M52 88l14-18 12 10 16-26 14 20 12-8" fill="none" stroke="url(#obAurora)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="100" cy="112" r="15" fill="var(--accent-soft)" stroke="url(#obAurora)" strokeWidth="2.4" />
      <path d="M95 105v14l12-7z" fill="var(--accent-2)" />
    </ArtFrame>
  );
}
