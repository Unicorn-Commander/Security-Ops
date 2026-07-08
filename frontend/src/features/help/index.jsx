/* Security-Ops — Help & documentation.
 *
 * The canonical, in-app help. A sticky in-page table of contents (with active-
 * section highlight on scroll) beside a scrollable, live-searchable content
 * column. Everything the console does is documented here — including the
 * agent-first surface (MCP server + Personal Access Tokens + Assistant), since
 * every capability in the UI is also reachable by an AI agent, under the same
 * server-enforced authorization gate.
 *
 * Exports:
 *   default  Help          — the full help page (route it at /help)
 *   named    HelpButton     — a "?" icon button for the topbar (self-contained nav)
 *   named    HELP_TOPICS     — { topicKey: '/help#anchor' } for contextual deep-links
 *
 * File ownership: this feature lives entirely under src/features/help/. It only
 * imports shared primitives (ui.jsx, icons.jsx) and its own help.css. */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Banner, CopyButton } from '../../components/ui.jsx';
import {
  ShieldIcon, TargetIcon, PlayIcon, BugIcon, LockIcon,
  SparkIcon, ZapIcon, SearchIcon, XIcon, ChevronRightIcon,
  InfoIcon, ArrowRightIcon, FileIcon,
} from '../../components/icons.jsx';
import './help.css';

/* ------------------------------------------------------------------ Constants */

const MCP_URL = 'https://security-ops.magicunicorn.dev/mcp/';
const PAT_PREFIX = 'secops_pat_';

/* Contextual deep-link map — other parts of the app import this to point at the
 * right section of the canonical help. Anchor ids match the section ids below. */
export const HELP_TOPICS = {
  gettingStarted:    '/help#getting-started',
  authorizationGate: '/help#authorization-gate',
  gate:              '/help#authorization-gate',
  engagements:       '/help#engagements',
  targets:           '/help#targets-attestation',
  attestation:       '/help#targets-attestation',
  runs:              '/help#runs-engine',
  engine:            '/help#runs-engine',
  findings:          '/help#findings-brigade',
  brigade:           '/help#findings-brigade',
  handoff:           '/help#findings-brigade',
  agentAccess:       '/help#agent-access',
  mcp:               '/help#agent-access',
  pat:               '/help#agent-access',
  assistant:         '/help#agent-access',
  shortcuts:         '/help#keyboard-shortcuts',
  troubleshooting:   '/help#troubleshooting',
  faq:               '/help#troubleshooting',
  glossary:          '/help#glossary',
};

/* ------------------------------------------------------------------ Local icons */
/* Small inline SVGs for the two glyphs icons.jsx doesn't carry. Same lucide-ish
 * 24×24 currentColor stroke system as components/icons.jsx. */
function HelpIcon({ size = 18, ...rest }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.2 9.3a2.8 2.8 0 0 1 5.4 1c0 1.9-2.8 2.5-2.8 2.5" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}
function KeyboardIcon({ size = 18, ...rest }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
      <rect x="2" y="5" width="20" height="14" rx="2.5" />
      <path d="M6 9h.01M10 9h.01M14 9h.01M18 9h.01M6 13h.01M18 13h.01M9 13h6" />
    </svg>
  );
}
function BookIcon({ size = 18, ...rest }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
      <path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v18H6.5A2.5 2.5 0 0 0 4 22.5z" />
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
    </svg>
  );
}

/* ------------------------------------------------------------------ Small parts */

function Kbd({ children }) { return <kbd className="kbd">{children}</kbd>; }

function CodeBlock({ text, caption }) {
  return (
    <div className="hlp-code">
      {caption && <div className="hlp-code__cap"><FileIcon size={13} />{caption}</div>}
      <div className="hlp-code__copy"><CopyButton text={text} /></div>
      <pre className="code">{text}</pre>
    </div>
  );
}

function SevChip({ level }) {
  const cls = { INFO: 'sev--info', LOW: 'sev--low', MEDIUM: 'sev--medium', HIGH: 'sev--high', CRITICAL: 'sev--critical' }[level];
  const label = level.charAt(0) + level.slice(1).toLowerCase();
  return <span className={`sev ${cls}`}><span className="bar" />{label}</span>;
}

/* Severity heat ramp, inline */
function SevRamp() {
  const levels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return (
    <div className="hlp-flow">
      {levels.map((l, i) => (
        <React.Fragment key={l}>
          <SevChip level={l} />
          {i < levels.length - 1 && <ArrowRightIcon size={14} className="hlp-flow__arrow" />}
        </React.Fragment>
      ))}
    </div>
  );
}

function LifecycleFlow({ steps }) {
  return (
    <div className="hlp-flow">
      {steps.map((s, i) => (
        <React.Fragment key={s.label}>
          <span className={`badge ${s.cls}`}><span className="dot" />{s.label}</span>
          {i < steps.length - 1 && <ChevronRightIcon size={15} className="hlp-flow__arrow" />}
        </React.Fragment>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ FAQ / Glossary data */

const FAQ = [
  {
    q: 'My run was denied. Why?',
    keywords: 'denied blocked gate 403 scope authorization refused halt cannot start run',
    a: (
      <>
        <p>A <b>DENIED</b> run means the authorization gate refused the request <i>before</i> the engine
          touched anything. The gate is server-side and fails closed, so a denial is always deliberate. Check, in order:</p>
        <ul>
          <li>The engagement is <b>ACTIVE</b> (not DRAFT, STOPPED, COMPLETED, or EXPIRED).</li>
          <li>Every requested target is <b>ATTESTED</b>, not <b>REVOKED</b>, and its attestation has not expired.</li>
          <li>The target actually falls inside the engagement's authorized scope.</li>
          <li>Your token/PAT carries the <code>security-ops</code> entitlement and is scoped to this org.</li>
        </ul>
      </>
    ),
  },
  {
    q: 'Attestation keeps failing verification.',
    keywords: 'attestation fail verify dns txt file drop http header ownership proof challenge token not found',
    a: (
      <>
        <p>The server fetches your proof live at attest time. Common causes:</p>
        <ul>
          <li><b>DNS_TXT</b> — the record hasn't propagated yet (wait for TTL), or it was added to the wrong
            name. Publish the exact <code>name</code> and <code>value</code> from the challenge.</li>
          <li><b>FILE_DROP</b> — the file must be reachable at the exact well-known URL over HTTPS with a 200
            response and the token as its body (no extra whitespace, no HTML wrapper).</li>
          <li><b>HTTP_HEADER</b> — the header must appear on the response for the challenge URL, spelled and
            cased as given.</li>
        </ul>
        <p>Each challenge token is bound to one target. Re-open the target and copy fresh values if you're unsure.</p>
      </>
    ),
  },
  {
    q: 'What is the difference between OWNED and a proof method?',
    keywords: 'owned checkbox typed confirmation dns file http self owned external asset method',
    a: (
      <p><b>OWNED</b> (and the CHECKBOX / TYPED_CONFIRMATION variants) is the self-owned escape hatch for assets you
        already control — your own suite. External assets — someone else's domain, URL, or IP range — require a live
        ownership proof (<b>DNS_TXT</b>, <b>FILE_DROP</b>, or <b>HTTP_HEADER</b>) so the gate can independently verify
        you're authorized before anything is scanned.</p>
    ),
  },
  {
    q: 'How do I stop a run immediately?',
    keywords: 'stop halt emergency cancel abort run engine kill terminate',
    a: (
      <p>Open the run and use <b>Stop</b>, or emergency-stop the whole engagement to halt every run under it at once.
        Stopping is honored by the engine as fast as it can unwind in-flight work; the run moves to <b>STOPPED</b> and
        the action is written to the immutable audit chain.</p>
    ),
  },
  {
    q: 'Do agents bypass the authorization gate?',
    keywords: 'agent mcp pat bypass gate authorization security ai automated same rules',
    a: (
      <p><b>No.</b> Agents reach the exact same server endpoints as the UI, so the exact same gate applies. A PAT or
        JWT authenticates <i>who</i> is asking; it never grants permission to test an unattested or out-of-scope asset.
        Everything an agent does is authorized, scoped, and audited identically to a human operator.</p>
    ),
  },
  {
    q: 'My Personal Access Token stopped working.',
    keywords: 'pat token expired revoked 401 unauthorized secops_pat authorization bearer invalid',
    a: (
      <>
        <p>A <code>401</code> from <code>{MCP_URL}</code> usually means the PAT was revoked, expired, or is malformed.</p>
        <ul>
          <li>Confirm the header is exactly <code>Authorization: Bearer {PAT_PREFIX}…</code> with no stray quotes.</li>
          <li>PATs are shown once at mint time — if you lost it, revoke it and mint a new one.</li>
          <li>A uchub Keycloak JWT works too, but expires quickly; PATs are the durable choice for agents.</li>
        </ul>
      </>
    ),
  },
  {
    q: 'A finding looks like a false positive.',
    keywords: 'false positive finding verify triage severity dismiss remediation',
    a: (
      <p>Open the finding and review the evidence and the exploit chain. Mark it <b>Verified</b> once you've confirmed
        it's real and reproducible, or set it <b>False positive</b> to take it out of the open count. Only verified
        findings are worth handing off to Brigade for remediation tracking.</p>
    ),
  },
  {
    q: 'What happens when an engagement expires?',
    keywords: 'expired engagement lifecycle window authorization lapse scope end date',
    a: (
      <p>An engagement defines the authorized window as well as the scope. Once it moves to <b>EXPIRED</b>, no new runs
        can start against it and the gate denies any attempt — even for still-attested targets. Create a fresh
        engagement (or re-activate within policy) to continue testing.</p>
    ),
  },
];

const GLOSSARY = [
  { term: 'Authorization gate', def: 'The server-enforced checkpoint that refuses any scan without an active, attested, unexpired, in-scope authorization. Fails closed.' },
  { term: 'Engagement', def: 'A defined, time-boxed authorization to test a set of assets. Its lifecycle (DRAFT → ACTIVE → STOPPED/COMPLETED/EXPIRED) governs when runs may execute.' },
  { term: 'Target', def: 'A registered asset — DOMAIN, URL, IP_RANGE, or REPO — that becomes scannable only after it passes attestation.' },
  { term: 'Attestation', def: 'Proof that you are authorized to test a target, verified live by the server via DNS_TXT, FILE_DROP, HTTP_HEADER, or a self-owned acknowledgement.' },
  { term: 'Challenge token', def: 'A one-time value the server issues per target; you publish it (in DNS, a file, or a header) so ownership can be verified.' },
  { term: 'Run', def: 'A single execution of the Strix engine against an engagement’s attested targets. Moves through PENDING → RUNNING → COMPLETED / FAILED / STOPPED / DENIED.' },
  { term: 'Strix engine', def: 'The autonomous offensive-security engine that executes a run, reasons about the target, and produces findings.' },
  { term: 'Finding', def: 'A discovered issue, rated on the INFO → CRITICAL heat ramp, that can be verified and handed off for remediation.' },
  { term: 'Severity ramp', def: 'The ordered heat scale used throughout: INFO, LOW, MEDIUM, HIGH, CRITICAL.' },
  { term: 'Brigade', def: 'Unicorn Brigade — the remediation-tracking destination a verified finding is handed off to.' },
  { term: 'MCP server', def: 'The Model Context Protocol endpoint at ' + MCP_URL + ' that exposes every console capability to AI agents, behind the same gate.' },
  { term: 'PAT', def: 'A Personal Access Token (prefix ' + PAT_PREFIX + ') minted from the console to authenticate an agent to the MCP server.' },
  { term: 'Audit chain', def: 'The immutable, hash-chained record of every authorization decision and action — tamper-evident by construction.' },
];

const SHORTCUTS = [
  { keys: ['?'], desc: 'Open this help', keywords: 'help question mark docs' },
  { keys: ['/'], desc: 'Focus the search / filter box on the current view', keywords: 'search filter focus find' },
  { keys: ['g', 'o'], desc: 'Go to Overview', keywords: 'navigate overview go home' },
  { keys: ['g', 'e'], desc: 'Go to Engagements', keywords: 'navigate engagements' },
  { keys: ['g', 't'], desc: 'Go to Targets', keywords: 'navigate targets registry' },
  { keys: ['g', 'r'], desc: 'Go to Runs', keywords: 'navigate runs' },
  { keys: ['g', 'f'], desc: 'Go to Findings', keywords: 'navigate findings inbox' },
  { keys: ['Enter'], desc: 'Open the focused table row', keywords: 'activate open row select' },
  { keys: ['Esc'], desc: 'Close the open drawer, dialog, or menu', keywords: 'close escape cancel dismiss' },
  { keys: ['Tab'], desc: 'Move focus (trapped inside an open drawer/dialog)', keywords: 'focus tab keyboard accessibility trap' },
];

/* ------------------------------------------------------------------ Sections */
/* Each section carries an id (its anchor), a number, a label, an icon, a
 * searchable keyword string, and a Body. Body may be a component that takes the
 * live query (FAQ/Glossary/Shortcuts filter their own items). */

const SECTIONS = [
  {
    id: 'getting-started',
    label: 'Getting started',
    icon: ZapIcon,
    keywords: 'getting started intro overview onboard first run quickstart tour how it works authorized pentest console what is security-ops workflow lifecycle five steps',
    Body: () => (
      <div className="hlp-prose">
        <p><b>Security-Ops is an authorized penetration-testing console.</b> It exists to make offensive security
          <i> provably in-bounds</i>: you can only test assets you own or have attested authorization for, every scan is
          gated server-side, and every decision is written to an immutable audit trail. Nothing here is for testing
          systems you are not authorized to test.</p>

        <p>The whole product is one disciplined loop. From a standing start, the path to your first finding is five moves:</p>

        <div className="hlp-cards">
          <div className="hlp-card">
            <div className="hlp-card__ic"><ShieldIcon size={17} /></div>
            <h3>1 · Create an engagement</h3>
            <p>Define the authorized scope and window. Start in DRAFT; activate it to arm testing.</p>
          </div>
          <div className="hlp-card">
            <div className="hlp-card__ic"><TargetIcon size={17} /></div>
            <h3>2 · Register &amp; attest targets</h3>
            <p>Add each asset, then prove you're allowed to test it. Only attested targets are scannable.</p>
          </div>
          <div className="hlp-card">
            <div className="hlp-card__ic"><PlayIcon size={15} /></div>
            <h3>3 · Start a run</h3>
            <p>Launch the Strix engine against your attested, in-scope targets and watch it work.</p>
          </div>
          <div className="hlp-card">
            <div className="hlp-card__ic"><BugIcon size={17} /></div>
            <h3>4 · Triage &amp; hand off</h3>
            <p>Verify findings on the INFO→CRITICAL ramp, then hand off to Unicorn Brigade to remediate.</p>
          </div>
        </div>

        <Banner kind="info">
          <div><b>Agent-first, always.</b> Everything you can do here by hand, an AI agent can do through the MCP
            server — under the exact same authorization gate. See <a href="#agent-access">Agent access</a>.</div>
        </Banner>

        <h3>Where things live</h3>
        <p>The left navigation follows the loop end to end: <b>Overview</b> (posture at a glance) → <b>Engagements</b> →
          <b> Targets</b> → <b>Runs</b> → <b>Findings</b>. The armed-gate indicator in the sidebar is the product's
          heartbeat — when it's green, the server is actively enforcing authorization on every request.</p>
      </div>
    ),
  },

  {
    id: 'authorization-gate',
    label: 'The authorization gate',
    icon: LockIcon,
    keywords: 'authorization gate server enforced fail closed audit hash chain immutable scope attested unexpired denied allow deny verdict permission legal safety no scan without arm own attested only test assets you own',
    Body: () => (
      <div className="hlp-prose">
        <p>The authorization gate is the single most important thing in Security-Ops. It is a <b>server-enforced</b>
          checkpoint that every run request passes through, and it <b>fails closed</b>: if authorization can't be
          positively established, the request is denied. You cannot disable it, and the client can't talk it into
          anything — the decision is made on the server, not in this UI.</p>

        <h3>What it checks</h3>
        <p>Before the Strix engine touches a single packet, the gate confirms every one of these is true:</p>
        <ul>
          <li>There is an <b>ACTIVE</b> engagement authorizing the work.</li>
          <li>Every requested target is <b>ATTESTED</b> — ownership proven — and <b>not REVOKED</b>.</li>
          <li>No attestation or engagement window has <b>expired</b>.</li>
          <li>The targets fall inside the engagement's declared <b>scope</b>.</li>
          <li>The caller (human or agent) is entitled and scoped to the owning org.</li>
        </ul>
        <p>If all pass, the run is <span className="badge badge--ok"><span className="dot" />Allowed</span> and proceeds.
          If any fail, it's <span className="badge badge--danger"><span className="dot" />Denied</span> and never runs.</p>

        <Banner kind="warn">
          <div><b>You may only test assets you own or have attested authorization for.</b> The gate is a technical
            control, not a substitute for having permission. Scanning systems without authorization is unlawful — this
            tool is built to keep you demonstrably on the right side of that line.</div>
        </Banner>

        <h3>The immutable audit chain</h3>
        <p>Every authorization decision and every consequential action is written to a <b>hash-chained, append-only
          audit log</b>. Each entry commits to the one before it, so the record is tamper-evident: you can prove, after
          the fact, exactly what was authorized, by whom, and when. This is what turns "we had permission" from a claim
          into evidence.</p>
      </div>
    ),
  },

  {
    id: 'engagements',
    label: 'Engagements',
    icon: ShieldIcon,
    keywords: 'engagement lifecycle draft active stopped completed expired activate arm emergency stop scope authorized window create manage halt',
    Body: () => (
      <div className="hlp-prose">
        <p>An <b>engagement</b> is a unit of authorization: it defines <i>what</i> may be tested and <i>when</i>. Runs
          only execute under an ACTIVE engagement, so this is where testing is armed and disarmed.</p>

        <h3>Lifecycle</h3>
        <LifecycleFlow steps={[
          { label: 'Draft', cls: 'badge--neutral' },
          { label: 'Active', cls: 'badge--ok' },
          { label: 'Stopped / Completed / Expired', cls: 'badge--danger' },
        ]} />
        <div className="hlp-table">
          <div className="tablewrap"><table className="tbl">
            <thead><tr><th>State</th><th>Meaning</th><th>Can runs start?</th></tr></thead>
            <tbody>
              <tr><td><span className="badge badge--neutral"><span className="dot" />Draft</span></td><td>Being prepared. Scope is editable; not yet authorized.</td><td className="muted">No</td></tr>
              <tr><td><span className="badge badge--ok"><span className="dot" />Active</span></td><td>Armed and authorizing. The gate will allow in-scope, attested runs.</td><td style={{ color: 'var(--ok)' }}>Yes</td></tr>
              <tr><td><span className="badge badge--danger"><span className="dot" />Stopped</span></td><td>Emergency-halted. All runs under it are stopped.</td><td className="muted">No</td></tr>
              <tr><td><span className="badge badge--info"><span className="dot" />Completed</span></td><td>Work is finished and the engagement was closed out.</td><td className="muted">No</td></tr>
              <tr><td><span className="badge badge--neutral"><span className="dot" />Expired</span></td><td>The authorized window lapsed. The gate denies further runs.</td><td className="muted">No</td></tr>
            </tbody>
          </table></div>
        </div>

        <h3>Arming and emergency-stop</h3>
        <ol className="hlp-steps">
          <li><b>Create</b> the engagement and declare its scope while in DRAFT.</li>
          <li><b>Activate</b> it to arm — from this moment the gate will authorize matching runs.</li>
          <li><b>Emergency-stop</b> at any time to halt every run under the engagement at once; it moves to STOPPED and the action is audited.</li>
        </ol>

        <Banner kind="info">
          <div>Activating an engagement doesn't scan anything by itself — it only makes in-scope, <b>attested</b>
            targets eligible. Attestation still gates each target individually.</div>
        </Banner>
      </div>
    ),
  },

  {
    id: 'targets-attestation',
    label: 'Targets & attestation',
    icon: TargetIcon,
    keywords: 'target registry attestation ownership proof dns txt record file drop well-known http response header challenge token owned checkbox typed confirmation domain url ip range repo scannable unattested revoked expires register verify live',
    Body: () => (
      <div className="hlp-prose">
        <p>The <b>target registry</b> is the list of assets the authorization gate consults. Registering an asset only
          records it — it stays <b>unscannable</b> until it passes <b>attestation</b> and sits inside an active engagement.</p>

        <h3>Register a target</h3>
        <p>Add the asset by kind — <code>DOMAIN</code>, <code>URL</code>, <code>IP_RANGE</code>, or <code>REPO</code> —
          with an optional label and owner principal. A newly registered target is <span className="badge badge--neutral"><span className="dot" />Unattested</span> and cannot be scanned.</p>

        <h3>Prove ownership</h3>
        <p>External assets require a live ownership proof. The server issues a per-target <b>challenge token</b>; you
          publish it using one of three methods, then attest — the server fetches and verifies the proof in real time.</p>
        <div className="hlp-table">
          <div className="tablewrap"><table className="tbl">
            <thead><tr><th>Method</th><th>What you publish</th><th>Best for</th></tr></thead>
            <tbody>
              <tr><td><span className="chip">DNS_TXT</span></td><td>A <code>TXT</code> record at the given name containing the challenge token.</td><td className="muted">Domains you control DNS for</td></tr>
              <tr><td><span className="chip">FILE_DROP</span></td><td>A file at a well-known URL whose body is the token, served 200 over HTTPS.</td><td className="muted">Web apps &amp; URLs</td></tr>
              <tr><td><span className="chip">HTTP_HEADER</span></td><td>A response header, with the given name and token value, on the challenge URL.</td><td className="muted">Sites behind a proxy/CDN</td></tr>
            </tbody>
          </table></div>
        </div>
        <p>For assets you already own — your own suite — use the self-owned path (<code>OWNED</code>, or the
          <code> CHECKBOX</code> / <code>TYPED_CONFIRMATION</code> acknowledgements) instead of an external proof.</p>

        <h3>Attested, and staying that way</h3>
        <p>Once verified, a target is <span className="badge badge--ok"><span className="dot" />Attested</span> and
          scannable within an active engagement. Attestations can carry an <b>expiry</b>; after it, they lapse to
          <span className="badge badge--neutral"><span className="dot" />Expired</span> and the gate stops honoring
          them. A revoked target (<span className="badge badge--danger"><span className="dot" />Revoked</span>) is
          immediately un-scannable.</p>

        <Banner kind="warn">
          <div>Attestation is verified <b>live at attest time</b>. If a proof isn't reachable and correct at that moment,
            attestation fails — see <a href="#troubleshooting">Troubleshooting</a> for the usual culprits (DNS
            propagation, wrong path, header casing).</div>
        </Banner>
      </div>
    ),
  },

  {
    id: 'runs-engine',
    label: 'Runs & the engine',
    icon: PlayIcon,
    keywords: 'run runs strix engine execute start monitor status pending running failed stopped denied completed stop halt live cost mode autonomous scan progress',
    Body: () => (
      <div className="hlp-prose">
        <p>A <b>run</b> is one execution of the <b>Strix engine</b> against an engagement's attested targets. Starting a
          run submits it to the authorization gate first; only if the gate allows does the engine begin.</p>

        <h3>Run status</h3>
        <LifecycleFlow steps={[
          { label: 'Pending', cls: 'badge--warn' },
          { label: 'Running', cls: 'badge--info' },
          { label: 'Completed / Failed / Stopped', cls: 'badge--neutral' },
        ]} />
        <div className="hlp-table">
          <div className="tablewrap"><table className="tbl">
            <thead><tr><th>Status</th><th>Meaning</th></tr></thead>
            <tbody>
              <tr><td><span className="badge badge--warn"><span className="dot" />Pending</span></td><td>Authorized and queued; the engine hasn't started yet.</td></tr>
              <tr><td><span className="badge badge--info badge--live"><span className="dot" />Running</span></td><td>The Strix engine is actively executing against the targets.</td></tr>
              <tr><td><span className="badge badge--ok"><span className="dot" />Completed</span></td><td>The run finished; findings (if any) are attached.</td></tr>
              <tr><td><span className="badge badge--danger"><span className="dot" />Failed</span></td><td>The engine errored out before completing.</td></tr>
              <tr><td><span className="badge badge--danger"><span className="dot" />Stopped</span></td><td>You (or an engagement emergency-stop) halted it.</td></tr>
              <tr><td><span className="badge badge--danger"><span className="dot" />Denied</span></td><td>The gate refused the request — it never ran. See the FAQ.</td></tr>
            </tbody>
          </table></div>
        </div>

        <h3>Monitoring &amp; stopping</h3>
        <p>Open a run to watch its status live; a running engagement animates in the sidebar and Overview. You can
          <b> Stop</b> a run at any time, or emergency-stop the whole engagement to halt everything under it. Stops are
          honored as the engine unwinds in-flight work and are recorded to the audit chain.</p>

        <Banner kind="info">
          <div>A <b>Denied</b> run is not a failure of the engine — it's the gate doing its job. Nothing was executed.
            Fix the underlying authorization (active engagement, attested in-scope targets) and start again.</div>
        </Banner>
      </div>
    ),
  },

  {
    id: 'findings-brigade',
    label: 'Findings & Brigade hand-off',
    icon: BugIcon,
    keywords: 'findings severity info low medium high critical verify verified false positive triage evidence exploit chain remediation hand off handoff unicorn brigade tracking ticket remediate',
    Body: () => (
      <div className="hlp-prose">
        <p>Findings are what a run produces — discovered issues, each rated on the ordered severity heat ramp:</p>
        <SevRamp />

        <h3>Triage</h3>
        <p>Open a finding to review its evidence and, where present, the reconstructed <b>exploit chain</b>. Your job is
          to decide what's real:</p>
        <ul>
          <li><b>Verify</b> a finding once you've confirmed it's genuine and reproducible — it becomes
            <span className="badge badge--accent" style={{ marginLeft: 6 }}><span className="dot" />Verified</span>.</li>
          <li>Mark clear noise as <b>False positive</b> to take it out of the open count.</li>
        </ul>

        <h3>Hand off to Unicorn Brigade</h3>
        <p>Verified findings are handed off to <b>Unicorn Brigade</b> for remediation tracking — that's where the fix is
          owned, assigned, and followed to closure. Once handed off, a finding shows
          <span className="badge badge--ok" style={{ marginLeft: 6 }}><span className="dot" />Handed off</span> and its
          remediation lifecycle continues in Brigade.</p>

        <div className="hlp-flow">
          <span className="badge badge--info"><span className="dot" />New</span>
          <ChevronRightIcon size={15} className="hlp-flow__arrow" />
          <span className="badge badge--accent"><span className="dot" />Verified</span>
          <ChevronRightIcon size={15} className="hlp-flow__arrow" />
          <span className="badge badge--ok"><span className="dot" />Handed off</span>
          <ChevronRightIcon size={15} className="hlp-flow__arrow" />
          <span className="badge badge--ok"><span className="dot" />Remediated</span>
        </div>

        <Banner kind="info">
          <div>Prioritize by severity, but verify before you hand off — Brigade's queue is most useful when it holds
            confirmed, actionable work, not raw engine output.</div>
        </Banner>
      </div>
    ),
  },

  {
    id: 'agent-access',
    label: 'Agent access (MCP + PATs + Assistant)',
    icon: SparkIcon,
    keywords: 'agent access mcp model context protocol server personal access token pat secops_pat keycloak jwt bearer authorization header claude code claude.json mcpServers type http assistant in-app ai automation tools list curl mint revoke same gate agent-first',
    Body: () => {
      const claudeJson = `{
  "mcpServers": {
    "security-ops": {
      "type": "http",
      "url": "${MCP_URL}",
      "headers": {
        "Authorization": "Bearer ${PAT_PREFIX}your_token_here"
      }
    }
  }
}`;
      const cliAdd = `claude mcp add --transport http security-ops \\
  ${MCP_URL} \\
  --header "Authorization: Bearer ${PAT_PREFIX}your_token_here"`;
      const smoke = `curl -s ${MCP_URL} \\
  -H "Authorization: Bearer ${PAT_PREFIX}your_token_here" \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`;
      return (
        <div className="hlp-prose">
          <p>Security-Ops is <b>agent-first</b>: every capability in this console is also exposed to AI agents. There
            are three ways in, and all of them sit behind the same authorization gate.</p>
          <ul>
            <li><b>MCP server</b> — a Model Context Protocol endpoint an agent connects to as a tool source.</li>
            <li><b>In-app Assistant</b> — an assistant embedded in the console that operates the same actions on your behalf.</li>
            <li><b>Direct API</b> — the underlying REST endpoints, authenticated the same way.</li>
          </ul>

          <Banner kind="warn">
            <div><b>Agents do not bypass the gate.</b> A token authenticates <i>who</i> is calling; it never authorizes
              testing an unattested or out-of-scope asset. Every agent action is gated, scoped, and audited exactly like
              a human operator's.</div>
          </Banner>

          <h3>1 · Mint a Personal Access Token</h3>
          <ol className="hlp-steps">
            <li>Open <b>Settings › Agent access</b> (the account menu in the top-right) and choose <b>New token</b>.</li>
            <li>Name it for the agent that will use it and, optionally, set an expiry.</li>
            <li>Copy the token <b>immediately</b> — it starts with <code>{PAT_PREFIX}</code> and is shown <b>once</b>. Store it in your agent's secret store; if you lose it, revoke and re-mint.</li>
          </ol>
          <p>A uchub <b>Keycloak JWT</b> carrying the <code>security-ops</code> entitlement works as an alternative bearer,
            but JWTs are short-lived — PATs are the durable choice for long-running agents.</p>

          <h3>2 · Add the MCP server to your client</h3>
          <p>For <b>Claude Code</b>, add the server to your <code>~/.claude.json</code> under <code>mcpServers</code>:</p>
          <CodeBlock caption="~/.claude.json" text={claudeJson} />
          <p>Or add it from the CLI:</p>
          <CodeBlock caption="shell" text={cliAdd} />

          <h3>3 · Verify the connection</h3>
          <p>A quick <code>tools/list</code> round-trip confirms auth and reachability before you wire it into an agent:</p>
          <CodeBlock caption="smoke test" text={smoke} />

          <div className="hlp-table">
            <div className="tablewrap"><table className="tbl">
              <thead><tr><th>Field</th><th>Value</th></tr></thead>
              <tbody>
                <tr><td className="muted">Endpoint</td><td className="mono" style={{ wordBreak: 'break-all' }}>{MCP_URL}</td></tr>
                <tr><td className="muted">Transport</td><td className="mono">http</td></tr>
                <tr><td className="muted">Auth header</td><td className="mono" style={{ wordBreak: 'break-all' }}>Authorization: Bearer {PAT_PREFIX}…</td></tr>
                <tr><td className="muted">Alt auth</td><td>uchub Keycloak JWT (realm <span className="mono">uchub</span>, <span className="mono">security-ops</span> entitlement)</td></tr>
              </tbody>
            </table></div>
          </div>

          <h3>The in-app Assistant</h3>
          <p>Prefer to stay in the console? The embedded <b>Assistant</b> can drive the same flows conversationally —
            register and attest targets, start and stop runs, triage findings — while every action it takes still passes
            through the gate and lands in the audit chain. It's the same authority model, a different surface.</p>
        </div>
      );
    },
  },

  {
    id: 'keyboard-shortcuts',
    label: 'Keyboard shortcuts',
    icon: KeyboardIcon,
    keywords: 'keyboard shortcuts keys hotkeys navigation go to search focus escape close enter open row tab accessibility ' + SHORTCUTS.map((s) => s.keys.join(' ') + ' ' + s.desc + ' ' + s.keywords).join(' '),
    Body: ({ query }) => {
      const q = query.trim().toLowerCase();
      const rows = SHORTCUTS.filter((s) => !q ||
        (s.desc + ' ' + s.keywords + ' ' + s.keys.join(' ')).toLowerCase().includes(q));
      return (
        <div className="hlp-prose">
          <p>Move around the console without leaving the keyboard. Chorded shortcuts (like <Kbd>g</Kbd> then <Kbd>o</Kbd>)
            are pressed in sequence.</p>
          {rows.length === 0 ? (
            <p className="muted">No shortcuts match your search.</p>
          ) : (
            <div className="hlp-keys">
              {rows.map((s) => (
                <div className="hlp-keys__row" key={s.keys.join('+') + s.desc}>
                  <div className="hlp-keys__combo">
                    {s.keys.map((k, i) => (
                      <React.Fragment key={k + i}>
                        {i > 0 && <span className="hlp-keys__plus">then</span>}
                        <Kbd>{k}</Kbd>
                      </React.Fragment>
                    ))}
                  </div>
                  <div className="hlp-keys__desc">{s.desc}</div>
                </div>
              ))}
            </div>
          )}
          <Banner kind="info">
            <div>Shortcuts apply where the console supports them; <Kbd>Esc</Kbd> to close, <Kbd>Enter</Kbd> to open a
              focused row, and drawer <Kbd>Tab</Kbd>-trapping work throughout.</div>
          </Banner>
        </div>
      );
    },
  },

  {
    id: 'troubleshooting',
    label: 'Troubleshooting / FAQ',
    icon: InfoIcon,
    keywords: 'troubleshooting faq frequently asked questions problems errors denied blocked attestation failing 401 403 token expired revoked false positive stop run engagement expired help common issues ' + FAQ.map((f) => f.q + ' ' + f.keywords).join(' '),
    Body: ({ query }) => {
      const q = query.trim().toLowerCase();
      const items = FAQ.filter((f) => !q || (f.q + ' ' + f.keywords).toLowerCase().includes(q));
      return (
        <div className="hlp-prose">
          <p>The questions that come up most, and how to resolve them. Search above to filter.</p>
          {items.length === 0 ? (
            <p className="muted">No questions match your search.</p>
          ) : (
            <div className="hlp-faq">
              {items.map((f, i) => (
                <details key={f.q} open={!!q && items.length <= 3 ? true : i === 0 && !q ? false : undefined}>
                  <summary>
                    <span>{f.q}</span>
                    <ChevronRightIcon size={16} className="hlp-faq__chev" />
                  </summary>
                  <div className="hlp-faq__body">{f.a}</div>
                </details>
              ))}
            </div>
          )}
        </div>
      );
    },
  },

  {
    id: 'glossary',
    label: 'Glossary',
    icon: BookIcon,
    keywords: 'glossary terms definitions vocabulary meaning ' + GLOSSARY.map((g) => g.term + ' ' + g.def).join(' '),
    Body: ({ query }) => {
      const q = query.trim().toLowerCase();
      const items = GLOSSARY.filter((g) => !q || (g.term + ' ' + g.def).toLowerCase().includes(q));
      return (
        <div className="hlp-prose">
          <p>The vocabulary the console uses, in one place.</p>
          {items.length === 0 ? (
            <p className="muted">No terms match your search.</p>
          ) : (
            <div className="hlp-gloss">
              {items.map((g) => (
                <div className="hlp-gloss__item" key={g.term}>
                  <div className="hlp-gloss__term"><DotMark />{g.term}</div>
                  <div className="hlp-gloss__def">{g.def}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    },
  },
];

function DotMark() {
  return <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-strong)', flex: 'none', boxShadow: '0 0 8px var(--accent-glow)' }} />;
}

/* ------------------------------------------------------------------ Active-section tracking */

function useActiveSection(ids, deps) {
  const [active, setActive] = React.useState(ids[0]);
  React.useEffect(() => {
    const els = ids.map((id) => document.getElementById(id)).filter(Boolean);
    if (!els.length) return undefined;
    const visible = new Map();
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) visible.set(e.target.id, e.intersectionRatio);
        else visible.delete(e.target.id);
      });
      // Choose the topmost visible section (first in document order that's intersecting).
      const firstVisible = ids.find((id) => visible.has(id));
      if (firstVisible) setActive(firstVisible);
    }, { rootMargin: '-84px 0px -60% 0px', threshold: [0, 0.25, 0.5, 1] });
    els.forEach((el) => obs.observe(el));
    return () => obs.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return [active, setActive];
}

/* ------------------------------------------------------------------ Page */

export default function Help() {
  const [query, setQuery] = React.useState('');
  const searchRef = React.useRef(null);

  const q = query.trim().toLowerCase();
  const visibleSections = React.useMemo(
    () => SECTIONS.filter((s) => !q || (s.label + ' ' + s.keywords).toLowerCase().includes(q)),
    [q],
  );

  const visibleIds = visibleSections.map((s) => s.id);
  const [active, setActive] = useActiveSection(visibleIds, [visibleIds.join(',')]);

  // Honor a deep-link hash (e.g. /help#agent-access from HELP_TOPICS) on mount.
  React.useEffect(() => {
    const id = window.location.hash.replace('#', '');
    if (!id) return;
    // Defer to next frame so the section elements are mounted.
    const t = requestAnimationFrame(() => {
      const el = document.getElementById(id);
      if (el) { el.scrollIntoView({ block: 'start' }); setActive(id); }
    });
    return () => cancelAnimationFrame(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // "/" focuses the search box (matching the console's search convention).
  React.useEffect(() => {
    function onKey(e) {
      if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  function goTo(e, id) {
    e.preventDefault();
    setActive(id);
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (window.history?.replaceState) window.history.replaceState(null, '', `#${id}`);
    }
  }

  return (
    <div className="page">
      <div className="page__head">
        <div className="page__head-main">
          <div className="page__title">
            <h1 className="display" style={{ fontSize: 24 }}>Help &amp; documentation</h1>
            <span className="badge badge--accent"><span className="dot" />Canonical</span>
          </div>
          <p className="page__sub">
            How Security-Ops works, end to end — the authorization gate, engagements, targets and attestation, runs,
            findings, and the agent-first MCP surface. Search to jump straight to an answer.
          </p>
        </div>
      </div>

      <div className="hlp">
        {/* Sticky table of contents */}
        <nav className="hlp__toc" aria-label="Help contents">
          <div className="hlp__toc-label">On this page</div>
          {visibleSections.length === 0 ? (
            <div className="hlp__toc-empty">No sections match.</div>
          ) : (
            <ul className="hlp__toc-list">
              {visibleSections.map((s, i) => (
                <li key={s.id}>
                  <a
                    href={`#${s.id}`}
                    className={`hlp__toc-link ${active === s.id ? 'is-active' : ''}`}
                    aria-current={active === s.id ? 'true' : undefined}
                    onClick={(e) => goTo(e, s.id)}
                  >
                    <span className="hlp__toc-num">{String(i + 1).padStart(2, '0')}</span>
                    <span className="grow">{s.label}</span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </nav>

        {/* Content column */}
        <div className="hlp__main">
          <div className="hlp__search">
            <SearchIcon size={17} className="hlp__search-ic" />
            <input
              ref={searchRef}
              className="input"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search the docs — gate, attestation, MCP, denied run, PAT…  ( / )"
              aria-label="Search help"
            />
            {query && (
              <div className="hlp__search-clear">
                <button className="iconbtn" onClick={() => { setQuery(''); searchRef.current?.focus(); }} aria-label="Clear search" title="Clear">
                  <XIcon size={15} />
                </button>
              </div>
            )}
            {q && (
              <div className="hlp__search-count">
                {visibleSections.length === 0
                  ? 'No sections match your search.'
                  : `${visibleSections.length} section${visibleSections.length === 1 ? '' : 's'} match “${query.trim()}”.`}
              </div>
            )}
          </div>

          {visibleSections.length === 0 ? (
            <div className="card"><div className="card__body">
              <div className="empty">
                <div className="empty__icon"><SearchIcon /></div>
                <h3>Nothing found</h3>
                <p className="muted" style={{ maxWidth: '42ch', margin: '0 auto' }}>
                  No help section matches “{query.trim()}”. Try a broader term, or clear the search to see everything.
                </p>
              </div>
            </div></div>
          ) : (
            visibleSections.map((s, i) => {
              const Body = s.Body;
              const Icon = s.icon;
              return (
                <section key={s.id} id={s.id} className="hlp-section">
                  <div className="hlp-section__head">
                    <div className="hlp-section__ic"><Icon size={17} /></div>
                    <h2>{s.label}</h2>
                    <span className="hlp-section__num">{String(i + 1).padStart(2, '0')} / {String(visibleSections.length).padStart(2, '0')}</span>
                  </div>
                  <Body query={query} />
                </section>
              );
            })
          )}

          <hr className="hlp-hr" />
          <p className="muted" style={{ fontSize: 12.5 }}>
            Security-Ops is for <b>authorized</b> testing only. If you can't attest authorization for an asset, you
            can't test it — by design.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Topbar button */

export function HelpButton({ className }) {
  const navigate = useNavigate();
  return (
    <button
      className={className || 'iconbtn'}
      type="button"
      onClick={() => navigate('/help')}
      title="Help & documentation"
      aria-label="Help and documentation"
    >
      <HelpIcon size={17} />
    </button>
  );
}
