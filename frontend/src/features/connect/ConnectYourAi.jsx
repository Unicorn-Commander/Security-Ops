import React from 'react';
import { CopyButton } from '../../components/ui.jsx';
import { FileIcon, ShieldIcon, SparkIcon } from '../../components/icons.jsx';
import './connect-your-ai.css';

const PAT_PREFIX = 'secops_pat_';
const CONFIGURED_MCP_URL = (import.meta.env.VITE_MCP_URL || '').trim();

function getMcpUrl(value = CONFIGURED_MCP_URL) {
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const raw = value || origin;
  if (!raw) return '/mcp/';

  try {
    const url = new URL(raw, origin || undefined);
    url.pathname = `${url.pathname.replace(/\/+$/, '') || '/mcp'}/`;
    url.hash = '';
    return url.toString();
  } catch {
    return raw.endsWith('/') ? raw : `${raw}/`;
  }
}

// VITE_MCP_URL is the ring-specific public endpoint when supplied at build time.
// The browser-origin fallback keeps an unset build correct on either public ring.
export const MCP_URL = getMcpUrl();

const TABS = [
  { id: 'claude-code', label: 'Claude Code' },
  { id: 'claude-desktop', label: 'Claude Desktop / claude.ai' },
  { id: 'chatgpt', label: 'ChatGPT' },
  { id: 'mcp-json', label: 'Cursor / Codex / other' },
];

function CodeBlock({ caption, text }) {
  return (
    <div className="connect-ai__code">
      <div className="connect-ai__code-head">
        <span><FileIcon size={13} />{caption}</span>
        <CopyButton text={text} label="Copy" className="btn btn--ghost btn--sm" />
      </div>
      <pre className="code">{text}</pre>
    </div>
  );
}

function Choice({ label, tone = 'oauth', children }) {
  return (
    <div className="connect-ai__choice">
      <div className="connect-ai__choice-head">
        <span className={`connect-ai__choice-mark connect-ai__choice-mark--${tone}`} aria-hidden="true" />
        <b>{label}</b>
      </div>
      {children}
    </div>
  );
}

function ClaudeCodeTab() {
  const oauthCommand = `claude mcp add --transport http security-ops ${MCP_URL}`;
  const tokenCommand = `claude mcp add --transport http security-ops ${MCP_URL} \\
  --header "Authorization: Bearer ${PAT_PREFIX}your_token_here"`;

  return (
    <>
      <p className="connect-ai__lead">Choose browser sign-in for an interactive session, or paste a Personal Access Token for a headless workflow.</p>
      <div className="connect-ai__choices">
        <Choice label="OAuth · browser sign-in">
          <p>Run this command with no header. Claude Code opens a browser window and asks you to sign in.</p>
          <CodeBlock caption="shell" text={oauthCommand} />
        </Choice>
        <Choice label="Personal Access Token" tone="token">
          <p>For CI or another non-interactive workflow, replace the placeholder with a token minted below.</p>
          <CodeBlock caption="shell" text={tokenCommand} />
        </Choice>
      </div>
    </>
  );
}

function ClaudeDesktopTab() {
  return (
    <div className="connect-ai__instructions">
      <p className="connect-ai__lead">Use the hosted connector flow; your browser handles sign-in before the client can call Security-Ops.</p>
      <ol>
        <li>Open <b>Settings → Connectors → Add custom connector → URL</b>.</li>
        <li>Enter the canonical MCP URL below.</li>
        <li>Complete the sign-in prompt when it appears.</li>
      </ol>
      <div className="connect-ai__inline-url"><span className="muted">URL</span><code>{MCP_URL}</code><CopyButton text={MCP_URL} label="Copy URL" className="btn btn--ghost btn--sm" /></div>
    </div>
  );
}

function ChatGptTab() {
  return (
    <div className="connect-ai__instructions">
      <p className="connect-ai__lead">ChatGPT uses a custom connector URL and prompts for sign-in as it establishes the connection.</p>
      <ol>
        <li>Open <b>Settings → Connectors → Developer mode → New connector → URL</b>.</li>
        <li>Paste the canonical MCP URL below and save the connector.</li>
        <li>Complete the sign-in prompt before using the connector in a chat.</li>
      </ol>
      <div className="connect-ai__inline-url"><span className="muted">URL</span><code>{MCP_URL}</code><CopyButton text={MCP_URL} label="Copy URL" className="btn btn--ghost btn--sm" /></div>
    </div>
  );
}

function McpJsonTab() {
  const mcpJson = `{
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

  return (
    <div className="connect-ai__instructions">
      <p className="connect-ai__lead">For clients that use an <code>mcp.json</code>, add an HTTP server and replace the placeholder with a token minted below. Keep the file private.</p>
      <CodeBlock caption="mcp.json" text={mcpJson} />
      <p className="connect-ai__hint">If your client supports browser-based MCP sign-in, omit the <code>headers</code> object and follow its OAuth prompt instead.</p>
    </div>
  );
}

function TabBody({ id }) {
  if (id === 'claude-code') return <ClaudeCodeTab />;
  if (id === 'claude-desktop') return <ClaudeDesktopTab />;
  if (id === 'chatgpt') return <ChatGptTab />;
  return <McpJsonTab />;
}

export default function ConnectYourAiPanel() {
  const [active, setActive] = React.useState(TABS[0].id);
  const tabRefs = React.useRef([]);
  const activeTabIndex = TABS.findIndex((tab) => tab.id === active);

  function selectTab(id, focus = false) {
    setActive(id);
    if (focus) {
      const nextIndex = TABS.findIndex((tab) => tab.id === id);
      tabRefs.current[nextIndex]?.focus();
    }
  }

  function onTabKeyDown(event) {
    let nextIndex = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (activeTabIndex + 1) % TABS.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (activeTabIndex - 1 + TABS.length) % TABS.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = TABS.length - 1;
    if (nextIndex == null) return;
    event.preventDefault();
    selectTab(TABS[nextIndex].id, true);
  }

  const panelId = `connect-ai-panel-${active}`;

  return (
    <section className="connect-ai" aria-labelledby="connect-ai-title">
      <div className="connect-ai__head">
        <div className="connect-ai__icon"><SparkIcon size={18} /></div>
        <div>
          <div className="connect-ai__eyebrow">Agent access</div>
          <h2 id="connect-ai-title">Connect your AI</h2>
          <p>Connect a supported client to the Security-Ops MCP server with the same permissions as your operator account.</p>
        </div>
      </div>

      <div className="connect-ai__endpoint">
        <div>
          <span className="connect-ai__endpoint-label">Canonical MCP URL</span>
          <code>{MCP_URL}</code>
        </div>
        <CopyButton text={MCP_URL} label="Copy URL" className="btn btn--ghost btn--sm" />
      </div>

      <div className="connect-ai__tabs" role="tablist" aria-label="AI client setup" onKeyDown={onTabKeyDown}>
        {TABS.map((tab, index) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active === tab.id}
            aria-controls={panelId}
            tabIndex={active === tab.id ? 0 : -1}
            ref={(element) => { tabRefs.current[index] = element; }}
            className="connect-ai__tab"
            onClick={() => selectTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="connect-ai__body" id={panelId} role="tabpanel" aria-label={`${TABS[activeTabIndex].label} setup`}>
        <TabBody id={active} />
      </div>

      <div className="connect-ai__note">
        <ShieldIcon size={16} />
        <span>Your AI gets your permissions and nothing more; revoke any time below.</span>
      </div>
    </section>
  );
}
