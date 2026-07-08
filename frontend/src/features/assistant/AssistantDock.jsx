/* AssistantDock — an in-app AI assistant chat dock for the Security-Ops console.
 *
 * Self-mounting: a floating launcher (bottom-right, clear of the authorization
 * gate) opens a right-side chat panel. The assistant streams answers from the
 * Security-Ops engine over SSE and proposes write actions as suggestion chips —
 * it never executes them itself; clicking a chip navigates the operator there.
 *
 * Drop <AssistantDock/> once, anywhere inside the Router (App.jsx). It owns its
 * own state and persistence and renders nothing that intrudes until opened.
 *
 * SSE contract (POST /api/v1/assistant/chat, body {messages:[{role,content}]}):
 *   response is text/event-stream; each event is a `data: {json}` line where json is
 *     { "delta": "…" }                              → append streamed text
 *     { "done": true, "suggestions": [{label,href}] } → finalize + render chips
 *     { "error": "…" }                              → surface an inline error
 *
 * localStorage keys (all prefixed secops_assistant_):
 *   secops_assistant_open      "1" | "0"   panel open state
 *   secops_assistant_messages  JSON        message history [{role,content,suggestions?}]
 *   secops_assistant_width     number(px)  panel width
 */
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { isDemo, getToken } from '../../lib/api.js';
import { SparkIcon, XIcon, PlusIcon, StopIcon, ArrowRightIcon } from '../../components/icons.jsx';
import Markdown from './Markdown.jsx';
import './assistant.css';

const LS_OPEN = 'secops_assistant_open';
const LS_MSGS = 'secops_assistant_messages';
const LS_WIDTH = 'secops_assistant_width';

const MIN_W = 340;
const MAX_W = 720;
const DEFAULT_W = 400;

const STARTERS = [
  'What can you do?',
  'Explain the authorization gate',
  'Summarize my open findings',
  'How do I attest a target?',
];

/* ---- persistence helpers -------------------------------------------------- */
function readMsgs() {
  try {
    const raw = localStorage.getItem(LS_MSGS);
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}
function readWidth() {
  try {
    const n = parseInt(localStorage.getItem(LS_WIDTH) || '', 10);
    if (Number.isFinite(n)) return Math.min(MAX_W, Math.max(MIN_W, n));
  } catch { /* ignore */ }
  return DEFAULT_W;
}
function readOpen() {
  try { return localStorage.getItem(LS_OPEN) === '1'; } catch { return false; }
}

/* ---- demo backend: a short canned, streamed reply ------------------------- */
const DEMO_REPLY = `I'm the **Security-Ops assistant**, wired to this console. I can:

- Explain how the **authorization gate** enforces scope before any run
- Summarize your **open findings** by severity and status
- Walk you through **attesting a target** so it's in scope
- Point you to the right screen for whatever you're doing

I never run scans or change records myself — when an action makes sense I'll surface it as a chip you can click.

\`\`\`text
demo mode · no backend calls · fully local
\`\`\`

Try one of the suggestions below, or ask me anything.`;

function demoStream({ onDelta, onDone, signal }) {
  // Chunk the canned reply into word-ish tokens and emit them on a timer so the
  // typing animation is real, respecting AbortController for the Stop button.
  const tokens = DEMO_REPLY.match(/\S+\s*|\s+/g) || [DEMO_REPLY];
  let i = 0;
  let timer = null;
  const stop = () => { if (timer) { clearTimeout(timer); timer = null; } };
  if (signal) signal.addEventListener('abort', stop, { once: true });
  const tick = () => {
    if (signal && signal.aborted) return;
    if (i >= tokens.length) {
      onDone({ suggestions: [
        { label: 'View findings', href: '/findings' },
        { label: 'Open targets', href: '/targets' },
      ] });
      return;
    }
    onDelta(tokens[i]);
    i += 1;
    timer = setTimeout(tick, 22);
  };
  timer = setTimeout(tick, 120);
}

/* ---- live backend: fetch + parse text/event-stream ------------------------ */
async function liveStream({ messages, onDelta, onDone, onError, signal }) {
  let res;
  try {
    res = await fetch('/api/v1/assistant/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      },
      body: JSON.stringify({ messages }),
      signal,
    });
  } catch (e) {
    if (signal && signal.aborted) return;
    onError('Network error — is the API reachable?');
    return;
  }
  if (!res.ok || !res.body) {
    onError(`The assistant is unavailable right now (${res.status || 'no response'}).`);
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finished = false;

  const handleData = (jsonStr) => {
    let evt;
    try { evt = JSON.parse(jsonStr); } catch { return; }
    if (evt.error) { onError(String(evt.error)); finished = true; return; }
    if (typeof evt.delta === 'string') { onDelta(evt.delta); return; }
    if (evt.done) { onDone({ suggestions: Array.isArray(evt.suggestions) ? evt.suggestions : [] }); finished = true; }
  };

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // SSE events are separated by a blank line; each may carry multiple `data:` lines.
      let sep;
      while ((sep = buffer.indexOf('\n\n')) !== -1) {
        const rawEvent = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        for (const line of rawEvent.split('\n')) {
          const trimmed = line.replace(/\r$/, '');
          if (trimmed.startsWith('data:')) handleData(trimmed.slice(5).trim());
        }
      }
    }
    // Flush any trailing single-line data without a terminating blank line.
    if (!finished && buffer.trim()) {
      for (const line of buffer.split('\n')) {
        const trimmed = line.replace(/\r$/, '');
        if (trimmed.startsWith('data:')) handleData(trimmed.slice(5).trim());
      }
    }
  } catch (e) {
    if (signal && signal.aborted) return;
    onError('The assistant connection was interrupted.');
    return;
  }
  if (!finished) onDone({ suggestions: [] });
}

/* ========================================================================== */
export default function AssistantDock() {
  const navigate = useNavigate();
  const [open, setOpen] = React.useState(readOpen);
  const [messages, setMessages] = React.useState(readMsgs);
  const [input, setInput] = React.useState('');
  const [streaming, setStreaming] = React.useState(false);
  const [unread, setUnread] = React.useState(false);
  const [width, setWidth] = React.useState(readWidth);

  const scrollRef = React.useRef(null);
  const textareaRef = React.useRef(null);
  const launcherRef = React.useRef(null);
  const abortRef = React.useRef(null);
  const openRef = React.useRef(open);
  openRef.current = open;

  /* persist */
  React.useEffect(() => { try { localStorage.setItem(LS_OPEN, open ? '1' : '0'); } catch { /* ignore */ } }, [open]);
  React.useEffect(() => { try { localStorage.setItem(LS_MSGS, JSON.stringify(messages.slice(-60))); } catch { /* ignore */ } }, [messages]);
  React.useEffect(() => { try { localStorage.setItem(LS_WIDTH, String(width)); } catch { /* ignore */ } }, [width]);

  /* abort any in-flight stream on unmount */
  React.useEffect(() => () => abortRef.current?.abort(), []);

  const scrollDown = React.useCallback(() => {
    requestAnimationFrame(() => { const el = scrollRef.current; if (el) el.scrollTop = el.scrollHeight; });
  }, []);

  /* focus the composer when the panel opens; clear the unread pulse */
  React.useEffect(() => {
    if (!open) return;
    setUnread(false);
    const t = setTimeout(() => { textareaRef.current?.focus(); scrollDown(); }, 30);
    return () => clearTimeout(t);
  }, [open, scrollDown]);

  const closePanel = React.useCallback(() => {
    setOpen(false);
    requestAnimationFrame(() => launcherRef.current?.focus());
  }, []);

  /* Esc closes the panel (only while open) */
  React.useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); closePanel(); } };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, closePanel]);

  const stop = React.useCallback(() => { abortRef.current?.abort(); }, []);

  const send = React.useCallback((override) => {
    const content = (override ?? input).trim();
    if (!content || streaming) return;
    setInput('');

    const history = [...messages, { role: 'user', content }];
    setMessages([...history, { role: 'assistant', content: '' }]);
    setStreaming(true);
    scrollDown();

    const controller = new AbortController();
    abortRef.current = controller;

    const appendDelta = (chunk) => {
      setMessages((m) => {
        const next = m.slice();
        const last = next[next.length - 1];
        if (last && last.role === 'assistant') next[next.length - 1] = { ...last, content: last.content + chunk };
        return next;
      });
      scrollDown();
    };
    const finalize = ({ suggestions } = {}) => {
      setMessages((m) => {
        const next = m.slice();
        const last = next[next.length - 1];
        if (last && last.role === 'assistant') {
          const clean = (suggestions || []).filter((s) => s && s.label && s.href);
          next[next.length - 1] = {
            ...last,
            content: last.content || 'Done.',
            suggestions: clean.length ? clean : undefined,
          };
        }
        return next;
      });
      setStreaming(false);
      abortRef.current = null;
      scrollDown();
      if (!openRef.current) setUnread(true);
    };
    const fail = (msg) => {
      setMessages((m) => {
        const next = m.slice();
        const last = next[next.length - 1];
        if (last && last.role === 'assistant') {
          next[next.length - 1] = { ...last, content: last.content ? `${last.content}\n\n_${msg}_` : `_${msg}_`, error: true };
        }
        return next;
      });
      setStreaming(false);
      abortRef.current = null;
      scrollDown();
      if (!openRef.current) setUnread(true);
    };

    if (isDemo()) {
      demoStream({ onDelta: appendDelta, onDone: finalize, signal: controller.signal });
    } else {
      liveStream({
        messages: history.map(({ role, content: c }) => ({ role, content: c })),
        onDelta: appendDelta,
        onDone: finalize,
        onError: fail,
        signal: controller.signal,
      });
    }
  }, [input, streaming, messages, scrollDown]);

  const newChat = React.useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setStreaming(false);
    setMessages([]);
    setInput('');
    requestAnimationFrame(() => textareaRef.current?.focus());
  }, []);

  const onSuggestion = React.useCallback((href) => {
    if (!href) return;
    navigate(href);
    // Keep the dock open so the operator can keep the conversation going.
  }, [navigate]);

  /* auto-grow the composer */
  const onInput = (e) => {
    setInput(e.target.value);
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
  };
  React.useEffect(() => {
    // reset height when input is cleared programmatically
    if (input === '' && textareaRef.current) textareaRef.current.style.height = 'auto';
  }, [input]);

  /* ---- resize handle ------------------------------------------------------ */
  const dragRef = React.useRef(null);
  const startResize = (e) => {
    e.preventDefault();
    const startX = e.clientX;
    const startW = width;
    dragRef.current = { startX, startW };
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'ew-resize';
    const onMove = (ev) => {
      const d = dragRef.current; if (!d) return;
      const next = Math.min(MAX_W, Math.max(MIN_W, d.startW + (d.startX - ev.clientX)));
      setWidth(next);
    };
    const onUp = () => {
      dragRef.current = null;
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };
  const resizeKey = (e) => {
    if (e.key === 'ArrowLeft') { e.preventDefault(); setWidth((w) => Math.min(MAX_W, w + 16)); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); setWidth((w) => Math.max(MIN_W, w - 16)); }
  };

  return (
    <>
      {/* Launcher — bottom-right, aurora + glow, unread pulse */}
      <button
        ref={launcherRef}
        type="button"
        className={`sa-launcher ${open ? 'is-open' : ''} ${unread ? 'has-unread' : ''}`}
        aria-label={open ? 'Close assistant' : 'Open assistant'}
        aria-expanded={open}
        onClick={() => (open ? closePanel() : setOpen(true))}
      >
        <span className="sa-launcher__glow" aria-hidden="true" />
        {open ? <XIcon size={20} /> : <SparkIcon size={20} />}
        {unread && !open && <span className="sa-launcher__dot" aria-hidden="true" />}
      </button>

      {open && (
        <section
          className="sa-panel"
          role="dialog"
          aria-label="Security-Ops assistant"
          style={{ width }}
        >
          <div
            className="sa-panel__resize"
            role="separator"
            aria-label="Resize assistant panel"
            aria-orientation="vertical"
            tabIndex={0}
            onMouseDown={startResize}
            onKeyDown={resizeKey}
          />

          {/* Header */}
          <header className="sa-head">
            <div className="sa-head__title">
              <span className="sa-head__spark" aria-hidden="true"><SparkIcon size={16} /></span>
              <div className="sa-head__text">
                <div className="sa-head__name">Assistant</div>
                <div className="sa-head__sub">Powered by the Security-Ops engine</div>
              </div>
            </div>
            <div className="sa-head__actions">
              <button type="button" className="sa-iconbtn" onClick={newChat} title="New chat" aria-label="New chat">
                <PlusIcon size={16} />
              </button>
              <button type="button" className="sa-iconbtn" onClick={closePanel} title="Close (Esc)" aria-label="Close assistant">
                <XIcon size={16} />
              </button>
            </div>
          </header>

          {/* Messages */}
          <div className="sa-log" ref={scrollRef} role="log" aria-live="polite" aria-relevant="additions text">
            {messages.length === 0 ? (
              <div className="sa-empty">
                <div className="sa-empty__mark" aria-hidden="true"><SparkIcon size={22} /></div>
                <h3>How can I help?</h3>
                <p>Ask about your engagements, targets, runs, or findings. I propose actions — you approve them.</p>
                <div className="sa-empty__starters">
                  {STARTERS.map((q) => (
                    <button key={q} type="button" className="sa-starter" onClick={() => send(q)}>{q}</button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m, i) => (
                m.role === 'user' ? (
                  <div className="sa-msg sa-msg--user" key={i}>
                    <div className="sa-bubble sa-bubble--user">{m.content}</div>
                  </div>
                ) : (
                  <div className="sa-msg sa-msg--assistant" key={i}>
                    <div className="sa-bubble sa-bubble--assistant">
                      {m.content
                        ? <Markdown content={m.content} />
                        : <span className="sa-typing" aria-label="Assistant is typing"><i /><i /><i /></span>}
                    </div>
                    {m.suggestions && m.suggestions.length > 0 && (
                      <div className="sa-suggestions">
                        {m.suggestions.map((s, si) => (
                          <button key={si} type="button" className="sa-chip" onClick={() => onSuggestion(s.href)}>
                            {s.label}
                            <ArrowRightIcon size={13} />
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )
              ))
            )}
          </div>

          {/* Composer */}
          <div className="sa-composer">
            <textarea
              ref={textareaRef}
              className="sa-input"
              value={input}
              onChange={onInput}
              rows={1}
              placeholder="Ask the assistant…"
              disabled={streaming}
              aria-label="Message the assistant"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
              }}
            />
            {streaming ? (
              <button type="button" className="sa-send sa-send--stop" onClick={stop} title="Stop" aria-label="Stop generating">
                <StopIcon size={15} />
              </button>
            ) : (
              <button type="button" className="sa-send" onClick={() => send()} disabled={!input.trim()} title="Send" aria-label="Send message">
                <ArrowRightIcon size={16} />
              </button>
            )}
          </div>
        </section>
      )}
    </>
  );
}
