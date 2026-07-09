/* API client. Speaks the real /api/v1 surface, or an in-memory demo backend when
 * demo mode is on (?demo=1 or localStorage('secops_demo')). All errors are
 * normalized to Error{code, message, detail, status}. */
import { demoHandle } from './demo.js';

const API = '/api/v1';

export function isDemo() {
  try {
    const q = new URLSearchParams(window.location.search);
    if (q.get('demo') === '1') { localStorage.setItem('secops_demo', '1'); }
    if (q.get('demo') === '0') { localStorage.removeItem('secops_demo'); }
    return localStorage.getItem('secops_demo') === '1';
  } catch { return false; }
}

export function getToken() { try { return localStorage.getItem('secops_token') || ''; } catch { return ''; } }
export function setToken(t) {
  try { if (t && t.trim()) localStorage.setItem('secops_token', t.trim()); else localStorage.removeItem('secops_token'); } catch { /* ignore */ }
}

function toError(envOrMsg, status) {
  const env = typeof envOrMsg === 'object' && envOrMsg ? envOrMsg : {};
  const err = new Error(env.message || (typeof envOrMsg === 'string' ? envOrMsg : `Request failed (${status})`));
  err.code = env.code || 'error';
  err.detail = env.detail || null;
  err.status = status || 0;
  return err;
}

export async function api(path, { method = 'GET', body } = {}) {
  if (isDemo()) {
    try { return await demoHandle(method, path, body); }
    catch (e) { throw toError({ message: e.message, code: e.code }, e.status || 500); }
  }
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(API + path, { method, headers, body: body != null ? JSON.stringify(body) : undefined });
  } catch (e) {
    throw toError({ message: 'Network error — is the API reachable?', code: 'network' }, 0);
  }
  const ct = res.headers.get('content-type') || '';
  const raw = await res.text();
  let data = null;
  if (ct.includes('application/json')) { try { data = raw ? JSON.parse(raw) : null; } catch { data = null; } }
  else { data = raw; }
  if (!res.ok) throw toError((data && data.error) || {}, res.status);
  return data;
}

export const apiGet = (p) => api(p);
export const apiPost = (p, body) => api(p, { method: 'POST', body });

/* Parse one raw SSE frame ("id: N\nevent: T\ndata: {…}") into {id, event, data}.
 * Returns null for a heartbeat/comment frame (every line starts with ':'). */
function parseSseFrame(frame) {
  let id = null; let event = 'message'; const dataLines = [];
  let sawField = false;
  for (const line of frame.split('\n')) {
    if (!line || line.startsWith(':')) continue; // comment / heartbeat
    const c = line.indexOf(':');
    const field = c === -1 ? line : line.slice(0, c);
    const val = c === -1 ? '' : line.slice(c + 1).replace(/^ /, '');
    if (field === 'id') { id = val; sawField = true; }
    else if (field === 'event') { event = val; sawField = true; }
    else if (field === 'data') { dataLines.push(val); sawField = true; }
  }
  if (!sawField) return null;
  let data = dataLines.join('\n');
  try { data = data ? JSON.parse(data) : null; } catch { /* keep raw string */ }
  return { id: id != null ? Number(id) : null, event, data };
}

/* Stream a run's live trace (Server-Sent Events) via fetch — EventSource can't
 * carry our Bearer header, so we read the body stream and split SSE frames by
 * hand. Calls onEvent({id,event,data}) per event, onEnd(data) on the terminal
 * 'end' frame. Resumes from afterSeq (Last-Event-ID). Abort with the signal.
 * Demo mode synthesizes a short canned trace so the panel is demoable offline. */
export async function streamRunEvents(runId, { afterSeq = 0, signal, onEvent, onEnd } = {}) {
  if (isDemo()) { await demoTrace(runId, { onEvent, onEnd, signal }); return; }
  const headers = { Accept: 'text/event-stream' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (afterSeq) headers['Last-Event-ID'] = String(afterSeq);

  const res = await fetch(API + `/runs/${runId}/events`, { headers, signal });
  if (!res.ok || !res.body) throw toError({ code: 'stream', message: `Trace stream failed (${res.status})` }, res.status);

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const ev = parseSseFrame(buf.slice(0, idx));
        buf = buf.slice(idx + 2);
        if (!ev) continue;
        if (ev.event === 'end') { onEnd && onEnd(ev.data); return; }
        onEvent && onEvent(ev);
      }
    }
  } finally {
    try { reader.cancel(); } catch { /* ignore */ }
  }
}

/* A small synthetic trace for demo mode (no backend). Best-effort + abortable. */
async function demoTrace(runId, { onEvent, onEnd, signal }) {
  let run = null;
  try { run = await demoHandle('GET', `/runs/${runId}`); } catch { /* ignore */ }
  const targets = (run && run.targets) || ['https://example.com'];
  const steps = [
    { event: 'queued', data: { message: `run queued over ${targets.length} target(s)` } },
    { event: 'running', data: { message: `strix run started · ${targets[0]}` } },
    { event: 'engine_spawned', data: { message: 'engine subprocess spawned' } },
    { event: 'reasoning', data: { message: 'recon: enumerating endpoints and auth surface' } },
    { event: 'reasoning', data: { message: 'probing login form for injection / auth bypass' } },
    { event: 'finding', data: { message: '[high] Reflected XSS on /search' } },
    { event: 'reasoning', data: { message: 'verifying candidate findings with the verify model' } },
    { event: 'completed', data: { message: 'run completed' } },
  ];
  let seq = 0;
  for (const s of steps) {
    if (signal && signal.aborted) return;
    await new Promise((r) => setTimeout(r, 450));
    onEvent && onEvent({ id: ++seq, event: s.event, data: s.data });
  }
  onEnd && onEnd({ status: 'COMPLETED' });
}
