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
