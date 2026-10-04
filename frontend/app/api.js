// Fetch wrapper for the Sealdesk API. It never throws: every call resolves to
// {ok, status, data, text, headers, ms, error}. status 0 means network failure or timeout.

// The admin token lives in sessionStorage: it survives a reload of this tab but dies with the
// browser session, so a shared machine does not keep admin authority after the tab is closed.
const TOKEN_KEY = 'agentshield.adminToken';
let memoryToken = '';

try { localStorage.removeItem(TOKEN_KEY); } catch { /* legacy persistent copy; storage may be blocked */ }

export function getAdminToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || memoryToken;
  } catch {
    return memoryToken;
  }
}

/** @returns {boolean} true when the token was also stored for reloads of this tab. */
export function setAdminToken(value) {
  memoryToken = value || '';
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
    return true;
  } catch {
    return false;
  }
}

function errorMessage(status, data, text) {
  if (data && typeof data === 'object') {
    const e = data.error;
    if (e && typeof e === 'object' && typeof e.message === 'string') return e.message;
    if (typeof e === 'string') return e;
    if (typeof data.detail === 'string') return data.detail;
  }
  if (status === 401) return 'admin token required (set it under Settings)';
  if (status === 404) return 'endpoint not available on this gateway';
  if (typeof text === 'string' && text && text.length < 200 && !text.trimStart().startsWith('<')) return text;
  return `HTTP ${status}`;
}

/**
 * @param {string} path same-origin path, e.g. "/api/snapshot"
 * @param {{method?: string, body?: unknown, headers?: Record<string,string>, timeout?: number,
 *          as?: 'json'|'text', signal?: AbortSignal}} [opts]
 */
export async function api(path, opts = {}) {
  const { method = 'GET', body, headers = {}, timeout = 5000, as = 'json', signal } = opts;
  const started = performance.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  const onOuterAbort = () => ctrl.abort();
  try {
    if (signal) {
      if (signal.aborted) ctrl.abort();
      else signal.addEventListener('abort', onOuterAbort, { once: true });
    }
    const h = { Accept: as === 'json' ? 'application/json' : 'text/plain, */*', ...headers };
    const token = getAdminToken();
    if (token && path.startsWith('/api/') && !('X-Admin-Token' in h)) h['X-Admin-Token'] = token;
    let payload;
    if (body !== undefined) {
      h['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const res = await fetch(path, {
      method, headers: h, body: payload, signal: ctrl.signal, credentials: 'same-origin', cache: 'no-store',
    });
    const text = await res.text();
    let data = text;
    if (as === 'json') {
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = null;
      }
    }
    return {
      ok: res.ok, status: res.status, data, text, headers: res.headers,
      ms: performance.now() - started, error: res.ok ? null : errorMessage(res.status, data, text),
    };
  } catch (err) {
    const aborted = err && err.name === 'AbortError';
    let error;
    if (aborted) error = signal && signal.aborted ? 'cancelled' : `timeout after ${timeout} ms`;
    else error = 'gateway unreachable: ' + String((err && err.message) || err);
    return { ok: false, status: 0, data: null, text: '', headers: null, ms: performance.now() - started, error };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onOuterAbort);
  }
}

/** The decision record carried by a gateway response (block body, tool result or /api/try). */
export function recordOf(res) {
  const d = res && res.data;
  if (!d || typeof d !== 'object') return null;
  if (d.error && typeof d.error === 'object' && d.error.record && typeof d.error.record === 'object') {
    return d.error.record;
  }
  if (d.record && typeof d.record === 'object') return d.record;
  if (d.agentshield && d.agentshield.record && typeof d.agentshield.record === 'object') return d.agentshield.record;
  if (typeof d.action === 'string' && typeof d.request_id === 'string') return d;
  return null;
}

/** A list payload that may be a bare array or wrapped as {key: [...]}. */
export function listOf(data, key) {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object' && Array.isArray(data[key])) return data[key];
  return null;
}
