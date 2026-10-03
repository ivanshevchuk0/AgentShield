// Global state (signals) and pollers. Pollers keep one request in flight, slow down when the tab
// is hidden, back off on errors, and never clear the last good data on failure.

import { signal } from './vendor/signals-core.js';
import { api, listOf } from './api.js';
import { toSec, isNum } from './lib/format.js';

/* ------------------------------------------------------------------ clock + route */

export const now = signal(Date.now());
setInterval(() => { now.value = Date.now(); }, 500);

/** server minus client clock, in ms (from snapshot.server_time). */
export const skewMs = signal(0);
export const serverNowSec = () => (Date.now() + skewMs.peek()) / 1000;

function parseRoute() {
  const raw = (location.hash || '').replace(/^#\/?/, '');
  const [tab, sub] = raw.split('/');
  const seq = sub && /^\d+$/.test(sub) ? Number(sub) : null;
  return { tab: tab === 'console' ? 'console' : 'demo', seq: tab === 'console' ? seq : null };
}
export const route = signal(parseRoute());
window.addEventListener('hashchange', () => { route.value = parseRoute(); });

export function go(hash) {
  if (location.hash !== hash) location.hash = hash;
  else route.value = parseRoute();
}

/* ------------------------------------------------------------------ snapshot */

export const snapshot = signal(null);
export const conn = signal({ lastOkAt: 0, lastError: null, fails: 0 });

function acceptSnapshot(data, receivedAt) {
  snapshot.value = data;
  const st = toSec(data.server_time);
  if (st !== null) skewMs.value = st * 1000 - receivedAt;
  conn.value = { lastOkAt: Date.now(), lastError: null, fails: 0 };
  if (Array.isArray(data.recent)) ingest(data.recent);
}

// Every fetch of a resource takes a ticket. A response is applied only if no newer request has
// already been applied, so a slow old response can never overwrite fresher state (pollers and
// manual refreshes run concurrently). Callers still receive their own response.
function sequencer() {
  let issued = 0;
  let applied = 0;
  return {
    take: () => ++issued,
    fresh(ticket) {
      if (ticket < applied) return false;
      applied = ticket;
      return true;
    },
  };
}
const snapSeq = sequencer();

/** Fetch the snapshot now; resolves to the snapshot or null. Used before/after demo actions. */
export async function fetchSnapshot() {
  const ticket = snapSeq.take();
  const r = await api('/api/snapshot', { timeout: 4000 });
  if (r.ok && r.data && typeof r.data === 'object' && r.data.policy) {
    // server_time was produced somewhere inside the round trip; dating it at the request start
    // makes the client clock run slightly ahead, so TTLs expire early, never late.
    if (snapSeq.fresh(ticket)) acceptSnapshot(r.data, Date.now() - r.ms);
    return r.data;
  }
  if (snapSeq.fresh(ticket)) {
    const c = conn.peek();
    conn.value = { ...c, lastError: r.error || 'bad snapshot payload', fails: c.fails + 1 };
  }
  return null;
}

/* ------------------------------------------------------------------ decision stream (ring buffer) */

export const MAX_EVENTS = 2000;
let ring = [];                 // newest first (descending seq)
const bySeq = new Map();
export const eventsVersion = signal(0);
export const eventsMeta = signal({ ok: null, error: null, cursor: 0, lastOkAt: 0 });

export function events() { return ring; }
export function eventBySeq(seq) { return bySeq.get(seq) || null; }
export function latestSeq() { return ring.length ? ring[0].seq : 0; }

export function ingest(list) {
  if (!Array.isArray(list) || !list.length) return 0;
  let added = 0;
  for (const rec of list) {
    if (!rec || typeof rec !== 'object' || !isNum(rec.seq) || bySeq.has(rec.seq)) continue;
    bySeq.set(rec.seq, rec);
    ring.push(rec);
    added += 1;
  }
  if (!added) return 0;
  ring.sort((a, b) => b.seq - a.seq);
  if (ring.length > MAX_EVENTS) {
    for (const old of ring.slice(MAX_EVENTS)) bySeq.delete(old.seq);
    ring = ring.slice(0, MAX_EVENTS);
  }
  eventsVersion.value += 1;
  return added;
}

/** Find one record by seq: buffer first, then the cursor endpoint, then a tail scan. */
export async function findRecord(seq) {
  if (!isNum(seq)) return null;
  const hit = eventBySeq(seq);
  if (hit) return hit;
  const r = await api(`/api/events?after_seq=${seq - 1}&limit=5`);
  const list = r.ok ? listOf(r.data, 'events') : null;
  if (list) {
    ingest(list);
    const found = list.find((x) => x && x.seq === seq);
    if (found) return found;
  }
  const t = await api('/api/events?limit=200');
  const tail = t.ok ? listOf(t.data, 'events') : null;
  if (tail) {
    ingest(tail);
    return tail.find((x) => x && x.seq === seq) || null;
  }
  return null;
}

let primed = false;
async function pollEvents() {
  const meta = eventsMeta.peek();
  const url = primed ? `/api/events?after_seq=${meta.cursor}&limit=500` : '/api/events?limit=500';
  const r = await api(url);
  const list = r.ok ? listOf(r.data, 'events') : null;
  if (!list) {
    eventsMeta.value = { ...meta, ok: false, error: r.error || 'unexpected /api/events payload',
      locked: r.status === 401 || r.status === 403 };
    return false;
  }
  ingest(list);
  let cursor = meta.cursor;
  for (const rec of list) if (rec && isNum(rec.seq) && rec.seq > cursor) cursor = rec.seq;
  primed = true;
  eventsMeta.value = { ok: true, error: null, cursor, lastOkAt: Date.now() };
  if (list.length >= 500) setTimeout(() => eventsPoller.now(), 0);   // catching up after a gap
  return true;
}

/* ------------------------------------------------------------------ approvals, chain, history */

export const approvals = signal({ ok: null, list: [], error: null });
const approvalsSeq = sequencer();

export async function pollApprovals() {
  const ticket = approvalsSeq.take();
  const r = await api('/api/approvals');
  const list = r.ok ? listOf(r.data, 'approvals') : null;
  if (!approvalsSeq.fresh(ticket)) return !!list;
  if (!list) {
    approvals.value = { ...approvals.peek(), ok: false, error: r.error || 'unexpected payload', status: r.status };
    return false;
  }
  approvals.value = { ok: true, list, error: null };
  return true;
}

/** {ok, count, broken_at, reason, at} after a verification; {error, failedAt, last} when the last
 *  attempt failed. A failure drops `ok` so no view can keep showing a stale "verified". */
export const chain = signal(null);
const chainSeq = sequencer();

export async function verifyChain() {
  const ticket = chainSeq.take();
  const r = await api('/api/audit/verify', { timeout: 8000 });
  const good = r.ok && r.data && typeof r.data === 'object' && 'ok' in r.data;
  if (!chainSeq.fresh(ticket)) return good;
  if (good) {
    chain.value = { ...r.data, at: Date.now() };
    return true;
  }
  const prev = chain.peek();
  const last = prev && 'ok' in prev ? prev : prev && prev.last ? prev.last : null;
  chain.value = { error: r.error || 'invalid verification response', locked: r.status === 401 || r.status === 403,
    failedAt: Date.now(), last };
  return false;
}

export const policyHistory = signal({ supported: null, list: [] });

export async function loadPolicyHistory() {
  const r = await api('/api/policy/history');
  const list = r.ok ? listOf(r.data, 'history') : null;
  if (list) policyHistory.value = { supported: true, list };
  else policyHistory.value = { supported: r.status === 404 || r.status === 405 ? false : policyHistory.peek().supported, list: policyHistory.peek().list, error: r.error };
}

/* ------------------------------------------------------------------ poller plumbing */

function makePoller(fn, interval, hiddenInterval, maxBackoff = 8000) {
  let timer = null;
  let running = false;
  let stopped = true;
  let fails = 0;
  async function tick() {
    timer = null;
    if (running || stopped) return;
    running = true;
    let ok = false;
    try {
      ok = await fn();
    } catch {
      ok = false;
    }
    running = false;
    fails = ok ? 0 : fails + 1;
    schedule();
  }
  function schedule() {
    if (stopped) return;
    clearTimeout(timer);
    const base = document.hidden ? hiddenInterval : interval;
    const delay = fails ? Math.min(maxBackoff, base * 2 ** Math.min(fails, 4)) : base;
    timer = setTimeout(tick, delay);
  }
  return {
    start() { if (!stopped) return; stopped = false; tick(); },
    now() { if (stopped) return; clearTimeout(timer); if (!running) tick(); },
  };
}

const snapshotPoller = makePoller(async () => (await fetchSnapshot()) !== null, 1000, 5000);
export const eventsPoller = makePoller(pollEvents, 1000, 5000);
const approvalsPoller = makePoller(pollApprovals, 2000, 8000, 16000);
const chainPoller = makePoller(verifyChain, 15000, 60000, 60000);

export function refreshAll() {
  snapshotPoller.now();
  eventsPoller.now();
  approvalsPoller.now();
}

export function startPolling() {
  snapshotPoller.start();
  eventsPoller.start();
  approvalsPoller.start();
  chainPoller.start();
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshAll();
  });
}
