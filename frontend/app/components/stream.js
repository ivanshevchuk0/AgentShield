// Live decision stream: cursor-polled ring buffer (state.js), instant client-side filters with a
// small query grammar, keyboard navigation (j/k, Enter, p) and a virtualized list.

import { html, useState, useRef, useEffect, useLayoutEffect, useMemo } from '../vendor/preact-htm.js';
import { events, eventsVersion, eventsMeta, snapshot, route, go, MAX_EVENTS } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, sevKey, sevOf, fmtClock, fmtMs, isNum, ADMIN_KINDS } from '../lib/format.js';

const OVERSCAN = 6;
const QUICK = [
  ['', 'All'], ['block', 'Block'], ['require_approval', 'Approval'], ['redact', 'Redact'],
  ['monitor', 'Monitor'], ['allow', 'Allow'], ['admin', 'Admin'],
];
const FIELDS = new Set(['agent', 'kind', 'control', 'owasp', 'seq', 'via', 'session', 'action', 'tool']);

/* Shared with the drawer: the current filtered order (newest first) and a way to focus a row. */
let order = [];
let focusRowImpl = null;
export function streamOrder() { return order; }
export function focusRow(seq) { if (focusRowImpl) focusRowImpl(seq); }

/** Local media-query hook (lib/hooks.js has none). */
export function useMedia(query) {
  const get = () => { try { return window.matchMedia(query).matches; } catch { return false; } };
  const [m, setM] = useState(get);
  useEffect(() => {
    let mq;
    try { mq = window.matchMedia(query); } catch { return undefined; }
    const on = () => setM(mq.matches);
    mq.addEventListener('change', on);
    window.addEventListener('resize', on);
    return () => { mq.removeEventListener('change', on); window.removeEventListener('resize', on); };
  }, [query]);
  return m;
}

export function isTyping(t) {
  if (!t) return false;
  const tag = t.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable;
}

/** "agent:bank control:pii. invoice" -> {fields: [[k, v]], words: [..]} */
function parseQuery(q) {
  const fields = [];
  const words = [];
  for (const tok of q.trim().toLowerCase().split(/\s+/).filter(Boolean)) {
    const m = /^([a-z]+):(.+)$/.exec(tok);
    if (m && FIELDS.has(m[1])) fields.push([m[1], m[2]]);
    else words.push(tok);
  }
  return { fields, words };
}

function controlIds(rec) {
  const ids = [];
  if (rec.primary && rec.primary.control_id) ids.push(str(rec.primary.control_id).toLowerCase());
  if (Array.isArray(rec.findings)) for (const f of rec.findings) if (f && f.control_id) ids.push(str(f.control_id).toLowerCase());
  return ids;
}

function matches(rec, quick, agent, kind, q) {
  const k = str(rec.kind);
  if (quick === 'admin') { if (!ADMIN_KINDS.has(k)) return false; }
  else if (quick && (str(rec.action) !== quick || ADMIN_KINDS.has(k))) return false;
  if (agent && str(rec.agent_id) !== agent) return false;
  if (kind && k !== kind) return false;
  for (const [f, v] of q.fields) {
    let ok = true;
    if (f === 'agent') ok = str(rec.agent_id).toLowerCase().includes(v);
    else if (f === 'kind') ok = k.toLowerCase() === v;
    else if (f === 'action') ok = str(rec.action).toLowerCase().startsWith(v);
    else if (f === 'control') ok = controlIds(rec).some((id) => id.includes(v));
    else if (f === 'owasp') ok = JSON.stringify([rec.primary && rec.primary.owasp, ...(rec.findings || []).map((x) => x && x.owasp)]).toLowerCase().includes(v);
    else if (f === 'seq') ok = String(rec.seq) === v;
    else if (f === 'via') ok = (rec.findings || []).some((x) => x && str(x.via).toLowerCase().includes(v));
    else if (f === 'session') ok = str(rec.session_id).toLowerCase().includes(v);
    else if (f === 'tool') ok = str(rec.tool).toLowerCase().includes(v);
    if (!ok) return false;
  }
  if (q.words.length) {
    const hay = [String(rec.seq), str(rec.agent_id), k, str(rec.action), str(rec.summary, 400), str(rec.tool),
      str(rec.primary && rec.primary.owasp), ...controlIds(rec)].join(' ').toLowerCase();
    for (const w of q.words) if (!hay.includes(w)) return false;
  }
  return true;
}

function Row({ rec, top, h, onOpen, selected, cursor }) {
  const admin = ADMIN_KINDS.has(str(rec.kind));
  const primary = rec.primary && typeof rec.primary === 'object' ? rec.primary : null;
  const total = rec.timings_ms && isNum(rec.timings_ms.total) ? rec.timings_ms.total : null;
  const s = sevOf(rec.action);
  const sev = admin ? 'admin' : sevKey(rec.action);
  const nf = Array.isArray(rec.findings) ? rec.findings.length : 0;
  const ctl = primary ? str(primary.control_id) : admin ? str(rec.kind) : '';
  const label = `Decision ${rec.seq}, ${admin ? 'admin ' + str(rec.kind) : s.label}, agent ${str(rec.agent_id) || 'none'}, ${ctl || 'no findings'}`;
  const open = () => onOpen(rec.seq);
  return html`<div class=${'cx-row sev-edge-' + sev + (selected ? ' is-open' : '') + (cursor ? ' is-cursor' : '')}
      style=${{ top: top + 'px', height: h + 'px' }} role="button" tabIndex=${cursor ? 0 : -1}
      data-seq=${rec.seq} aria-label=${label} aria-current=${selected ? 'true' : undefined} onClick=${open}
      onKeyDown=${(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } }}>
    <span class="c-seq num">${rec.seq}</span>
    <span class="c-time num">${fmtClock(rec.ts)}</span>
    <span class="c-agent mono">${str(rec.agent_id) || '—'}</span>
    <span class="c-kind">${str(rec.kind)}</span>
    <span class="c-act">${admin
      ? html`<span class="cx-chip sev-admin">${str(rec.kind).toUpperCase()}</span>`
      : html`<span class=${'cx-chip sev-' + sevKey(rec.action)}><span aria-hidden="true">${s.glyph}</span>${s.short}</span>`}</span>
    <span class="c-ctl">
      ${ctl ? html`<span class="mono cx-ctl-id">${ctl}</span>` : html`<span class="muted">no findings</span>`}
      ${nf > 1 ? html`<span class="cx-count" title=${nf + ' findings'}>+${nf - 1}</span>` : null}
      <span class="muted cx-sum">${str(rec.summary, 160)}</span>
    </span>
    <span class="c-owasp mono">${primary ? str(primary.owasp) : ''}</span>
    <span class="c-ms num">${total !== null ? fmtMs(total) : '—'}</span>
  </div>`;
}

export function Stream() {
  useSig(eventsVersion);
  const meta = useSig(eventsMeta);
  const snap = useSig(snapshot);
  const r = useSig(route);
  const mobile = useMedia('(max-width: 820px)');
  const ROW_H = mobile ? 58 : 34;
  const VIEW_ROWS = mobile ? 7 : 14;
  const [quick, setQuick] = useState('');
  const [agent, setAgent] = useState('');
  const [kind, setKind] = useState('');
  const [query, setQuery] = useState('');
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [cursor, setCursor] = useState(null);   // seq of the keyboard cursor row
  const boxRef = useRef(null);
  const prevTop = useRef(0);
  const focusWanted = useRef(null);

  const live = events();
  const source = paused && frozen ? frozen : live;
  const q = useMemo(() => parseQuery(query), [query]);
  const head = live[0] ? live[0].seq : 0;
  const rows = useMemo(() => source.filter((x) => matches(x, quick, agent, kind, q)),
    [source, quick, agent, kind, q, live.length, head]);
  order = rows.map((x) => x.seq);

  const counts = useMemo(() => {
    const c = { '': 0, admin: 0 };
    for (const x of source) {
      c[''] += 1;
      if (ADMIN_KINDS.has(str(x.kind))) c.admin += 1;
      else c[str(x.action)] = (c[str(x.action)] || 0) + 1;
    }
    return c;
  }, [source, live.length, head]);

  const frozenTop = frozen && frozen.length ? frozen[0].seq : 0;
  let newSincePause = 0;
  if (paused && frozen) for (const x of live) { if (x.seq > frozenTop) newSincePause += 1; else break; }

  const agents = useMemo(() => {
    const set = new Set(snap && Array.isArray(snap.agents) ? snap.agents.map((x) => str(x)) : []);
    live.forEach((x) => x.agent_id && set.add(str(x.agent_id)));
    return Array.from(set).sort();
  }, [snap, live.length]);

  // Keep the viewport anchored when new rows arrive above a scrolled position.
  const topSeq = rows[0] ? rows[0].seq : 0;
  useLayoutEffect(() => {
    const box = boxRef.current;
    if (box && box.scrollTop > 0 && prevTop.current && topSeq > prevTop.current) {
      let added = 0;
      for (const x of rows) { if (x.seq > prevTop.current) added += 1; else break; }
      if (added) { box.scrollTop += added * ROW_H; setScrollTop(box.scrollTop); }
    }
    prevTop.current = topSeq;
  }, [topSeq]);

  function togglePause() {
    if (paused) { setPaused(false); setFrozen(null); } else { setFrozen(live.slice()); setPaused(true); }
  }

  function scrollToIndex(i) {
    const box = boxRef.current;
    if (!box || i < 0) return;
    const y = i * ROW_H;
    if (y < box.scrollTop) box.scrollTop = y;
    else if (y + ROW_H > box.scrollTop + box.clientHeight) box.scrollTop = y + ROW_H - box.clientHeight;
    setScrollTop(box.scrollTop);
  }

  function moveCursor(delta) {
    if (!rows.length) return;
    let i = cursor === null ? -1 : rows.findIndex((x) => x.seq === cursor);
    i = i < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, i + delta));
    const seq = rows[i].seq;
    setCursor(seq);
    focusWanted.current = seq;
    scrollToIndex(i);
  }

  focusRowImpl = (seq) => {
    const i = rows.findIndex((x) => x.seq === seq);
    if (i < 0) { const box = boxRef.current; if (box) box.focus(); return; }
    setCursor(seq);
    focusWanted.current = seq;
    scrollToIndex(i);
  };

  useEffect(() => {
    if (focusWanted.current === null || !boxRef.current) return;
    const el = boxRef.current.querySelector(`[data-seq="${focusWanted.current}"]`);
    if (el) { el.focus({ preventScroll: true }); focusWanted.current = null; }
  });

  useEffect(() => {
    const onKey = (e) => {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
      if (document.querySelector('.modal, .cx-drawer')) return;
      if (e.key === '/') {
        const el = document.getElementById('flt-q');
        if (el) { e.preventDefault(); el.focus(); el.select(); }
      } else if (e.key === 'j' || (e.key === 'ArrowDown' && e.target && e.target.classList && e.target.classList.contains('cx-row'))) {
        e.preventDefault(); moveCursor(1);
      } else if (e.key === 'k' || (e.key === 'ArrowUp' && e.target && e.target.classList && e.target.classList.contains('cx-row'))) {
        e.preventDefault(); moveCursor(-1);
      } else if (e.key === 'p') {
        e.preventDefault(); togglePause();
      } else if (e.key === 'Enter' && cursor !== null && !(e.target && e.target.closest && e.target.closest('button, a, .cx-row'))) {
        e.preventDefault(); go('#/console/' + cursor);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  });

  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + VIEW_ROWS * ROW_H) / ROW_H) + OVERSCAN);
  const visible = rows.slice(first, last);
  const cursorSeq = cursor !== null && rows.some((x) => x.seq === cursor) ? cursor : (rows[0] ? rows[0].seq : null);
  const filtered = quick || agent || kind || query.trim();

  const status = meta.ok === false && meta.locked
    ? html`<span class="cx-live tone-paused" title=${str(meta.error)}><span class="dot" aria-hidden="true"></span>Locked</span>`
    : meta.ok === false
    ? html`<span class="cx-live tone-warn" title=${str(meta.error)}><span class="dot" aria-hidden="true"></span>Retrying</span>`
    : paused ? html`<span class="cx-live tone-paused"><span class="dot" aria-hidden="true"></span>Paused</span>`
      : html`<span class="cx-live tone-ok"><span class="dot" aria-hidden="true"></span>Live</span>`;

  return html`<section class="cx-card cx-stream" aria-labelledby="sec-stream">
    <header class="cx-card-head">
      <div class="cx-card-title-wrap">
        <h2 id="sec-stream" class="cx-card-title" tabIndex="-1">Decision stream</h2>
        ${status}
      </div>
      <div class="cx-card-actions">
        ${paused && newSincePause ? html`<button type="button" class="cx-btn sm accent" onClick=${togglePause}>${newSincePause} new · resume</button>` : null}
        <button type="button" class="cx-btn sm" aria-pressed=${paused ? 'true' : 'false'} onClick=${togglePause}
          title="Pause or resume the live stream (p)">${paused ? 'Resume' : 'Pause'}<kbd>p</kbd></button>
      </div>
    </header>
    <div class="cx-filters" role="search" aria-label="Filter decisions">
      <div class="cx-quick" role="group" aria-label="Decision">
        ${QUICK.map(([v, label]) => html`<button type="button" class=${'cx-q' + (quick === v ? ' on' : '') + (v ? ' q-' + v : '')}
          aria-pressed=${quick === v ? 'true' : 'false'} onClick=${() => setQuick(quick === v && v ? '' : v)}>
          ${label}<span class="num cx-q-n">${counts[v] || 0}</span></button>`)}
      </div>
      <div class="cx-filter-row">
        <label class="sr-only" for="flt-q">Search decisions</label>
        <div class="cx-search">
          <input id="flt-q" type="search" placeholder="Search  agent:  control:pii.  owasp:LLM06  seq:12" value=${query}
            onInput=${(e) => setQuery(e.currentTarget.value)} autocomplete="off" spellcheck="false"
            onKeyDown=${(e) => { if (e.key === 'Escape' && query) { e.preventDefault(); e.stopPropagation(); setQuery(''); } else if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.blur(); moveCursor(0); } }} />
          <kbd aria-hidden="true">/</kbd>
        </div>
        <label class="sr-only" for="flt-agent">Agent</label>
        <select id="flt-agent" value=${agent} onChange=${(e) => setAgent(e.currentTarget.value)}>
          <option value="">All agents</option>
          ${agents.map((a) => html`<option value=${a}>${a}</option>`)}
        </select>
        <label class="sr-only" for="flt-kind">Kind</label>
        <select id="flt-kind" value=${kind} onChange=${(e) => setKind(e.currentTarget.value)}>
          <option value="">All kinds</option>
          ${['chat', 'tool', 'try', 'policy', 'approval', 'kill'].map((k) => html`<option value=${k}>${k}</option>`)}
        </select>
        ${filtered ? html`<button type="button" class="cx-btn sm ghost" onClick=${() => { setQuick(''); setAgent(''); setKind(''); setQuery(''); }}>Clear</button>` : null}
      </div>
    </div>
    <div class="cx-table" role="presentation">
      <div class="cx-thead" aria-hidden="true">
        <span class="c-seq">Seq</span><span class="c-time">Time</span><span class="c-agent">Agent</span><span class="c-kind">Kind</span>
        <span class="c-act">Decision</span><span class="c-ctl">Control · summary</span><span class="c-owasp">OWASP</span><span class="c-ms">ms</span>
      </div>
      <div class="cx-tbody" ref=${boxRef} style=${{ height: VIEW_ROWS * ROW_H + 'px' }}
          onScroll=${(e) => setScrollTop(e.currentTarget.scrollTop)} role="region"
          aria-label="Decisions, newest first. j and k move, Enter opens." tabIndex="-1">
        ${rows.length === 0
          ? html`<div class="cx-empty">${live.length
            ? html`<p>No decisions match these filters.</p><button type="button" class="cx-btn sm" onClick=${() => { setQuick(''); setAgent(''); setKind(''); setQuery(''); }}>Clear filters</button>`
            : meta.locked
              ? html`<p>The decision stream is behind the admin token on this deployment.</p><p class="muted">Open Settings in the top bar and paste the token. The Demo tab works without it.</p>`
            : html`<p>No decisions yet.</p><p class="muted">Send traffic from the Demo tab, run <code>demo/run_demo.sh</code> or <code>demo/agent.py</code>.</p>`}</div>`
          : html`<div class="cx-tinner" style=${{ height: rows.length * ROW_H + 'px' }}>
              ${visible.map((rec, i) => html`<${Row} key=${rec.seq} rec=${rec} top=${(first + i) * ROW_H} h=${ROW_H}
                selected=${r.seq === rec.seq} cursor=${cursorSeq === rec.seq}
                onOpen=${(seq) => { setCursor(seq); go('#/console/' + seq); }} />`)}
            </div>`}
      </div>
    </div>
    <footer class="cx-card-foot">
      <span class="num">${rows.length.toLocaleString('en-US')} shown${filtered ? ` of ${source.length.toLocaleString('en-US')}` : ''}</span>
      <span class="muted">Buffer keeps the newest ${MAX_EVENTS.toLocaleString('en-US')} records · <kbd>j</kbd><kbd>k</kbd> move · <kbd>Enter</kbd> open</span>
    </footer>
  </section>`;
}
