// Live decision stream: cursor-polled ring buffer (state.js), client-side filters, and a
// virtualized list that renders only the rows in view.

import { html, useState, useRef, useEffect, useMemo } from '../vendor/preact-htm.js';
import { events, eventsVersion, eventsMeta, snapshot, go, MAX_EVENTS } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, sevKey, sevOf, fmtClock, fmtMs, isNum, ADMIN_KINDS } from '../lib/format.js';
import { Section } from './ui.js';

const ROW_H = 36;
const VIEW_ROWS = 14;
const OVERSCAN = 6;

function FilterSelect({ id, value, options, onChange, placeholder }) {
  const [open, setOpen] = useState(false);
  const [hi, setHi] = useState(-1);
  const [menuBox, setMenuBox] = useState(null);
  const root = useRef(null);
  const btnRef = useRef(null);
  const listRef = useRef(null);
  const listId = id + '-list';
  const current = options.find((o) => o.value === value);
  const label = current ? current.label : placeholder;

  function placeMenu() {
    const btn = btnRef.current;
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    const gap = 4;
    const below = window.innerHeight - r.bottom - gap;
    const maxH = Math.min(280, Math.max(120, below));
    setMenuBox({
      left: Math.round(r.left),
      width: Math.max(Math.round(r.width), 180),
      maxHeight: maxH,
      top: Math.round(r.bottom + gap),
    });
  }

  useEffect(() => {
    if (!open) { setMenuBox(null); return undefined; }
    placeMenu();
    const onDoc = (e) => {
      if (root.current && !root.current.contains(e.target)) setOpen(false);
    };
    const onReposition = () => placeMenu();
    document.addEventListener('mousedown', onDoc);
    window.addEventListener('resize', onReposition);
    window.addEventListener('scroll', onReposition, true);
    requestAnimationFrame(() => {
      if (listRef.current) listRef.current.focus({ preventScroll: true });
    });
    return () => {
      document.removeEventListener('mousedown', onDoc);
      window.removeEventListener('resize', onReposition);
      window.removeEventListener('scroll', onReposition, true);
    };
  }, [open]);

  function pick(next) {
    onChange(next);
    setOpen(false);
    setHi(-1);
    if (btnRef.current) btnRef.current.focus();
  }

  function onTriggerKey(e) {
    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setOpen(true);
      setHi(Math.max(0, options.findIndex((o) => o.value === value)));
    }
  }

  function onListKey(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHi((i) => (i + 1) % options.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHi((i) => (i <= 0 ? options.length - 1 : i - 1));
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      const opt = options[hi >= 0 ? hi : 0];
      if (opt) pick(opt.value);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setOpen(false);
      if (btnRef.current) btnRef.current.focus();
    }
  }

  const menuStyle = menuBox ? {
    position: 'fixed',
    left: menuBox.left + 'px',
    width: menuBox.width + 'px',
    maxHeight: menuBox.maxHeight + 'px',
    top: menuBox.top + 'px',
    zIndex: 80,
  } : { display: 'none' };

  return html`<div class=${'flt' + (open ? ' open' : '') + (value ? ' set' : '')} ref=${root}>
    <button type="button" class="flt-btn" id=${id} ref=${btnRef}
      aria-haspopup="listbox" aria-expanded=${open ? 'true' : 'false'} aria-controls=${listId}
      onClick=${() => { setOpen((o) => !o); setHi(Math.max(0, options.findIndex((o) => o.value === value))); }}
      onKeyDown=${onTriggerKey}>
      <span class="flt-label">
        ${current && current.glyph ? html`<span class=${'flt-mark tone-' + current.tone} aria-hidden="true">${current.glyph}</span>` : null}
        ${label}
      </span>
      <span class="flt-chev" aria-hidden="true"></span>
    </button>
    ${open ? html`<ul class="flt-menu" id=${listId} role="listbox" tabindex="-1"
      aria-label=${placeholder} onKeyDown=${onListKey} style=${menuStyle}
      ref=${(n) => { listRef.current = n; }}>
      ${options.map((o, i) => html`<li role="option" aria-selected=${o.value === value ? 'true' : 'false'}
        class=${'flt-opt' + (o.value === value ? ' selected' : '') + (i === hi ? ' hi' : '') + (o.mono ? ' mono' : '')}
        onMouseEnter=${() => setHi(i)}
        onClick=${() => pick(o.value)}>
        ${o.glyph ? html`<span class=${'flt-mark tone-' + o.tone} aria-hidden="true">${o.glyph}</span>` : null}
        <span class="flt-opt-label">${o.label}</span>
      </li>`)}
    </ul>` : null}
  </div>`;
}

function matches(rec, f) {
  if (f.action && str(rec.action) !== f.action) return false;
  if (f.agent && str(rec.agent_id) !== f.agent) return false;
  if (f.kind && str(rec.kind) !== f.kind) return false;
  if (f.control) {
    const q = f.control.toLowerCase();
    const ids = [rec.primary && rec.primary.control_id, ...(Array.isArray(rec.findings) ? rec.findings.map((x) => x && x.control_id) : [])];
    if (!ids.some((id) => str(id).toLowerCase().includes(q))) return false;
  }
  return true;
}

function Row({ rec, top, onOpen }) {
  const admin = ADMIN_KINDS.has(str(rec.kind));
  const primary = rec.primary && typeof rec.primary === 'object' ? rec.primary : null;
  const total = rec.timings_ms && isNum(rec.timings_ms.total) ? rec.timings_ms.total : null;
  const s = sevOf(rec.action);
  const label = `Decision ${rec.seq}, ${s.label}, ${str(rec.kind)}, agent ${str(rec.agent_id) || 'none'}, ${primary ? str(primary.control_id) : 'no findings'}`;
  const open = () => onOpen(rec.seq);
  return html`<div class=${'srow' + (admin ? ' admin' : '')} style=${{ top: top + 'px' }} role="button" tabIndex="0"
      aria-label=${label} onClick=${open}
      onKeyDown=${(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } }}>
    <span class="c-seq num">${rec.seq}</span>
    <span class="c-time num">${fmtClock(rec.ts)}</span>
    <span class="c-agent mono">${str(rec.agent_id) || '-'}</span>
    <span class="c-kind">${str(rec.kind)}</span>
    <span class="c-act"><span class=${'chip sev-' + (admin ? 'none' : sevKey(rec.action))}><span aria-hidden="true">${s.glyph}</span> ${s.short}</span></span>
    <span class="c-ctl"><span class="mono">${primary ? str(primary.control_id) : '-'}</span> <span class="muted">${str(rec.summary, 140)}</span></span>
    <span class="c-owasp">${primary ? str(primary.owasp) : ''}</span>
    <span class="c-ms num">${total !== null ? fmtMs(total) : '-'}</span>
  </div>`;
}

export function Stream() {
  useSig(eventsVersion);
  const meta = useSig(eventsMeta);
  const snap = useSig(snapshot);
  const [filters, setFilters] = useState({ action: '', agent: '', kind: '', control: '' });
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState(null);
  const [scrollTop, setScrollTop] = useState(0);
  const boxRef = useRef(null);

  const live = events();
  const source = paused && frozen ? frozen : live;
  const rows = useMemo(() => source.filter((r) => matches(r, filters)), [source, filters, live.length, live[0] && live[0].seq]);
  const frozenTop = frozen && frozen.length ? frozen[0].seq : 0;
  let newSincePause = 0;
  if (paused && frozen) for (const r of live) { if (r.seq > frozenTop) newSincePause += 1; else break; }

  const agents = useMemo(() => {
    const set = new Set(snap && Array.isArray(snap.agents) ? snap.agents.map((x) => str(x)) : []);
    live.forEach((r) => r.agent_id && set.add(str(r.agent_id)));
    return Array.from(set).sort();
  }, [snap, live.length]);

  function togglePause() {
    if (paused) {
      setPaused(false);
      setFrozen(null);
    } else {
      setFrozen(live.slice());
      setPaused(true);
    }
  }

  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey) return;
      const t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.tagName === 'BUTTON')) return;
      if (document.querySelector('.modal')) return;
      const el = document.getElementById('flt-control');
      if (el) { e.preventDefault(); el.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + VIEW_ROWS * ROW_H) / ROW_H) + OVERSCAN);
  const visible = rows.slice(first, last);
  const set = (k) => (value) => setFilters({ ...filters, [k]: value });
  const actionOptions = [
    { value: '', label: 'All actions' },
    { value: 'block', label: 'Block', glyph: '■', tone: 'block' },
    { value: 'require_approval', label: 'Approval', glyph: '◆', tone: 'approval' },
    { value: 'redact', label: 'Redact', glyph: '◐', tone: 'redact' },
    { value: 'monitor', label: 'Monitor', glyph: '○', tone: 'monitor' },
    { value: 'allow', label: 'Allow', glyph: '✓', tone: 'allow' },
  ];
  const agentOptions = [{ value: '', label: 'All agents' }, ...agents.map((a) => ({ value: a, label: a, mono: true }))];
  const kindOptions = [
    { value: '', label: 'All kinds' },
    ...['chat', 'tool', 'try', 'policy', 'approval', 'kill'].map((k) => ({
      value: k,
      label: k.charAt(0).toUpperCase() + k.slice(1),
    })),
  ];

  const status = meta.ok === false
    ? html`<span class="chip sev-redact" title=${str(meta.error)}>stream error, retrying</span>`
    : paused ? html`<span class="chip sev-none">paused${newSincePause ? ` · ${newSincePause} new` : ''}</span>`
      : html`<span class="chip sev-allow"><span aria-hidden="true">●</span> live</span>`;

  return html`<${Section} title="Decision stream" id="stream-title" className="stream-card"
    actions=${html`${status}
      <button type="button" class="btn" aria-pressed=${paused} onClick=${togglePause}>${paused ? 'Resume' : 'Pause'}</button>`}>
    <div class="filters" role="search" aria-label="Filter decisions">
      <${FilterSelect} id="flt-action" value=${filters.action} options=${actionOptions}
        placeholder="All actions" onChange=${set('action')} />
      <${FilterSelect} id="flt-agent" value=${filters.agent} options=${agentOptions}
        placeholder="All agents" onChange=${set('agent')} />
      <${FilterSelect} id="flt-kind" value=${filters.kind} options=${kindOptions}
        placeholder="All kinds" onChange=${set('kind')} />
      <label class="sr-only" for="flt-control">Control id contains</label>
      <input id="flt-control" type="search" placeholder="control, e.g. pii. or flow  ( / )" value=${filters.control}
        onInput=${(e) => set('control')(e.currentTarget.value)} autocomplete="off" spellcheck="false" />
    </div>
    <p class="small muted">${rows.length} shown of ${live.length} buffered (last ${MAX_EVENTS} kept in memory)</p>
    <div class="shead" aria-hidden="true">
      <span class="c-seq">seq</span><span class="c-time">time</span><span class="c-agent">agent</span><span class="c-kind">kind</span>
      <span class="c-act">decision</span><span class="c-ctl">control / summary</span><span class="c-owasp">OWASP</span><span class="c-ms">ms</span>
    </div>
    <div class="sbox" ref=${boxRef} style=${{ height: VIEW_ROWS * ROW_H + 'px' }}
        onScroll=${(e) => setScrollTop(e.currentTarget.scrollTop)} role="region" aria-label="Decisions, newest first" tabIndex="-1">
      ${rows.length === 0
        ? html`<p class="sempty muted">${live.length ? 'No decisions match these filters.' : 'No decisions yet. Send traffic from the Demo tab or run demo/agent.py.'}</p>`
        : html`<div class="sinner" style=${{ height: rows.length * ROW_H + 'px' }}>
            ${visible.map((rec, i) => html`<${Row} key=${rec.seq} rec=${rec} top=${(first + i) * ROW_H} onOpen=${(seq) => go('#/console/' + seq)} />`)}
          </div>`}
    </div>
  <//>`;
}
