// Shared presentational components. All server values are passed through str()/fmt* and
// rendered as text; nothing here builds markup from strings or links to record content.

import { html, useEffect, useRef, useState } from '../vendor/preact-htm.js';
import {
  str, sevOf, sevKey, fmtMs, isNum, owaspTags, OWASP_TITLES, shortHash, fmtClock, fmtUsd, fmtInt,
} from '../lib/format.js';
import { excerptSegments, decodedOnly } from '../lib/highlight.js';

/** Custom agent picker: title + role + API key. Replaces the native <select> in the demo free-text form. */
export function AgentPicker({ id, value, options, onChange, label = 'agent' }) {
  const [open, setOpen] = useState(false);
  const [hi, setHi] = useState(-1);
  const root = useRef(null);
  const listId = id + '-list';
  const current = options.find((a) => a.key === value) || options[0];

  useEffect(() => {
    if (!open) return undefined;
    const onDoc = (e) => {
      if (root.current && !root.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); setOpen(false); }
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey, true);
    };
  }, [open]);

  function pick(key) {
    onChange(key);
    setOpen(false);
    setHi(-1);
  }

  function onTriggerKey(e) {
    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setOpen(true);
      setHi(Math.max(0, options.findIndex((a) => a.key === value)));
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
      if (opt) pick(opt.key);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setOpen(false);
    }
  }

  return html`<div class=${'agent-picker' + (open ? ' open' : '')} ref=${root}>
    <span class="label small" id=${id + '-label'}>${label}</span>
    <button type="button" class="agent-picker-btn" id=${id}
      aria-haspopup="listbox" aria-expanded=${open ? 'true' : 'false'} aria-controls=${listId}
      aria-labelledby=${id + '-label ' + id}
      onClick=${() => { setOpen((o) => !o); setHi(Math.max(0, options.findIndex((a) => a.key === value))); }}
      onKeyDown=${onTriggerKey}>
      <span class="agent-picker-main">
        <span class="agent-picker-name">${str(current && current.id)}</span>
        <span class="agent-picker-role muted">${str(current && current.role)}</span>
      </span>
      <span class="agent-picker-key mono">${str(current && current.key)}</span>
      <span class="agent-picker-chev" aria-hidden="true"></span>
    </button>
    ${open ? html`<ul class="agent-picker-menu" id=${listId} role="listbox" tabindex="-1"
      aria-labelledby=${id + '-label'} onKeyDown=${onListKey} ref=${(n) => { if (n) n.focus(); }}>
      ${options.map((a, i) => html`<li role="option" aria-selected=${a.key === value ? 'true' : 'false'}
        class=${'agent-picker-opt' + (a.key === value ? ' selected' : '') + (i === hi ? ' hi' : '')}
        onMouseEnter=${() => setHi(i)}
        onClick=${() => pick(a.key)}>
        <span class="agent-picker-opt-text">
          <span class="agent-picker-name">${str(a.id)}</span>
          <span class="agent-picker-role muted">${str(a.role)}</span>
        </span>
        <span class="agent-picker-key mono">${str(a.key)}</span>
      </li>`)}
    </ul>` : null}
  </div>`;
}

export function SevChip({ action, compact = false }) {
  const s = sevOf(action);
  return html`<span class=${'chip sev-' + sevKey(action)}>
    <span aria-hidden="true">${s.glyph}</span> ${compact ? s.short : s.label}</span>`;
}

export function Stamp({ action, http, monitorMode }) {
  const s = sevOf(action);
  return html`<div class=${'stamp sev-' + sevKey(action)} role="img" aria-label=${s.label + (http ? ' HTTP ' + http : '')}>
    <span class="stamp-glyph" aria-hidden="true">${s.glyph}</span>
    <span class="stamp-label">${monitorMode && action === 'monitor' ? 'WOULD ACT (monitor)' : s.label}</span>
    ${http ? html`<span class="stamp-http">HTTP ${str(http)}</span>` : null}
  </div>`;
}

export function Mono({ children, title }) {
  return html`<code class="mono" title=${title || undefined}>${children}</code>`;
}

export function Meter({ value, max, label, tone }) {
  const v = isNum(value) ? value : 0;
  const m = isNum(max) ? max : null;
  let pct = 0;
  if (m !== null && m > 0) pct = Math.min(100, (v / m) * 100);
  else if (m === 0) pct = 100;
  const t = tone || (pct >= 100 ? 'block' : pct >= 80 ? 'redact' : 'allow');
  return html`<div class="meter" role="meter" aria-label=${label} aria-valuemin="0"
      aria-valuemax=${m === null ? undefined : m} aria-valuenow=${v}>
    <div class=${'meter-fill sev-bg-' + t} style=${{ width: pct + '%' }}></div>
  </div>`;
}

/** Masked excerpt with highlighted finding spans (offsets corrected by excerpt_offset). */
export function Evidence({ rec }) {
  const ex = excerptSegments(rec);
  const decoded = decodedOnly(rec);
  if (!ex && !decoded.length) {
    return html`<p class="muted small">No excerpt in this record${rec && rec.primary && rec.primary.evidence
      ? html`; masked evidence: <${Mono}>${str(rec.primary.evidence)}<//>` : ''}.</p>`;
  }
  return html`<div>
    ${ex ? html`<p class="excerpt" aria-label="Masked excerpt">
      ${ex.truncatedStart ? '…' : ''}${ex.segments.map((s) => (s.mark
        ? html`<mark class=${'hl sev-' + sevKey(s.mark.action)} title=${s.mark.control}>${s.text}</mark>`
        : s.text))}
    </p>` : null}
    ${decoded.length ? html`<ul class="badges" aria-label="Findings seen only after decoding">
      ${decoded.map((f) => html`<li class="badge decoded">
        <span class="badge-k">decoded view</span> <${Mono}>${str(f.via)}<//> · ${str(f.control_id)}
      </li>`)}
    </ul>` : null}
    <p class="muted small">Masked by the gateway before storage. Highlights use the record's offsets.</p>
  </div>`;
}

export function FindingsList({ rec, limit = 50 }) {
  const fs = Array.isArray(rec && rec.findings) ? rec.findings.filter((f) => f && typeof f === 'object') : [];
  if (!fs.length) return html`<p class="muted small">No findings.</p>`;
  return html`<ul class="findings">
    ${fs.slice(0, limit).map((f) => {
      const span = Number.isInteger(f.start) ? `${f.start}–${f.end}` : '';
      return html`<li class="finding">
        <div class="finding-head">
          <${SevChip} action=${str(f.action)} compact />
          <${Mono}>${str(f.control_id)}<//>
          ${f.owasp ? html`<span class="tag" title=${OWASP_TITLES[str(f.owasp)] || ''}>${str(f.owasp)}</span>` : null}
          ${span ? html`<span class="muted small">span ${span}</span>` : null}
          ${f.via && str(f.via) !== 'original' ? html`<span class="badge decoded small">via ${str(f.via)}</span>` : null}
          ${isNum(f.score) && f.score !== 1 ? html`<span class="muted small">score ${f.score.toFixed(2)}</span>` : null}
        </div>
        ${f.evidence ? html`<div class="small">evidence <${Mono}>${str(f.evidence, 200)}<//></div>` : null}
        ${f.detail ? html`<div class="small muted">${str(f.detail, 400)}</div>` : null}
      </li>`;
    })}
    ${fs.length > limit ? html`<li class="muted small">+${fs.length - limit} more</li>` : null}
  </ul>`;
}

/** Measured timings only: detect, judge, upstream (model or tool), total. */
export function Waterfall({ rec }) {
  const t = rec && rec.timings_ms && typeof rec.timings_ms === 'object' ? rec.timings_ms : {};
  const total = isNum(t.total) ? t.total : null;
  const upstreamLabel = str(rec && rec.kind) === 'tool' ? 'tool exec' : 'model';
  const judgeCalled = ['allow', 'block'].includes(str(rec && rec.judge));
  const rows = [
    ['detect', isNum(t.detect) ? t.detect : null, 'detect'],
    ['judge', judgeCalled && isNum(t.judge) ? t.judge : null, 'judge', judgeCalled ? '' : `not called (${str(rec && rec.judge) || 'skipped'})`],
    [upstreamLabel, isNum(t.upstream) ? t.upstream : null, 'upstream', 'not called'],
  ];
  const scale = total || Math.max(1, ...rows.map((r) => r[1] || 0));
  const overhead = total !== null ? Math.max(0, total - (isNum(t.upstream) ? t.upstream : 0)) : null;
  return html`<div class="waterfall" role="table" aria-label="Measured timings in milliseconds">
    ${rows.map(([label, v, cls, empty]) => html`<div class="wf-row" role="row">
      <span class="wf-label" role="rowheader">${label}</span>
      <span class="wf-track" role="cell">
        ${v !== null ? html`<span class=${'wf-bar wf-' + cls} style=${{ width: Math.max(1.5, (v / scale) * 100) + '%' }}></span>` : null}
      </span>
      <span class="wf-val num" role="cell">${v !== null ? fmtMs(v) + ' ms' : html`<span class="muted">${empty || '-'}</span>`}</span>
    </div>`)}
    <div class="wf-row wf-total" role="row">
      <span class="wf-label" role="rowheader">total</span>
      <span class="wf-track" role="cell">${total !== null ? html`<span class="wf-bar wf-total-bar" style=${{ width: '100%' }}></span>` : null}</span>
      <span class="wf-val num" role="cell">${total !== null ? fmtMs(total) + ' ms' : '-'}</span>
    </div>
    ${overhead !== null ? html`<p class="small muted">Gateway overhead (total minus ${upstreamLabel}): <strong class="num">${fmtMs(overhead)} ms</strong></p>` : null}
  </div>`;
}

export function Provenance({ rec }) {
  if (!rec) return null;
  const tags = owaspTags(rec);
  return html`<dl class="kv">
    ${isNum(rec.seq) ? html`<dt>audit seq</dt><dd class="num">#${rec.seq}</dd>` : null}
    <dt>policy</dt><dd>v${str(rec.policy_version)} <${Mono}>${shortHash(rec.policy_hash)}<//></dd>
    ${rec.ts ? html`<dt>time</dt><dd class="num">${fmtClock(rec.ts)}</dd>` : null}
    <dt>agent</dt><dd><${Mono}>${str(rec.agent_id) || '-'}<//></dd>
    <dt>kind</dt><dd>${str(rec.kind)} · ${str(rec.direction)}</dd>
    ${rec.session_id ? html`<dt>session</dt><dd><${Mono}>${str(rec.session_id, 80)}<//></dd>` : null}
    ${rec.tool ? html`<dt>tool</dt><dd><${Mono}>${str(rec.tool)}<//></dd>` : null}
    ${rec.request_id ? html`<dt>request</dt><dd><${Mono}>${str(rec.request_id)}<//></dd>` : null}
    ${tags.length ? html`<dt>OWASP</dt><dd>${tags.map((t) => html`<span class="tag" title=${OWASP_TITLES[t] || ''}>${t}</span> `)}</dd>` : null}
    ${rec.model ? html`<dt>model</dt><dd><${Mono}>${str(rec.model)}<//></dd>` : null}
    ${isNum(rec.tokens_in) && (rec.tokens_in || rec.tokens_out) ? html`<dt>tokens</dt><dd class="num">${fmtInt(rec.tokens_in)} in / ${fmtInt(rec.tokens_out)} out · ${fmtUsd(rec.cost_usd)}</dd>` : null}
    ${rec.approval_id ? html`<dt>approval</dt><dd><${Mono}>${str(rec.approval_id)}<//></dd>` : null}
    ${Array.isArray(rec.detectors_disabled) && rec.detectors_disabled.length
      ? html`<dt>disabled</dt><dd class="sev-text-block">${rec.detectors_disabled.map((x) => str(x)).join(', ')}</dd>` : null}
    ${rec.hash ? html`<dt>hash</dt><dd><${Mono} title=${'prev ' + str(rec.prev)}>${shortHash(rec.hash, 16)}<//></dd>` : null}
  </dl>`;
}

/** Accessible modal dialog: Esc and backdrop close it, focus moves inside and returns on close. */
export function Modal({ title, onClose, children, labelId = 'modal-title' }) {
  const ref = useRef(null);
  useEffect(() => {
    const prev = document.activeElement;
    const el = ref.current;
    const first = el && el.querySelector('input, textarea, select, button');
    if (first) first.focus();
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      } else if (e.key === 'Tab' && el) {
        const items = Array.from(el.querySelectorAll('button, input, textarea, select, a[href]')).filter((n) => !n.disabled);
        if (!items.length) return;
        const firstItem = items[0];
        const lastItem = items[items.length - 1];
        if (e.shiftKey && document.activeElement === firstItem) { e.preventDefault(); lastItem.focus(); }
        else if (!e.shiftKey && document.activeElement === lastItem) { e.preventDefault(); firstItem.focus(); }
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      if (prev && typeof prev.focus === 'function') prev.focus();
    };
  }, []);
  return html`<div class="modal-backdrop" onClick=${(e) => { if (e.target === e.currentTarget) onClose(); }}>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby=${labelId} ref=${ref}>
      <h2 id=${labelId} class="modal-title">${title}</h2>
      ${children}
    </div>
  </div>`;
}

export function Section({ title, id, children, actions, className = '' }) {
  return html`<section class=${'card ' + className} aria-labelledby=${id}>
    <header class="card-head">
      <h2 id=${id} class="card-title">${title}</h2>
      ${actions ? html`<div class="card-actions">${actions}</div>` : null}
    </header>
    ${children}
  </section>`;
}

export function ErrorLine({ text }) {
  if (!text) return null;
  return html`<p class="error-line" role="alert">${str(text, 400)}</p>`;
}

/** A few chain links around the record where verification of the tampered copy broke. */
export function DrillRibbon({ drill }) {
  if (!drill || !isNum(drill.broken_at)) return null;
  const b = drill.broken_at;
  const max = isNum(drill.records) ? drill.records : b + 3;
  const tiles = [];
  for (let s = Math.max(1, b - 4); s <= Math.min(max, b + 3); s += 1) tiles.push(s);
  return html`<div class="ribbon" role="img" aria-label=${`Copy of the chain breaks at record ${b}`}>
    ${tiles.map((s, i) => html`
      ${i > 0 ? html`<span class=${'rib-link' + (s === b ? ' broken' : '')} aria-hidden="true">${s === b ? '\u2715' : ''}</span>` : null}
      <span class=${'rib-tile' + (s === b ? ' broken' : s > b ? ' after' : '')}><span class="num">#${s}</span>
        ${s === b ? html`<span class="rib-note">${str(drill.field) || 'edited'}</span>` : null}</span>`)}
  </div>`;
}
