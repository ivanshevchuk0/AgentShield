// Shared presentational components. All server values are passed through str()/fmt* and
// rendered as text; nothing here builds markup from strings or links to record content.

import { html, useEffect, useRef, useState } from '../vendor/preact-htm.js';
import {
  str, sevOf, sevKey, fmtMs, isNum, owaspTags, OWASP_TITLES, shortHash, fmtClock, fmtUsd, fmtInt,
} from '../lib/format.js';
import { excerptSegments, decodedOnly } from '../lib/highlight.js';
import { decisionExplanation } from '../lib/decision.js';

/** Plain-language impact and next step; never turns policy content into markup. */
export function DecisionExplanation({ rec }) {
  const explanation = decisionExplanation(rec);
  if (!explanation) return null;
  return html`<div class="small" aria-label="Decision explanation">
    <p><strong>What happened:</strong> ${explanation.impact}</p>
    <p><strong>Why:</strong> ${explanation.reason}
      ${explanation.control ? html` · <${Mono}>${explanation.control}<//>` : null}</p>
    <p class="muted"><strong>Next:</strong> ${explanation.next}</p>
  </div>`;
}

/** Custom agent picker: title + role + API key. Replaces the native <select> in the demo free-text form. */
export function AgentPicker({ id, value, options, onChange, label = 'agent', hideLabel = false }) {
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
    <span class=${hideLabel ? 'sr-only' : 'label small'} id=${id + '-label'}>${label}</span>
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

/* ------------------------------------------------------------------ icons
   Inline SVG built with htm (no markup strings). 24px grid, 2px stroke, currentColor. */

const C = (cx, cy, r) => `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
const ICONS = {
  block: ['M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z', 'M8 12h8'],
  require_approval: [C(9, 7, 4), 'M2 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2', 'm16 11 2 2 4-4'],
  redact: ['M9.9 4.24A9.1 9.1 0 0 1 12 4c7 0 10 8 10 8a13.2 13.2 0 0 1-1.67 2.68', 'M6.61 6.61A13.5 13.5 0 0 0 2 12s3 8 10 8a9.7 9.7 0 0 0 5.39-1.61', 'M9.88 9.88a3 3 0 1 0 4.24 4.24', 'M2 2l20 20'],
  monitor: ['M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z', C(12, 12, 3)],
  allow: ['M20 6 9 17l-5-5'],
  info: [C(12, 12, 10), 'M12 16v-4', 'M12 8h.01'],
  error: ['M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z', 'M12 9v4', 'M12 17h.01'],
  lock: ['M5 11h14v10H5z', 'M8 11V7a4 4 0 0 1 8 0v4'],
  bypass: ['M4 18c0-6.6 4.4-10 10-10h5', 'm16 5 3 3-3 3'],
  off: [C(12, 12, 9), 'M5.6 5.6l12.8 12.8'],
  pending: [C(12, 12, 3)],
  clock: [C(12, 12, 9), 'M12 7v5l3 2'],
  sun: [C(12, 12, 4), 'M12 2v2', 'M12 20v2', 'M4.93 4.93l1.41 1.41', 'M17.66 17.66l1.41 1.41', 'M2 12h2', 'M20 12h2', 'M4.93 19.07l1.41-1.41', 'M17.66 6.34l1.41-1.41'],
  moon: ['M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z'],
  system: ['M3 4h18v12H3z', 'M8 20h8', 'M12 16v4'],
  sliders: ['M4 21v-7', 'M4 10V3', 'M12 21v-9', 'M12 8V3', 'M20 21v-5', 'M20 12V3', 'M1 14h6', 'M9 8h6', 'M17 16h6'],
  replay: ['M3 12a9 9 0 1 0 2.64-6.36L3 8', 'M3 3v5h5'],
  send: ['M5 12h14', 'm13 6 6 6-6 6'],
  judge: ['M13 2 3 14h9l-1 8 10-12h-9l1-8z'],
  shield: ['M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z', 'm8.5 12 2.5 2.5 4.5-5'],
  external: ['M14 4h6v6', 'M20 4 10 14', 'M18 14v6H4V6h6'],
};

/** Decorative icon (aria-hidden). `name` is a key of ICONS; unknown names render nothing. */
export function Icon({ name, size = 16, className = '' }) {
  if (name === 'notReached') {
    return html`<svg class=${'icon ' + className} width=${size} height=${size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="3 3.3" />
    </svg>`;
  }
  const paths = ICONS[name];
  if (!paths) return null;
  return html`<svg class=${'icon ' + className} width=${size} height=${size} viewBox="0 0 24 24" aria-hidden="true" focusable="false"
    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    ${paths.map((d) => html`<path d=${d} />`)}
  </svg>`;
}

/** Icon name for an action (or a non-record tone such as 'info' / 'error'). */
export function sevIcon(action) {
  if (action === 'info' || action === 'error') return action;
  const k = sevKey(action);
  return k === 'none' ? 'info' : k;
}

export function SevChip({ action, compact = false }) {
  const s = sevOf(action);
  return html`<span class=${'chip sev-' + sevKey(action)}>
    <${Icon} name=${sevIcon(action)} size=${12} /> ${compact ? s.short : s.label}</span>`;
}

/** Decision badge: icon + label + HTTP status. Same mapping everywhere (shape + text + colour). */
export function Stamp({ action, http, monitorMode, label }) {
  const s = sevOf(action);
  const text = label || (monitorMode && action === 'monitor' ? 'WOULD ACT (monitor)' : s.label);
  return html`<div class=${'stamp sev-' + sevKey(action)} role="img" aria-label=${text + (http ? ', HTTP ' + http : '')}>
    <span class="stamp-glyph" aria-hidden="true"><${Icon} name=${sevIcon(action)} size=${16} /></span>
    <span class="stamp-label">${text}</span>
    ${http ? html`<span class="stamp-http">${str(http)}</span>` : null}
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
  return html`<div class="evidence">
    ${ex ? html`<p class="excerpt" aria-label="Masked excerpt">
      ${ex.truncatedStart ? '…' : ''}${ex.segments.map((s) => (s.mark
        ? html`<mark class=${'hl sev-' + sevKey(s.mark.action)} title=${s.mark.control}>${s.text}</mark>`
        : s.text))}
    </p>` : null}
    ${decoded.length ? html`<ul class="badges" aria-label="Findings seen only after decoding">
      ${decoded.map((f) => html`<li class="badge decoded">
        <span class="badge-k">decoded</span> <${Mono}>${str(f.via)}<//> <span aria-hidden="true">·</span> ${str(f.control_id)}
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
          ${span ? html`<span class="muted small num">span ${span}</span>` : null}
          ${f.via && str(f.via) !== 'original' ? html`<span class="badge decoded small">via ${str(f.via)}</span>` : null}
          ${isNum(f.score) && f.score !== 1 ? html`<span class="muted small num">score ${f.score.toFixed(2)}</span>` : null}
        </div>
        ${f.evidence ? html`<div class="small finding-ev">evidence <${Mono}>${str(f.evidence, 200)}<//></div>` : null}
        ${f.detail ? html`<div class="small muted">${str(f.detail, 400)}</div>` : null}
      </li>`;
    })}
    ${fs.length > limit ? html`<li class="muted small">+${fs.length - limit} more</li>` : null}
  </ul>`;
}

/** Judge statuses for which no classification call was made. Anything else ran (and may have failed). */
export const JUDGE_NOT_RUN = new Set(['skipped', 'disabled', '']);

/** judge_detail {risk, category, model, latency_ms, cost_usd, reason} when the record carries one. */
export function judgeDetailOf(rec) {
  const d = rec && rec.judge_detail;
  return d && typeof d === 'object' && !Array.isArray(d) ? d : null;
}

/** Semantic judge panel: only rendered when the judge actually ran for this record. */
export function JudgeDetail({ rec }) {
  const status = str(rec && rec.judge);
  const d = judgeDetailOf(rec);
  if (JUDGE_NOT_RUN.has(status) && !d) return null;
  const t = rec && rec.timings_ms && typeof rec.timings_ms === 'object' ? rec.timings_ms : {};
  const latency = d && isNum(d.latency_ms) ? d.latency_ms : isNum(t.judge) ? t.judge : null;
  return html`<dl class="kv judge-kv">
    <dt>status</dt><dd><strong>${status || 'unknown'}</strong></dd>
    ${d && isNum(d.risk) ? html`<dt>risk</dt><dd class="num">${d.risk.toFixed(2)}
      <span class="risk-track" aria-hidden="true"><span class="risk-fill" style=${{ width: Math.max(0, Math.min(1, d.risk)) * 100 + '%' }}></span></span></dd>` : null}
    ${d && d.category ? html`<dt>category</dt><dd><${Mono}>${str(d.category, 80)}<//></dd>` : null}
    ${d && d.model ? html`<dt>model</dt><dd><${Mono}>${str(d.model, 120)}<//></dd>` : null}
    ${latency !== null ? html`<dt>latency</dt><dd class="num">${fmtMs(latency)} ms</dd>` : null}
    ${d && isNum(d.cost_usd) ? html`<dt>cost</dt><dd class="num">${fmtUsd(d.cost_usd)}</dd>` : null}
    ${d && d.reason ? html`<dt>reason</dt><dd class="small">${str(d.reason, 300)}</dd>` : null}
  </dl>`;
}

/** Measured timings only: detect, judge, upstream (model or tool), total. */
export function Waterfall({ rec }) {
  const t = rec && rec.timings_ms && typeof rec.timings_ms === 'object' ? rec.timings_ms : {};
  const total = isNum(t.total) ? t.total : null;
  const upstreamLabel = str(rec && rec.kind) === 'tool' ? 'tool exec' : 'model';
  const judge = str(rec && rec.judge) || 'skipped';
  // The judge stage ran whenever it was not skipped/disabled, including timeouts and errors:
  // its elapsed time is real latency even when no verdict came back.
  const judgeRan = !JUDGE_NOT_RUN.has(judge);
  const judgeMs = judgeRan && isNum(t.judge) ? t.judge : null;
  const judgeNote = judgeRan ? (['allow', 'block'].includes(judge) ? '' : judge) : `not called (${judge})`;
  const rows = [
    ['detect', isNum(t.detect) ? t.detect : null, 'detect', '', ''],
    ['judge', judgeMs, 'judge', judgeRan ? 'no time recorded' : judgeNote, judgeMs !== null ? judgeNote : ''],
    [upstreamLabel, isNum(t.upstream) ? t.upstream : null, 'upstream', 'not called', ''],
  ];
  const scale = total || Math.max(1, ...rows.map((r) => r[1] || 0));
  const overhead = total !== null ? Math.max(0, total - (isNum(t.upstream) ? t.upstream : 0)) : null;
  return html`<div class="waterfall" role="table" aria-label="Measured timings in milliseconds">
    ${rows.map(([label, v, cls, empty, note]) => html`<div class="wf-row" role="row">
      <span class="wf-label" role="rowheader">${label}</span>
      <span class="wf-track" role="cell">
        ${v !== null ? html`<span class=${'wf-bar wf-' + cls} style=${{ width: Math.max(1.5, (v / scale) * 100) + '%' }}></span>` : null}
      </span>
      <span class="wf-val num" role="cell">${v !== null
        ? html`${fmtMs(v)} ms${note ? html` <span class="wf-note">${note}</span>` : null}`
        : html`<span class="muted">${empty || '-'}</span>`}</span>
    </div>`)}
    <div class="wf-row wf-total" role="row">
      <span class="wf-label" role="rowheader">total</span>
      <span class="wf-track" role="cell">${total !== null ? html`<span class="wf-bar wf-total-bar" style=${{ width: '100%' }}></span>` : null}</span>
      <span class="wf-val num" role="cell">${total !== null ? fmtMs(total) + ' ms' : '-'}</span>
    </div>
    ${overhead !== null ? html`<p class="small muted wf-foot">Gateway overhead (total minus ${upstreamLabel}): <strong class="num">${fmtMs(overhead)} ms</strong></p>` : null}
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
    ${tags.length ? html`<dt>OWASP</dt><dd class="tags">${tags.map((t) => html`<span class="tag" title=${OWASP_TITLES[t] || ''}>${t}</span>`)}</dd>` : null}
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
