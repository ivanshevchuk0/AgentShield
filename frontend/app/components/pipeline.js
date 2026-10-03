// Pipeline theater: replays a real decision record stage by stage, as a vertical run log.
// The motion is choreography; the only numbers shown are the record's measured timings_ms.

import { html, useEffect, useState, useMemo } from '../vendor/preact-htm.js';
import { pipelineFor, idlePipeline } from '../lib/pipeline.js';
import { sevOf, sevKey, fmtMs, str } from '../lib/format.js';
import { prefersReducedMotion } from '../lib/hooks.js';
import { Icon, sevIcon } from './ui.js';

const STEP_MS = 55;

const STATE_TEXT = {
  pass: 'passed',
  hit: 'hit',
  note: 'noted',
  off: 'off',
  skipped: 'skipped',
  degraded: 'unavailable',
  'not-reached': 'not reached',
  'not-called': 'not called',
  sealed: 'sealed',
  idle: '',
  pending: '',
};

const STATE_ICON = {
  pass: 'allow',
  note: 'monitor',
  off: 'off',
  skipped: 'bypass',
  degraded: 'clock',
  'not-reached': 'notReached',
  'not-called': 'notReached',
  sealed: 'lock',
  idle: 'pending',
  pending: 'pending',
};

function stateLabel(n, state) {
  if (state === 'hit' && n.action) return sevOf(n.action).short.toLowerCase();
  if (state === 'degraded' && n.judge) return n.judge;
  return STATE_TEXT[state] ?? state;
}

function nodeAria(n) {
  let s = `${n.label}: ${STATE_TEXT[n.state] || n.state || 'idle'}`;
  if (n.action) s += `, ${sevOf(n.action).label.toLowerCase()}`;
  if (n.detail) s += `, ${n.detail}`;
  if (n.ms !== null && n.ms !== undefined) s += `, ${fmtMs(n.ms)} ms measured`;
  return s;
}

function classes(n, state, decisive) {
  const cls = ['st-' + state];
  if (n.action && (state === 'hit' || state === 'note')) cls.push('v-' + sevKey(n.action));
  if (n.independent) cls.push('independent');
  if (decisive) cls.push('decisive');
  return cls.join(' ');
}

function StageIcon({ n, state }) {
  const name = state === 'hit' ? sevIcon(n.action) : STATE_ICON[state] || 'pending';
  return html`<span class="pstage-icon" aria-hidden="true"><${Icon} name=${name} size=${14} /></span>`;
}

function Stage({ n, shown, decisive }) {
  const state = shown ? n.state : 'pending';
  return html`<li class=${'pstage ' + classes(n, state, decisive && shown)} aria-label=${shown ? nodeAria(n) : `${n.label}: waiting`}>
    <${StageIcon} n=${n} state=${state} />
    <span class="pstage-main">
      <span class="pstage-label">${n.label}</span>
      ${n.independent ? html`<span class="pstage-tag">independent</span>` : null}
      ${shown && n.detail && n.detail !== stateLabel(n, state) ? html`<span class="pstage-detail" title=${n.detail}>${n.detail}</span>` : null}
    </span>
    <span class="pstage-state">${shown ? stateLabel(n, state) : ''}</span>
    <span class="pstage-ms num">${shown && n.ms !== null && n.ms !== undefined ? fmtMs(n.ms) + ' ms' : ''}</span>
  </li>`;
}

function Chip({ n, shown }) {
  const state = shown ? n.state : 'pending';
  return html`<li class=${'pchip ' + classes(n, state, false)} aria-label=${shown ? nodeAria(n) : `${n.label}: waiting`}
      title=${shown && n.detail ? n.detail : undefined}>
    <${StageIcon} n=${n} state=${state} />
    <span class="pchip-label">${n.label}</span>
    ${shown && state !== 'pass' && state !== 'idle' ? html`<span class="pchip-state">${stateLabel(n, state)}</span>` : null}
  </li>`;
}

function Group({ col, shown, views }) {
  const hits = col.nodes.filter((n) => n.state === 'hit');
  const strongestHit = hits.length ? hits.map((n) => n.action).sort((a, b) => sevRank(b) - sevRank(a))[0] : null;
  const off = col.nodes.filter((n) => n.state === 'off').length;
  const notReached = col.nodes.every((n) => n.state === 'not-reached');
  const state = !shown ? 'pending' : notReached ? 'not-reached' : col.nodes.every((n) => n.state === 'idle') ? 'idle'
    : strongestHit ? 'hit' : off === col.nodes.length ? 'off' : 'pass';
  const g = { label: 'Detectors', action: strongestHit, state };
  let summary = '';
  if (shown && state !== 'idle') {
    if (notReached) summary = 'not reached';
    else if (hits.length) summary = `${hits.length} hit${hits.length > 1 ? 's' : ''}`;
    else if (off === col.nodes.length) summary = 'all off';
    else summary = 'passed';
  }
  const sub = [`${col.nodes.length} in parallel`];
  if (off && off < col.nodes.length) sub.push(`${off} off`);
  if (views.length) sub.push(`decoded: ${views.join(', ')}`);
  return html`<li class=${'pstage pgroup ' + classes(g, state, false)}>
    <${StageIcon} n=${g} state=${state} />
    <span class="pstage-main">
      <span class="pstage-label">Detectors</span>
      <span class="pstage-detail">${sub.join(' · ')}</span>
    </span>
    <span class="pstage-state">${summary}</span>
    <span class="pstage-ms"></span>
    <ul class="pchips" aria-label="Deterministic detectors, run in parallel on all text views">
      ${col.nodes.map((n) => html`<${Chip} n=${n} shown=${shown} />`)}
    </ul>
  </li>`;
}

const RANK = { allow: 0, monitor: 1, redact: 2, require_approval: 3, block: 4 };
const sevRank = (a) => RANK[a] ?? -1;

export function Pipeline({ rec, replayToken = 0 }) {
  const model = useMemo(() => (rec ? pipelineFor(rec) : idlePipeline('chat')), [rec]);
  const total = model ? model.columns.length : 0;
  const [revealed, setRevealed] = useState(() => (prefersReducedMotion() || !rec ? total : 0));

  useEffect(() => {
    if (!model) return undefined;
    if (prefersReducedMotion() || !rec) {
      setRevealed(total);
      return undefined;
    }
    setRevealed(0);
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setRevealed(i);
      if (i >= total) clearInterval(id);
    }, STEP_MS);
    return () => clearInterval(id);
  }, [rec, replayToken]);

  if (rec && !model) {
    return html`<div class="pipe-empty">
      <p>Record #${str(rec.seq)} is an admin record (<code class="mono">${str(rec.kind)}</code>): it has no request pipeline.</p>
      <p class="muted small">${str(rec.summary, 300)}</p>
    </div>`;
  }
  return html`<div class="pipe-wrap">
    <ol class=${'pstages' + (rec ? '' : ' idle')} aria-label=${rec ? `Pipeline for record ${str(rec.seq)}, ${model.kind} request` : 'Gateway pipeline for a chat request'}>
      ${model.columns.map((col, i) => (col.group
        ? html`<${Group} col=${col} shown=${i < revealed} views=${model.views} />`
        : html`<${Stage} n=${col.nodes[0]} shown=${i < revealed} decisive=${model.decisive === col.nodes[0].id} />`))}
    </ol>
    <p class="pipe-note small muted">${model.note}${rec ? ' Timings are measured; the replay animation is not.' : ''}</p>
  </div>`;
}
