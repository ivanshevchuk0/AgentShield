// Pipeline theater: replays a real decision record stage by stage. The motion is choreography;
// the only numbers shown are the record's measured timings_ms.

import { html, useEffect, useState, useMemo } from '../vendor/preact-htm.js';
import { pipelineFor } from '../lib/pipeline.js';
import { sevOf, sevKey, fmtMs, str } from '../lib/format.js';
import { prefersReducedMotion } from '../lib/hooks.js';

const STEP_MS = 90;

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
  idle: 'idle',
  pending: 'waiting',
};

function nodeAria(n) {
  let s = `${n.label}: ${STATE_TEXT[n.state] || n.state}`;
  if (n.action) s += `, ${sevOf(n.action).label.toLowerCase()}`;
  if (n.detail) s += `, ${n.detail}`;
  if (n.ms !== null && n.ms !== undefined) s += `, ${fmtMs(n.ms)} ms measured`;
  return s;
}

function Node({ n, shown }) {
  const state = shown ? n.state : 'pending';
  const cls = ['pnode', 'st-' + state];
  if (shown && n.action && (state === 'hit' || state === 'note')) cls.push('sev-' + sevKey(n.action));
  if (n.independent) cls.push('independent');
  return html`<div class=${cls.join(' ')} aria-label=${nodeAria(n)} role="listitem">
    <span class="pnode-label">${n.label}</span>
    ${n.independent ? html`<span class="pnode-tag">independent</span>` : null}
    <span class="pnode-state">${shown ? (n.action && state === 'hit' ? sevOf(n.action).short : STATE_TEXT[state]) : ' '}</span>
    ${shown && n.detail ? html`<span class="pnode-detail" title=${n.detail}>${n.detail}</span>` : null}
    ${shown && n.ms !== null && n.ms !== undefined ? html`<span class="pnode-ms num">${fmtMs(n.ms)} ms</span>` : null}
  </div>`;
}

export function Pipeline({ rec, replayToken = 0 }) {
  const model = useMemo(() => pipelineFor(rec), [rec]);
  const total = model ? model.columns.length : 0;
  const [revealed, setRevealed] = useState(() => (prefersReducedMotion() ? total : 0));

  useEffect(() => {
    if (!model) return undefined;
    if (prefersReducedMotion()) {
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

  if (!rec) {
    return html`<div class="pipe-empty">
      <p><strong>Fire anything from the deck, or type your own.</strong> Nothing reaches the model without passing here.</p>
      <p class="muted">bank-ops-agent can look up customers, read documents, send e-mail and move money.</p>
    </div>`;
  }
  if (!model) {
    return html`<div class="pipe-empty">
      <p>Record #${str(rec.seq)} is an admin record (<code class="mono">${str(rec.kind)}</code>): it has no request pipeline.</p>
      <p class="muted">${str(rec.summary, 300)}</p>
    </div>`;
  }
  return html`<div class="pipe-wrap">
    <div class="pipe" role="list" aria-label=${`Pipeline for record ${str(rec.seq)}, ${model.kind} request`}>
      ${model.columns.map((col, i) => html`
        ${i > 0 ? html`<span class=${'pconn' + (i <= revealed ? ' on' : '')} aria-hidden="true"></span>` : null}
        ${col.group
          ? html`<div class="pgroup" role="listitem" aria-label="Deterministic detectors, run in parallel on all text views">
              <span class="pgroup-label">detectors${model.views.length ? html` · views: ${model.views.join(', ')}` : ''}</span>
              <div role="list">${col.nodes.map((n) => html`<${Node} n=${n} shown=${i < revealed} />`)}</div>
            </div>`
          : html`<${Node} n=${col.nodes[0]} shown=${i < revealed} />`}`)}
    </div>
    <p class="pipe-note small muted">${model.note}</p>
  </div>`;
}
