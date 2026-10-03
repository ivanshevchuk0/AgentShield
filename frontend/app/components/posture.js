// Posture score, formula, gaps, and the OWASP LLM Top 10 (2025) coverage grid.

import { html } from '../vendor/preact-htm.js';
import { snapshot } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, num, isNum, OWASP_TITLES } from '../lib/format.js';
import { Section } from './ui.js';

const STATUS_LABEL = { covered: 'covered', partial: 'partial', gap: 'gap' };

export function Coverage() {
  const snap = useSig(snapshot);
  const cov = snap && (Array.isArray(snap.coverage) ? snap.coverage
    : snap.posture && Array.isArray(snap.posture.coverage) ? snap.posture.coverage : null);
  if (!cov || !cov.length) return null;
  return html`<${Section} title="OWASP LLM Top 10 (2025) coverage" id="owasp-title">
    <ul class="owasp-grid">
      ${cov.filter((c) => c && typeof c === 'object').map((c) => {
        const st = STATUS_LABEL[str(c.status)] ? str(c.status) : 'gap';
        return html`<li class=${'owasp-cell cov-' + st}>
          <span class="owasp-id">${str(c.id)}</span>
          <span class="owasp-title">${str(c.title) || OWASP_TITLES[str(c.id)] || ''}</span>
          <span class="owasp-status"><span aria-hidden="true">${st === 'covered' ? '✓' : st === 'partial' ? '◐' : '—'}</span> ${STATUS_LABEL[st]}</span>
          <span class="owasp-controls small muted">${Array.isArray(c.controls) && c.controls.length ? c.controls.map((x) => str(x)).join(', ') : 'out of scope for a runtime gateway'}</span>
        </li>`;
      })}
    </ul>
    <p class="small muted">Covered means every mapped control enforces at full weight. Runtime controls cannot cover training-data or retrieval risks; those rows stay gaps on purpose.</p>
  <//>`;
}

export function Posture() {
  const snap = useSig(snapshot);
  const p = snap && snap.posture && typeof snap.posture === 'object' ? snap.posture : null;
  if (!p) return null;
  const gaps = Array.isArray(p.gaps) ? p.gaps : [];
  const controls = Array.isArray(p.controls) ? p.controls.filter((c) => c && typeof c === 'object') : [];
  const score = num(p.score, NaN);
  return html`<${Section} title="Posture" id="posture-title">
    <div class="posture-head">
      <div class="score" aria-label=${`Posture score ${isNum(score) ? score : 'unknown'} of 100${p.grade ? ', grade ' + str(p.grade) : ''}`}>
        ${p.grade ? html`<span class="grade">${str(p.grade)}</span>` : null}
        <span class="score-num num">${isNum(score) ? score : '-'}</span><span class="muted">/100</span>
      </div>
      <p class="small muted">Policy posture, not a security guarantee.</p>
    </div>
    ${controls.length ? html`<ul class="contrib">
      ${controls.map((c) => {
        const w = num(c.weight, 0);
        const v = num(c.contribution, 0);
        const pct = w > 0 ? Math.min(100, (v / w) * 100) : 0;
        return html`<li class="contrib-row">
          <span class="mono small">${str(c.id)}</span>
          <span class="contrib-track" aria-hidden="true"><span class=${'contrib-fill ' + (pct >= 100 ? 'full' : pct > 0 ? 'part' : 'none')} style=${{ width: pct + '%' }}></span></span>
          <span class="small num">${v.toFixed(1)} / ${w}</span>
        </li>`;
      })}
    </ul>` : null}
    <h3 class="sub-title">Gaps (${gaps.length})</h3>
    ${gaps.length ? html`<ul class="plain small gaps">${gaps.map((g) => html`<li>${str(g, 300)}</li>`)}</ul>` : html`<p class="small muted">No open gaps.</p>`}
    ${p.formula ? html`<details class="small"><summary>Formula</summary><p class="muted">${str(p.formula, 1500)}</p></details>` : null}
  <//>`;
}
