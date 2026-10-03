// Audit integrity: live chain verification, tamper drill on a scratch copy, exports.

import { html, useState } from '../vendor/preact-htm.js';
import { chain, verifyChain, latestSeq, now } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, fmtAgo } from '../lib/format.js';
import { tamperDrill } from '../lib/moments.js';
import { Section, DrillRibbon } from './ui.js';

export function AuditPanel() {
  const c = useSig(chain);
  const t = useSig(now);
  const [busy, setBusy] = useState(false);
  const [seq, setSeq] = useState('');
  const [drill, setDrill] = useState(null);

  async function verify() { setBusy(true); await verifyChain(); setBusy(false); }
  async function runDrill() {
    setBusy(true);
    const n = /^\d+$/.test(seq.trim()) ? Number(seq.trim()) : null;
    setDrill(await tamperDrill(n));
    setBusy(false);
  }

  const status = !c ? html`<span class="chip sev-none">not verified yet</span>`
    : c.error && !('ok' in c) ? html`<span class="chip sev-redact">verify failed: ${str(c.error)}</span>`
      : c.ok ? html`<span class="chip sev-allow"><span aria-hidden="true">✓</span> VERIFIED</span>`
        : html`<span class="chip sev-block"><span aria-hidden="true">✕</span> BROKEN at #${str(c.broken_at)}</span>`;

  return html`<${Section} title="Audit integrity" id="audit-title">
    <p class="row wrap">${status}
      ${c && 'count' in c ? html`<span class="small num">${str(c.count)} records · HMAC-SHA256 chain</span>` : null}
      ${c && c.reason && !c.ok ? html`<span class="small">${str(c.reason, 200)}</span>` : null}
      ${c && c.at ? html`<span class="small muted">checked ${fmtAgo(t - c.at)} ago</span>` : null}
    </p>
    <div class="row wrap">
      <button type="button" class="btn" disabled=${busy} onClick=${verify}>Verify now</button>
      <a class="btn" href="/api/audit.jsonl" download="audit.jsonl">Export audit.jsonl</a>
      <a class="btn" href="/api/report.md" target="_blank" rel="noopener noreferrer">report.md</a>
    </div>
    <h3 class="sub-title">Tamper drill</h3>
    <p class="small muted">Copies the live chain, rewrites one field of one record, and verifies the copy. audit.jsonl itself is never written.</p>
    <div class="row wrap">
      <label class="label small" for="drill-seq">record seq</label>
      <input id="drill-seq" class="narrow" type="text" inputmode="numeric" placeholder=${String(latestSeq() || 'latest')}
        value=${seq} onInput=${(e) => setSeq(e.currentTarget.value)} />
      <button type="button" class="btn danger-outline" disabled=${busy} onClick=${runDrill}>Run tamper drill</button>
    </div>
    ${drill ? html`<div class=${'drill tone-' + str(drill.tone)}>
      <p><strong>${str(drill.title)}</strong></p>
      <ul class="result-lines">${(drill.lines || []).filter(Boolean).map((l) => html`<li>${str(l, 400)}</li>`)}</ul>
      <${DrillRibbon} drill=${drill.drill} />
    </div>` : null}
  <//>`;
}
