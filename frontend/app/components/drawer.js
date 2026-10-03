// Decision detail drawer, deep-linked as #/console/<seq>. A modal side panel: focus is trapped
// inside, the rest of the page is inert, Esc closes, and focus returns to the stream row.

import { html, useEffect, useRef, useState } from '../vendor/preact-htm.js';
import { route, go, eventBySeq, findRecord, eventsVersion, events } from '../state.js';
import { useSig } from '../lib/hooks.js';
import {
  str, sevOf, sevKey, owaspTags, OWASP_TITLES, shortHash, isNum, fmtMs, fmtUsd, fmtInt, toSec,
  SEVERITY, ADMIN_KINDS, isDecodedVia,
} from '../lib/format.js';
import { streamOrder, focusRow } from './stream.js';
import { DecisionExplanation } from './ui.js';

const MASKED_PREFIXES = ['pii.', 'secrets.', 'canary'];
const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/* ------------------------------------------------------------------ evidence (code-point safe) */

function spanOf(f) {
  return f && Number.isInteger(f.start) && Number.isInteger(f.end) && f.end > f.start ? [f.start, f.end] : null;
}

/** Excerpt segments. Python offsets count code points, so slice an Array.from() copy, not the
 *  UTF-16 string (a local fix for review finding #4; lib/highlight.js has the same issue). */
function segments(rec) {
  if (!rec || typeof rec.excerpt !== 'string' || !rec.excerpt) return null;
  const chars = Array.from(rec.excerpt);
  const cut = (a, b) => chars.slice(a, b).join('');
  const off = Number.isInteger(rec.excerpt_offset) ? rec.excerpt_offset : 0;
  const primary = rec.primary && typeof rec.primary === 'object' ? rec.primary : null;
  const ps = spanOf(primary);
  const cand = [];
  if (ps) cand.push({ s: ps[0] - off, e: ps[1] - off, action: str(primary.action || rec.action), control: str(primary.control_id) });
  for (const f of Array.isArray(rec.findings) ? rec.findings : []) {
    const sp = spanOf(f);
    if (!sp) continue;
    const control = str(f.control_id);
    if (ps && sp[0] === ps[0] && sp[1] === ps[1] && control === str(primary.control_id)) continue;
    if (!MASKED_PREFIXES.some((p) => control.startsWith(p))) continue;
    const s = sp[0] - off;
    const e = sp[1] - off;
    if (s < 0 || e > chars.length || !cut(s, e).includes('•')) continue;   // only spans this excerpt really masks
    cand.push({ s, e, action: str(f.action), control });
  }
  const spans = cand.map((c) => ({ ...c, s: Math.max(0, c.s), e: Math.min(chars.length, c.e) }))
    .filter((c) => c.e > c.s)
    .sort((a, b) => a.s - b.s || (SEVERITY[b.action] ?? 0) - (SEVERITY[a.action] ?? 0));
  const merged = [];
  for (const c of spans) {
    const lastM = merged[merged.length - 1];
    if (lastM && c.s < lastM.e) {
      lastM.e = Math.max(lastM.e, c.e);
      if ((SEVERITY[c.action] ?? 0) > (SEVERITY[lastM.action] ?? 0)) { lastM.action = c.action; lastM.control = c.control; }
    } else merged.push({ ...c });
  }
  const out = [];
  let pos = 0;
  for (const m of merged) {
    if (m.s > pos) out.push({ text: cut(pos, m.s), mark: null });
    out.push({ text: cut(m.s, m.e), mark: m });
    pos = m.e;
  }
  if (pos < chars.length) out.push({ text: cut(pos), mark: null });
  return { out, truncatedStart: off > 0 };
}

function Evidence({ rec }) {
  const ex = segments(rec);
  const decoded = (Array.isArray(rec.findings) ? rec.findings : [])
    .filter((f) => f && !Number.isInteger(f.start) && isDecodedVia(f.via));
  if (!ex && !decoded.length) {
    return html`<p class="muted">No excerpt stored for this record${rec.primary && rec.primary.evidence
      ? html`. Masked evidence: <code class="mono">${str(rec.primary.evidence)}</code>` : ''}.</p>`;
  }
  return html`<div class="cx-evidence">
    ${ex ? html`<p class="cx-excerpt" aria-label="Masked excerpt">${ex.truncatedStart ? '…' : ''}${ex.out.map((s) => (s.mark
      ? html`<mark class=${'cx-mark sev-' + sevKey(s.mark.action)} title=${s.mark.control}>${s.text}</mark>` : s.text))}</p>` : null}
    ${decoded.length ? html`<ul class="cx-decoded" aria-label="Findings seen only after decoding">
      ${decoded.map((f) => html`<li><span class="cx-badge">decoded view</span> <code class="mono">${str(f.via)}</code> · <code class="mono">${str(f.control_id)}</code></li>`)}
    </ul>` : null}
    <p class="cx-note">Masked by the gateway before it was written to the audit log. Highlights use the record's own offsets.</p>
  </div>`;
}

/* ------------------------------------------------------------------ findings, judge, timings */

function Findings({ rec }) {
  const fs = (Array.isArray(rec.findings) ? rec.findings : []).filter((f) => f && typeof f === 'object')
    .slice().sort((a, b) => (SEVERITY[str(b.action)] ?? -1) - (SEVERITY[str(a.action)] ?? -1)
      || (Number.isInteger(a.start) ? a.start : 1e9) - (Number.isInteger(b.start) ? b.start : 1e9));
  if (!fs.length) return html`<p class="muted">No control fired.</p>`;
  return html`<ol class="cx-findings">
    ${fs.slice(0, 40).map((f) => {
      const span = Number.isInteger(f.start) ? `${f.start}–${f.end}` : null;
      const s = sevOf(str(f.action));
      return html`<li class=${'cx-finding sev-edge-' + sevKey(str(f.action))}>
        <div class="cx-finding-head">
          <span class=${'cx-chip sev-' + sevKey(str(f.action))}><span aria-hidden="true">${s.glyph}</span>${s.short}</span>
          <code class="mono strong">${str(f.control_id)}</code>
          ${f.owasp ? html`<span class="cx-tag" title=${OWASP_TITLES[str(f.owasp)] || ''}>${str(f.owasp)}</span>` : null}
          <span class="cx-finding-meta">
            ${span ? html`<span class="num">span ${span}</span>` : null}
            ${f.via && str(f.via) !== 'original' ? html`<span>via <code class="mono">${str(f.via)}</code></span>` : null}
            ${isNum(f.score) && f.score !== 1 ? html`<span class="num">score ${f.score.toFixed(2)}</span>` : null}
          </span>
        </div>
        ${f.evidence ? html`<div class="cx-finding-line"><span class="muted">evidence</span> <code class="mono">${str(f.evidence, 200)}</code></div>` : null}
        ${f.detail ? html`<div class="cx-finding-line muted">${str(f.detail, 400)}</div>` : null}
      </li>`;
    })}
    ${fs.length > 40 ? html`<li class="muted">+${fs.length - 40} more</li>` : null}
  </ol>`;
}

const JUDGE_STATUS = {
  allow: ['allow', 'Judge ran: allowed'], block: ['block', 'Judge ran: flagged'], timeout: ['redact', 'Judge timed out'],
  circuit_open: ['redact', 'Breaker open: judge not called'], error: ['block', 'Judge error'],
  budget: ['redact', 'Judge budget exhausted'], disabled: ['none', 'Judge disabled'],
};

function Judge({ rec }) {
  const st = str(rec.judge);
  const d = rec.judge_detail && typeof rec.judge_detail === 'object' ? rec.judge_detail : null;
  if (!d && (!st || st === 'skipped')) return null;
  const [tone, label] = JUDGE_STATUS[st] || ['none', st ? `Judge: ${st}` : 'Judge'];
  const risk = d && isNum(d.risk) ? Math.max(0, Math.min(1, d.risk)) : null;
  return html`<section class="cx-dsec" aria-labelledby="d-judge">
    <h3 id="d-judge" class="cx-dsec-title">Semantic judge</h3>
    <div class="cx-judge">
      <div class="cx-judge-top">
        <span class=${'cx-chip sev-' + tone}>${label}</span>
        ${d && d.category ? html`<code class="mono">${str(d.category)}</code>` : null}
      </div>
      ${risk !== null ? html`<div class="cx-risk" role="meter" aria-label="Judge risk" aria-valuemin="0" aria-valuemax="1" aria-valuenow=${risk}>
        <span class="cx-risk-k">risk</span>
        <span class="cx-risk-track"><span class=${'cx-risk-fill ' + (risk >= 0.7 ? 'hi' : risk >= 0.4 ? 'mid' : 'lo')} style=${{ width: risk * 100 + '%' }}></span></span>
        <span class="num strong">${risk.toFixed(2)}</span>
      </div>` : null}
      ${d ? html`<dl class="cx-kv cols">
        ${d.model ? html`<div><dt>model</dt><dd><code class="mono">${str(d.model)}</code></dd></div>` : null}
        ${isNum(d.latency_ms) ? html`<div><dt>latency</dt><dd class="num">${fmtMs(d.latency_ms)} ms</dd></div>` : null}
        ${isNum(d.cost_usd) ? html`<div><dt>cost</dt><dd class="num">${fmtUsd(d.cost_usd)}</dd></div>` : null}
      </dl>` : null}
      ${d && d.reason ? html`<p class="cx-judge-reason">${str(d.reason, 400)}</p>` : null}
      <p class="cx-note">The judge only sees grey-zone text with PII redacted, and can only raise risk.</p>
    </div>
  </section>`;
}

/** Measured timings. A judge that ran and timed out still shows its latency (review finding #11). */
function Waterfall({ rec }) {
  const t = rec.timings_ms && typeof rec.timings_ms === 'object' ? rec.timings_ms : {};
  const total = isNum(t.total) ? t.total : null;
  const jst = str(rec.judge);
  const judgeRan = jst && !['skipped', 'disabled', 'circuit_open'].includes(jst);
  const upLabel = str(rec.kind) === 'tool' ? 'tool exec' : 'model';
  const rows = [
    ['detect', isNum(t.detect) ? t.detect : null, 'detect', '—'],
    ['judge', judgeRan && isNum(t.judge) ? t.judge : null, 'judge', jst && jst !== 'skipped' ? `not called (${jst})` : 'not needed'],
    [upLabel, isNum(t.upstream) ? t.upstream : null, 'upstream', 'not called'],
  ];
  if (!total && rows.every((x) => x[1] === null)) return html`<p class="muted">No timings in this record.</p>`;
  const scale = total || Math.max(1, ...rows.map((x) => x[1] || 0));
  const overhead = total !== null ? Math.max(0, total - (isNum(t.upstream) ? t.upstream : 0)) : null;
  let offset = 0;
  return html`<div class="cx-wf" role="table" aria-label="Measured timings in milliseconds">
    ${rows.map(([label, v, cls, empty]) => {
      const left = offset;
      if (v !== null) offset += v;
      return html`<div class="cx-wf-row" role="row">
        <span class="cx-wf-k" role="rowheader">${label}</span>
        <span class="cx-wf-track" role="cell">${v !== null ? html`<span class=${'cx-wf-bar wf-' + cls}
          style=${{ left: Math.min(98, (left / scale) * 100) + '%', width: Math.max(1, (v / scale) * 100) + '%' }}></span>` : null}</span>
        <span class="cx-wf-v num" role="cell">${v !== null ? fmtMs(v) + ' ms' : html`<span class="muted">${empty}</span>`}</span>
      </div>`;
    })}
    <div class="cx-wf-row total" role="row">
      <span class="cx-wf-k" role="rowheader">total</span>
      <span class="cx-wf-track" role="cell">${total !== null ? html`<span class="cx-wf-bar wf-total" style=${{ left: 0, width: '100%' }}></span>` : null}</span>
      <span class="cx-wf-v num strong" role="cell">${total !== null ? fmtMs(total) + ' ms' : '—'}</span>
    </div>
    ${overhead !== null ? html`<p class="cx-note">Gateway overhead (total minus ${upLabel}): <strong class="num">${fmtMs(overhead)} ms</strong></p>` : null}
  </div>`;
}

/* ------------------------------------------------------------------ the "why" sentence */

function whyLine(rec) {
  const kind = str(rec.kind);
  const p = rec.primary && typeof rec.primary === 'object' ? rec.primary : null;
  if (ADMIN_KINDS.has(kind)) return `Admin action recorded in the audit chain: ${str(rec.summary, 300)}`;
  if (!p) return str(rec.action) === 'allow' ? 'No control fired. The request was forwarded unchanged.' : str(rec.summary, 300);
  const act = str(rec.action);
  const verb = { block: 'Blocked', redact: 'Redacted and forwarded', require_approval: 'Held for human approval',
    monitor: 'Logged only (monitor)', allow: 'Allowed' }[act] || act;
  const where = p.via && isDecodedVia(p.via) ? ` after decoding the ${str(p.via)} view` : '';
  const dir = str(rec.direction) === 'output' ? ' in the model output' : str(rec.kind) === 'tool' ? ' in a tool call' : '';
  const detail = p.detail ? `: ${str(p.detail, 220)}` : '';
  return `${verb} because ${str(p.control_id)} matched${dir}${where}${detail}.`;
}

function fmtFull(ts) {
  const s = toSec(ts);
  if (s === null) return '—';
  const d = new Date(s * 1000);
  const pad = (x, n = 2) => String(x).padStart(n, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

/* ------------------------------------------------------------------ drawer */

/** Make everything outside the drawer inert while it is open (true modal, finding #9). */
function useInertOutside(rootRef, active) {
  useEffect(() => {
    if (!active || !rootRef.current) return undefined;
    const keep = rootRef.current;
    const touched = [];
    let node = keep;
    while (node && node.parentElement && node !== document.body) {
      for (const sib of Array.from(node.parentElement.children)) {
        if (sib === node || sib.hasAttribute('inert') || sib.tagName === 'SCRIPT') continue;
        sib.setAttribute('inert', '');
        touched.push(sib);
      }
      node = node.parentElement;
    }
    return () => { for (const el of touched) el.removeAttribute('inert'); };
  }, [active]);
}

export function Drawer() {
  const r = useSig(route);
  useSig(eventsVersion);
  const seq = r.tab === 'console' ? r.seq : null;
  const [fetched, setFetched] = useState({ seq: null, rec: null, missing: false });
  const [copied, setCopied] = useState('');
  const panel = useRef(null);
  const root = useRef(null);
  const returnTo = useRef(null);
  const lastSeq = useRef(null);
  const rec = seq === null ? null : eventBySeq(seq) || (fetched.seq === seq ? fetched.rec : null);
  const open = seq !== null;

  if (seq !== null) lastSeq.current = seq;

  useEffect(() => {
    if (seq === null || eventBySeq(seq)) return undefined;
    let alive = true;
    findRecord(seq).then((found) => { if (alive) setFetched({ seq, rec: found, missing: !found }); });
    return () => { alive = false; };
  }, [seq]);

  useInertOutside(root, open);

  // Remember what had focus when the drawer opened; restore it (or the stream row) on close.
  useEffect(() => {
    if (!open) return undefined;
    const prev = document.activeElement;
    returnTo.current = prev && prev !== document.body ? prev : null;
    const h = panel.current && panel.current.querySelector('h2');
    if (h) h.focus();
    return () => {
      const back = returnTo.current;
      const s = lastSeq.current;
      setTimeout(() => {
        const rowMoved = back && back.dataset && back.dataset.seq && Number(back.dataset.seq) !== s;
        if (back && back.isConnected && !rowMoved && !back.closest('[inert]')) back.focus();
        else if (s !== null) focusRow(s);
      }, 0);
    };
  }, [open]);

  useEffect(() => { setCopied(''); }, [seq]);

  function step(delta) {
    const ord = streamOrder().length ? streamOrder() : events().map((x) => x.seq);
    const i = ord.indexOf(seq);
    const next = i < 0 ? ord[0] : ord[i + delta];
    if (next !== undefined && next !== seq) location.replace('#/console/' + next);
  }

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (document.querySelector('.modal')) return;
      const el = panel.current;
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); go('#/console'); return; }
      if (e.key === 'Tab' && el) {
        const items = Array.from(el.querySelectorAll(FOCUSABLE)).filter((n) => n.offsetParent !== null || n === document.activeElement);
        if (!items.length) { e.preventDefault(); return; }
        const first = items[0];
        const lastI = items[items.length - 1];
        const inside = el.contains(document.activeElement);
        if (e.shiftKey && (document.activeElement === first || !inside || document.activeElement === el.querySelector('h2'))) { e.preventDefault(); lastI.focus(); }
        else if (!e.shiftKey && (document.activeElement === lastI || !inside)) { e.preventDefault(); first.focus(); }
        return;
      }
      const t = e.target;
      if (e.metaKey || e.ctrlKey || e.altKey || (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA'))) return;
      if (e.key === 'j') { e.preventDefault(); step(1); }
      else if (e.key === 'k') { e.preventDefault(); step(-1); }
    };
    const onFocusIn = (e) => {
      const el = panel.current;
      if (el && !el.contains(e.target) && !document.querySelector('.modal')) {
        const h = el.querySelector('h2');
        if (h) h.focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('focusin', onFocusIn);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('focusin', onFocusIn);
    };
  }, [open, seq]);

  if (!open) return null;
  const close = () => go('#/console');
  const tags = rec ? owaspTags(rec) : [];
  const admin = rec && ADMIN_KINDS.has(str(rec.kind));
  const s = rec ? sevOf(rec.action) : null;
  const t = rec && rec.timings_ms && typeof rec.timings_ms === 'object' ? rec.timings_ms : {};
  const overhead = isNum(t.total) ? Math.max(0, t.total - (isNum(t.upstream) ? t.upstream : 0)) : null;
  const session = rec && rec.session_id ? events().filter((x) => x.session_id === rec.session_id).length : 0;
  const ord = streamOrder();
  const idx = ord.indexOf(seq);

  async function copy(what) {
    try {
      await navigator.clipboard.writeText(what === 'json' ? JSON.stringify(rec, null, 2) : location.href);
      setCopied(what === 'json' ? 'JSON copied' : 'Link copied');
    } catch {
      setCopied(what === 'json' ? 'Clipboard unavailable' : 'Clipboard unavailable: use the address bar');
    }
  }

  return html`<div class="cx-drawer-root" ref=${root}>
    <div class="cx-drawer-scrim" onClick=${close} aria-hidden="true"></div>
    <aside class="cx-drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title" ref=${panel}>
      <header class="cx-drawer-head">
        <div class="cx-drawer-title">
          <h2 id="drawer-title" tabIndex="-1">Decision <span class="num">#${seq}</span></h2>
          ${rec ? html`<span class="muted num">${fmtFull(rec.ts)}</span>` : null}
        </div>
        <div class="cx-drawer-tools">
          <button type="button" class="cx-btn sm icon" onClick=${() => step(-1)} disabled=${idx <= 0}
            aria-label="Newer decision (k)" title="Newer (k)">↑</button>
          <button type="button" class="cx-btn sm icon" onClick=${() => step(1)} disabled=${idx < 0 || idx >= ord.length - 1}
            aria-label="Older decision (j)" title="Older (j)">↓</button>
          <button type="button" class="cx-btn sm" onClick=${() => copy('link')}>Copy link</button>
          ${rec ? html`<button type="button" class="cx-btn sm" onClick=${() => copy('json')}>Copy JSON</button>` : null}
          <button type="button" class="cx-btn sm" onClick=${close} aria-label="Close decision details (Esc)">Close<kbd>Esc</kbd></button>
        </div>
      </header>
      <p class="sr-only" role="status">${copied}</p>
      ${copied ? html`<p class="cx-toast" aria-hidden="true">${copied}</p>` : null}
      ${!rec
        ? html`<div class="cx-drawer-body"><p class="muted">${fetched.seq === seq && fetched.missing
          ? `Record #${seq} is not in the buffer and the gateway did not return it.` : 'Loading record…'}</p></div>`
        : html`<div class="cx-drawer-body">
          <section class=${'cx-verdict sev-edge-' + (admin ? 'admin' : sevKey(rec.action))} aria-label="Decision">
            <div class="cx-verdict-top">
              <span class=${'cx-stamp sev-' + (admin ? 'admin' : sevKey(rec.action))}>
                <span aria-hidden="true">${admin ? '' : s.glyph}</span>${admin ? str(rec.kind).toUpperCase() + ' · ' + s.short : s.label}</span>
              ${rec.primary ? html`<code class="mono strong">${str(rec.primary.control_id)}</code>` : null}
              ${tags.map((tg) => html`<span class="cx-tag" title=${OWASP_TITLES[tg] || ''}>${tg} · ${OWASP_TITLES[tg] || ''}</span>`)}
            </div>
            <p class="cx-why">${whyLine(rec)}</p>
          </section>

          <dl class="cx-facts">
            <div><dt>Agent</dt><dd><code class="mono">${str(rec.agent_id) || '—'}</code></dd></div>
            <div><dt>Kind</dt><dd>${str(rec.kind)}${rec.direction ? ' · ' + str(rec.direction) : ''}${rec.tool ? html` · <code class="mono">${str(rec.tool)}</code>` : null}</dd></div>
            <div><dt>Policy</dt><dd><span class="num">v${str(rec.policy_version)}</span> <code class="mono">${shortHash(rec.policy_hash)}</code></dd></div>
            <div><dt>Overhead</dt><dd class="num">${overhead !== null ? fmtMs(overhead) + ' ms' : '—'}</dd></div>
          </dl>

          ${Array.isArray(rec.detectors_disabled) && rec.detectors_disabled.length ? html`<p class="cx-alert tone-block">
            Detectors disabled when this was decided: ${rec.detectors_disabled.map((x) => str(x)).join(', ')}.</p>` : null}
          ${rec.approval_id ? html`<p class="cx-alert tone-approval">Approval <code class="mono">${shortHash(rec.approval_id, 14)}</code>
            ${str(rec.action) === 'require_approval' ? ' was requested: see the Approvals inbox.' : ' is referenced by this record.'}</p>` : null}

          <${DecisionExplanation} rec=${rec} />
          <section class="cx-dsec" aria-labelledby="d-ev"><h3 id="d-ev" class="cx-dsec-title">Evidence</h3><${Evidence} rec=${rec} /></section>
          <section class="cx-dsec" aria-labelledby="d-f"><h3 id="d-f" class="cx-dsec-title">Findings <span class="num muted">${Array.isArray(rec.findings) ? rec.findings.length : 0}</span></h3><${Findings} rec=${rec} /></section>
          <${Judge} rec=${rec} />
          <section class="cx-dsec" aria-labelledby="d-t"><h3 id="d-t" class="cx-dsec-title">Timings</h3><${Waterfall} rec=${rec} /></section>
          <section class="cx-dsec" aria-labelledby="d-p">
            <h3 id="d-p" class="cx-dsec-title">Provenance</h3>
            <dl class="cx-kv">
              <dt>audit seq</dt><dd class="num">#${str(rec.seq)}</dd>
              ${rec.hash ? html`<dt>hash</dt><dd><code class="mono">${str(rec.hash)}</code></dd>` : null}
              ${rec.prev ? html`<dt>prev</dt><dd><code class="mono">${str(rec.prev)}</code></dd>` : null}
              ${rec.request_id ? html`<dt>request</dt><dd><code class="mono">${str(rec.request_id)}</code></dd>` : null}
              ${rec.session_id ? html`<dt>session</dt><dd><code class="mono">${str(rec.session_id, 80)}</code>${session > 1 ? html` <span class="muted">· ${session} records in buffer</span>` : null}</dd>` : null}
              ${rec.model ? html`<dt>model</dt><dd><code class="mono">${str(rec.model)}</code></dd>` : null}
              ${isNum(rec.tokens_in) && (rec.tokens_in || rec.tokens_out) ? html`<dt>tokens</dt><dd class="num">${fmtInt(rec.tokens_in)} in · ${fmtInt(rec.tokens_out)} out · ${fmtUsd(rec.cost_usd)}</dd>` : null}
              ${rec.approval_id ? html`<dt>approval</dt><dd><code class="mono">${str(rec.approval_id)}</code></dd>` : null}
            </dl>
            <p class="cx-note">hash = HMAC-SHA256(key, prev + canonical JSON). Editing this record breaks every later link.</p>
          </section>
        </div>`}
    </aside>
  </div>`;
}
