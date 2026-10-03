// DEMO tab ("Glass Gateway"): attack deck, pipeline replay of the real record, one-sentence
// verdict, evidence with highlighted spans, and the "was the model called?" proof.

import { html, useState, useRef, useEffect, useMemo } from '../vendor/preact-htm.js';
import { buildDeck, chatCall, tryCall, AGENT_KEYS, KEYS } from '../lib/moments.js';
import { Pipeline } from './pipeline.js';
import { Stamp, Evidence, FindingsList, Waterfall, Provenance, Mono, DrillRibbon, AgentPicker } from './ui.js';
import { str, sevKey, sevOf, fmtMs, shortHash, isNum } from '../lib/format.js';
import { localRedaction } from '../lib/highlight.js';
import { snapshot, route, go } from '../state.js';
import { useSig } from '../lib/hooks.js';

const TONE_LABEL = { info: 'INFO', error: 'ERROR' };

function judgePhrase(rec) {
  const j = str(rec.judge) || 'skipped';
  if (j === 'skipped') return 'judge not called';
  if (j === 'allow' || j === 'block') return `judge called (${j})`;
  return `judge ${j}`;
}

/** The verdict sentence a risk officer can read aloud. */
function Verdict({ result, mode }) {
  if (!result) return html`<p class="verdict-empty muted">No decision yet.</p>`;
  const rec = result.record;
  if (!rec) {
    return html`<div class=${'verdict tone-' + (result.tone || 'info')}>
      <div class=${'stamp sev-' + sevKey(result.tone)}>
        <span class="stamp-label">${TONE_LABEL[result.tone] || sevOf(result.tone).label}</span>
        ${result.http ? html`<span class="stamp-http">HTTP ${str(result.http)}</span>` : null}
      </div>
      <p class="verdict-line"><strong>${str(result.title)}</strong></p>
      ${result.lines && result.lines.length ? html`<ul class="result-lines">${result.lines.filter(Boolean).map((l) => html`<li>${str(l, 500)}</li>`)}</ul>` : null}
    </div>`;
  }
  const primary = rec.primary && typeof rec.primary === 'object' ? rec.primary : null;
  const total = rec.timings_ms && isNum(rec.timings_ms.total) ? rec.timings_ms.total : null;
  return html`<div class=${'verdict sev-border-' + sevKey(rec.action)}>
    <${Stamp} action=${str(rec.action)} http=${result.http} monitorMode=${mode === 'monitor'} />
    <p class="verdict-line">
      <strong>${sevOf(rec.action).label}</strong>
      ${primary ? html` · <${Mono}>${str(primary.control_id)}<//>` : null}
      ${' · '}${str(rec.summary, 260)}
      ${total !== null ? html` · <span class="num">${fmtMs(total)} ms</span>` : null}
      ${' · '}${judgePhrase(rec)}
      ${' · '}policy v${str(rec.policy_version)} <${Mono}>${shortHash(rec.policy_hash)}<//>
      ${isNum(rec.seq) ? html` · audit #${rec.seq} sealed` : ''}
    </p>
    <p class="small muted">${str(result.title)}</p>
    ${result.lines && result.lines.length ? html`<ul class="result-lines">${result.lines.filter(Boolean).map((l) => html`<li>${str(l, 500)}</li>`)}</ul>` : null}
  </div>`;
}

/** Model-called proof, what the model received, and the model's reply. */
function Proof({ result }) {
  if (!result || !result.record) return null;
  const rec = result.record;
  const kind = result.kind || str(rec.kind);
  const items = [];
  if (kind === 'chat') {
    const measured = rec.timings_ms && isNum(rec.timings_ms.upstream);
    if (result.upstream) {
      const d = result.upstream.after - result.upstream.before;
      const called = d > 0;
      items.push(html`<div class=${'proof ' + (called ? 'proof-yes' : 'proof-no')}>
        <span class="proof-q">Model called?</span>
        <strong>${called ? 'YES' : 'NO'}</strong>
        <span class="num">upstream calls ${str(result.upstream.before)} → ${str(result.upstream.after)} (Δ${d})</span>
        ${d > 1 ? html`<span class="small muted">other agents' traffic is counted too</span>` : null}
      </div>`);
    } else {
      items.push(html`<div class=${'proof ' + (measured ? 'proof-yes' : 'proof-no')}>
        <span class="proof-q">Model called?</span>
        <strong>${measured ? 'YES' : 'NO'}</strong>
        <span class="small muted">${measured ? 'the record carries a measured upstream time' : 'the record has no upstream time'}</span>
      </div>`);
    }
  }
  const redacted = result.serverRedacted !== undefined && result.serverRedacted !== null
    ? [{ text: result.serverRedacted, token: false }]
    : localRedaction(result.text, rec);
  if (redacted && str(rec.action) === 'redact') {
    items.push(html`<div class="received">
      <span class="proof-q">What the model received</span>
      <p class="received-text">${redacted.map((p) => (p.token ? html`<span class="token">${p.text}</span>` : p.text))}</p>
      <span class="small muted">${result.serverRedacted != null ? 'returned by /api/try' : 'your text with the record’s redaction spans applied in this browser'}</span>
    </div>`);
  }
  if (result.reply) {
    items.push(html`<div class="received">
      <span class="proof-q">Model reply (mock upstream)</span>
      <p class="received-text">${str(result.reply, 600)}</p>
    </div>`);
  }
  return items.length ? html`<div class="proofs">${items}</div>` : null;
}

function MomentCard({ m, index, state, onRun, busy, active, selectedStep }) {
  const done = state ? state.done : [];
  const next = done.length < m.steps.length ? done.length : -1;
  const doneCount = done.filter(Boolean).length;
  return html`<li class=${'mcard' + (active ? ' active' : '')}>
    <div class="mcard-head">
      <span class="mkey" aria-hidden="true">${index + 1}</span>
      <h3 class="mtitle">${m.title}</h3>
      <span class="mcard-meta muted small">
        ${doneCount ? `${doneCount}/${m.steps.length}` : `${m.steps.length} step${m.steps.length > 1 ? 's' : ''}`}
      </span>
    </div>
    <p class="mclaim">${m.claim}</p>
    <div class="msteps" role="group" aria-label=${m.title + ' steps'}>
      ${m.steps.map((s, i) => {
        const outcome = done[i];
        const on = selectedStep === i;
        return html`<button type="button"
          class=${'mstep' + (on ? ' on' : '') + (!on && i === next ? ' next' : '') + (outcome ? ' done sev-edge-' + sevKey(outcome) : '')}
          disabled=${busy} onClick=${() => onRun(m, i)} aria-pressed=${on ? 'true' : 'false'}
          aria-label=${`${m.title}, step ${i + 1}: ${s.label}${on ? ', selected, click to clear' : ''}${outcome ? ', last result ' + sevOf(outcome).short : ''}`}>
          ${m.steps.length > 1 ? html`<span class="mstep-n" aria-hidden="true">${i + 1}</span>` : null}${s.label}
        </button>`;
      })}
    </div>
  </li>`;
}

function FreeText({ onResult, busy, setBusy }) {
  const [text, setText] = useState('');
  const [key, setKey] = useState(KEYS.judge);
  async function send(mode) {
    if (!text.trim() || busy) return;
    setBusy(true);
    const title = mode === 'try' ? 'Your text, inspect only' : 'Your text, through the gateway';
    const r = mode === 'try' ? await tryCall(key, text, title) : await chatCall(key, text, null, title);
    setBusy(false);
    onResult(r);
  }
  return html`<details class="freetext">
    <summary class="freetext-sum">Custom request <span class="muted small">optional free-text</span></summary>
    <form class="freetext-body" onSubmit=${(e) => { e.preventDefault(); send('chat'); }}>
      <label for="ft-text" class="label">Type your own attack</label>
      <textarea id="ft-text" rows="2" spellcheck="false" placeholder="e.g. a sentence with PESEL 44051401359"
        value=${text} onInput=${(e) => setText(e.currentTarget.value)}
        onKeyDown=${(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send('chat'); } }}></textarea>
      <${AgentPicker} id="ft-agent" label="agent" value=${key} options=${AGENT_KEYS}
        onChange=${setKey} />
      <div class="row wrap">
        <button type="submit" class="btn primary" disabled=${busy || !text.trim()}>Send via gateway</button>
        <button type="button" class="btn" disabled=${busy || !text.trim()} onClick=${() => send('try')}>Inspect only</button>
      </div>
      <p class="small muted">Ctrl/Cmd+Enter sends.</p>
    </form>
  </details>`;
}

export function DemoView() {
  const snap = useSig(snapshot);
  const r = useSig(route);
  const [result, setResult] = useState(null);
  const [lastRecord, setLastRecord] = useState(null);
  const [busy, setBusy] = useState(false);
  const [replay, setReplay] = useState(0);
  const [progress, setProgress] = useState({});
  const [activeId, setActiveId] = useState(null);
  const [activeStep, setActiveStep] = useState(null); // { id, i } currently shown in pipeline/why
  const lastRecRef = useRef(null);
  const ctx = useRef({ sessions: {}, approval: { id: null }, lastRecordSeq: () => (lastRecRef.current ? lastRecRef.current.seq : null) });
  const deck = useMemo(() => buildDeck(ctx.current), []);

  function accept(res) {
    setResult(res);
    if (res && res.record) {
      setLastRecord(res.record);
      lastRecRef.current = res.record;
    }
  }

  const isClean = !result && !lastRecord && !activeId && !activeStep && !Object.keys(progress).length;

  function clearView() {
    setResult(null);
    setLastRecord(null);
    lastRecRef.current = null;
    setActiveId(null);
    setActiveStep(null);
    setReplay(0);
  }

  function resetStage() {
    if (busy || isClean) return;
    clearView();
    setProgress({});
    ctx.current.sessions = {};
    ctx.current.approval = { id: null };
  }

  async function run(m, i) {
    if (busy) return;
    // Toggle off: same step already driving the theater ? idle center + right.
    if (activeStep && activeStep.id === m.id && activeStep.i === i && (result || lastRecord)) {
      clearView();
      return;
    }
    setBusy(true);
    setActiveId(m.id);
    setActiveStep({ id: m.id, i });
    let res;
    try {
      res = await m.steps[i].run();
    } catch (e) {
      res = { title: m.steps[i].label, tone: 'error', lines: [String((e && e.message) || e)] };
    }
    setBusy(false);
    accept(res);
    setProgress((p) => {
      const done = (p[m.id] ? p[m.id].done : []).slice();
      done[i] = res.record ? str(res.record.action) : res.tone;
      return { ...p, [m.id]: { done } };
    });
  }

  // keyboard: 1-9 fire the next step of a moment, R replays, Esc resets
  useEffect(() => {
    const onKey = (e) => {
      if (r.tab !== 'demo' || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      if (document.querySelector('.modal')) return;
      if (/^[1-9]$/.test(e.key)) {
        const m = deck[Number(e.key) - 1];
        if (!m) return;
        e.preventDefault();
            const done = progress[m.id] ? progress[m.id].done : [];
        const next = done.length < m.steps.length ? done.length : 0;
        run(m, next);
      } else if (e.key === 'r' || e.key === 'R') {
        if (lastRecord) { e.preventDefault(); setReplay((x) => x + 1); }
      } else if (e.key === 'Escape') {
        if (!isClean && !busy) { e.preventDefault(); resetStage(); }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  });

  const mode = snap && snap.policy ? str(snap.policy.mode) : '';
  const shownRec = result && result.record ? result.record : lastRecord;
  const stale = result && !result.record && lastRecord;

  return html`<div class="demo">
    <aside class="panel deck" aria-label="Attack deck">
      <header class="panel-head">
        <h2 class="panel-title">Attack deck</h2>
        <button type="button" class="btn small ghost deck-reset" disabled=${busy || isClean}
          onClick=${resetStage}
          title="Clear the deck selection and return to the empty pipeline (Esc)">
          Reset
        </button>
      </header>
      <p class="panel-hint muted small">Keys 1–9 fire the next step. Esc resets.</p>
      <div class="panel-body">
        <ol class="mcards">
          ${deck.map((m, i) => html`<${MomentCard} m=${m} index=${i} state=${progress[m.id]} onRun=${run}
            busy=${busy} active=${activeId === m.id}
            selectedStep=${activeStep && activeStep.id === m.id ? activeStep.i : -1} />`)}
        </ol>
        <${FreeText} onResult=${accept} busy=${busy} setBusy=${setBusy} />
      </div>
    </aside>

    <section class=${'panel theater' + (shownRec ? '' : ' theater-idle')} aria-labelledby="theater-title">
      <header class="panel-head theater-head">
        <h2 id="theater-title" class="panel-title">Pipeline</h2>
        ${shownRec ? html`<span class="tag replay-tag">replay of record #${str(shownRec.seq)} · timings measured, animation is not</span>` : html`<span class="tag replay-tag">awaiting traffic</span>`}
        <button type="button" class="btn small" disabled=${!shownRec} onClick=${() => setReplay((x) => x + 1)} title="Replay (R)">Replay</button>
        ${busy ? html`<span class="spinner" role="status">sending…</span>` : null}
      </header>
      <div class="panel-body">
        <div class=${'theater-body' + (stale ? ' dimmed' : '')}><${Pipeline} rec=${shownRec} replayToken=${replay} /></div>
        <div class="verdict-region" aria-live="assertive" aria-atomic="true">
          <${Verdict} result=${result} mode=${mode} />
        </div>
        ${result && result.drill ? html`<${DrillRibbon} drill=${result.drill} />` : null}
        ${result && result.chain ? html`<p class="small">Chain: <strong class=${result.chain.ok ? 'sev-text-allow' : 'sev-text-block'}>${result.chain.ok ? 'intact' : 'broken at #' + str(result.chain.broken_at)}</strong> · ${str(result.chain.count)} records</p>` : null}
        <${Proof} result=${result} />
        ${shownRec && shownRec.timings_ms ? html`<div class="timing-block">
          <h3 class="sub-title">Measured timings</h3>
          <${Waterfall} rec=${shownRec} />
        </div>` : null}
      </div>
    </section>

    <aside class=${'panel rail' + (shownRec ? '' : ' rail-idle')} aria-label="Evidence">
      <header class="panel-head">
        <h2 id="rail-why" class="panel-title">Why</h2>
        ${shownRec
          ? html`<span class="tag">record #${str(shownRec.seq)}</span>
            ${isNum(shownRec.seq) ? html`<button type="button" class="btn small" onClick=${() => go('#/console/' + shownRec.seq)}>Console</button>` : null}`
          : html`<span class="tag rail-standby"><span class="rail-dot" aria-hidden="true"></span>standing by</span>`}
      </header>
      <div class="panel-body">
        ${shownRec ? html`
          <div class="blot-live">
            <section class="blot-block" aria-label="Excerpt">
              <h3 class="blot-h">Excerpt</h3>
              <${Evidence} rec=${shownRec} />
            </section>
            <section class="blot-block" aria-label="Findings">
              <h3 class="blot-h">Findings</h3>
              <${FindingsList} rec=${shownRec} limit=${12} />
            </section>
            <section class="blot-block" aria-label="Record provenance">
              <h3 class="blot-h">Record</h3>
              <${Provenance} rec=${shownRec} />
            </section>
          </div>` : html`
          <div class="blot" aria-label="Empty decision blotter">
            <p class="blot-lead">Decision blotter — empty until the gateway seals a record.</p>

            <section class="blot-block is-empty" aria-label="Excerpt placeholder">
              <div class="blot-h-row">
                <h3 class="blot-h">Excerpt</h3>
                <span class="blot-meta">masked · stored</span>
              </div>
              <div class="blot-ph blot-ph-excerpt" aria-hidden="true">
                <span class="blot-ph-line w90"></span>
                <span class="blot-ph-line w70"></span>
                <span class="blot-ph-line w55"></span>
              </div>
            </section>

            <section class="blot-block is-empty" aria-label="Findings placeholder">
              <div class="blot-h-row">
                <h3 class="blot-h">Findings</h3>
                <span class="blot-meta">0 hits</span>
              </div>
              <table class="blot-table">
                <thead><tr><th>Control</th><th>Score</th><th>OWASP</th></tr></thead>
                <tbody>
                  <tr><td colspan="3" class="blot-empty-cell">No detector hits yet</td></tr>
                </tbody>
              </table>
            </section>

            <section class="blot-block is-empty" aria-label="Policy placeholder">
              <div class="blot-h-row">
                <h3 class="blot-h">Policy in force</h3>
                <span class="blot-meta">live snap</span>
              </div>
              <dl class="blot-kv">
                <div><dt>version</dt><dd class="mono muted">—</dd></div>
                <div><dt>hash</dt><dd class="mono muted">········</dd></div>
                <div><dt>mode</dt><dd class="muted">${mode || '—'}</dd></div>
              </dl>
            </section>

            <section class="blot-block is-empty" aria-label="Audit seal placeholder">
              <div class="blot-h-row">
                <h3 class="blot-h">Audit seal</h3>
                <span class="blot-meta">HMAC chain</span>
              </div>
              <dl class="blot-kv">
                <div><dt>seq</dt><dd class="mono muted">#—</dd></div>
                <div><dt>prev</dt><dd class="mono muted">········</dd></div>
                <div><dt>status</dt><dd><span class="blot-unset">unset</span></dd></div>
              </dl>
            </section>

            <p class="blot-foot muted small">Fire a moment from the deck. Console holds the full blotter after seal.</p>
          </div>`}
      </div>
    </aside>
  </div>`;
}
