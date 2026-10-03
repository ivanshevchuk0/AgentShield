// Fleet: per-agent budget meters, live activity from the decision buffer, and the kill switch.
// Kill opens a dialog that states the blast radius and requires typing the agent id; revive is
// a lighter confirm. Nothing changes on screen until the server confirms.

import { html, useState } from '../vendor/preact-htm.js';
import { api } from '../api.js';
import { snapshot, refreshAll, events, eventsVersion, now } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, fmtUsd, fmtInt, num, isNum, toSec, fmtAgo, sevOf, sevKey } from '../lib/format.js';
import { Modal } from './ui.js';

const WINDOW_S = 300;

function activity(id, nowMs) {
  const since = nowMs / 1000 - WINDOW_S;
  let n = 0;
  let blocks = 0;
  let usd = 0;
  let last = null;
  for (const r of events()) {
    if (str(r.agent_id) !== id || ['policy', 'approval', 'kill'].includes(str(r.kind))) continue;
    if (!last) last = r;
    const ts = toSec(r.ts);
    if (ts === null || ts < since) continue;
    n += 1;
    if (r.action === 'block') blocks += 1;
    usd += num(r.cost_usd);
  }
  return { n, blocks, usd, last };
}

function Bar({ value, max, label, warnAt = 0.8 }) {
  const v = isNum(value) ? value : 0;
  let pct = 0;
  if (isNum(max) && max > 0) pct = Math.min(100, (v / max) * 100);
  else if (max === 0) pct = 100;
  const tone = pct >= 100 ? 'block' : pct >= warnAt * 100 ? 'redact' : 'ok';
  return html`<span class="cx-meter" role="meter" aria-label=${label} aria-valuemin="0"
      aria-valuemax=${isNum(max) ? max : undefined} aria-valuenow=${v}>
    <span class=${'cx-meter-fill tone-' + tone} style=${{ width: pct + '%' }}></span>
    ${isNum(max) && max > 0 ? html`<span class="cx-meter-warn" style=${{ left: warnAt * 100 + '%' }} aria-hidden="true"></span>` : null}
  </span>`;
}

function KillDialog({ agent, revive, stats, onClose }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ok = revive || typed.trim() === agent;
  async function confirm(e) {
    e.preventDefault();
    if (!ok || busy) return;
    setBusy(true);
    setErr('');
    const res = await api(`/api/kill/${encodeURIComponent(agent)}`, { method: revive ? 'DELETE' : 'POST' });
    setBusy(false);
    refreshAll();
    if (!res.ok) { setErr(res.status === 401 ? 'Admin token required: set it under Settings.' : res.error); return; }
    onClose();
  }
  return html`<${Modal} title=${revive ? `Revive ${agent}?` : `Kill agent ${agent}?`} onClose=${onClose} labelId="kill-title">
    <form onSubmit=${confirm} class="cx-form">
      ${revive
        ? html`<p>Requests with this agent's key are accepted again and go through every control as usual. Logged to the audit chain.</p>
          <p class="cx-note">If the agent is also listed under <code class="mono">kill_switch</code> in policy.yaml, it stays blocked until the policy is edited.</p>`
        : html`<ul class="cx-effects">
            <li>Every request with this agent's key is refused: <code class="mono">tools.kill_switch</code>, HTTP 403.</li>
            <li>In-flight model calls finish; their output is still inspected.</li>
            <li>Logged to the audit chain. Revive restores access.</li>
          </ul>
          <p class="cx-blast num">Last ${WINDOW_S / 60} min: <strong>${fmtInt(stats.n)}</strong> requests · <strong>${fmtInt(stats.blocks)}</strong> blocked · <strong>${fmtUsd(stats.usd)}</strong></p>
          <label class="cx-label" for="kill-confirm">Type <code class="mono strong">${agent}</code> to confirm</label>
          <input id="kill-confirm" type="text" autocomplete="off" spellcheck="false" autocapitalize="off" value=${typed}
            onInput=${(e) => setTyped(e.currentTarget.value)} aria-invalid=${typed && !ok ? 'true' : undefined} />`}
      ${err ? html`<p class="cx-error" role="alert">${str(err, 300)}</p>` : null}
      <div class="cx-form-actions">
        <button type="button" class="cx-btn" onClick=${onClose}>Cancel</button>
        <button type="submit" class=${'cx-btn ' + (revive ? 'primary' : 'danger')} disabled=${!ok || busy}>
          ${busy ? 'Working…' : revive ? `Revive ${agent}` : `Kill ${agent}`}
        </button>
      </div>
    </form>
  <//>`;
}

export function Agents() {
  const snap = useSig(snapshot);
  useSig(eventsVersion);
  const t = useSig(now);
  const [dialog, setDialog] = useState(null);
  const head = html`<header class="cx-card-head"><div class="cx-card-title-wrap">
    <h2 id="sec-agents" class="cx-card-title" tabIndex="-1">Agents and budgets</h2></div>
    ${snap ? html`<span class="muted small">USD today · last ${WINDOW_S / 60} min activity</span>` : null}</header>`;
  if (!snap) return html`<section class="cx-card" aria-labelledby="sec-agents">${head}<div class="cx-skel" aria-hidden="true"></div><p class="sr-only">Connecting…</p></section>`;
  const killed = new Set(snap.policy && Array.isArray(snap.policy.kill_switch) ? snap.policy.kill_switch.map((x) => str(x)) : []);
  let rows = Array.isArray(snap.budgets) ? snap.budgets.filter((b) => b && typeof b === 'object') : [];
  if (!rows.length && Array.isArray(snap.agents)) rows = snap.agents.map((a) => ({ agent_id: a }));
  const nKilled = rows.filter((b) => killed.has(str(b.agent_id)) || b.killed === true).length;

  return html`<section class=${'cx-card cx-agents' + (nKilled ? ' has-killed' : '')} aria-labelledby="sec-agents">
    ${head}
    ${rows.length === 0 ? html`<p class="muted">No agents in the policy.</p>` : html`<ul class="cx-fleet">
      ${rows.map((b) => {
        const id = str(b.agent_id);
        const isKilled = killed.has(id) || b.killed === true;
        const limit = b.usd_limit === null || b.usd_limit === undefined ? null : num(b.usd_limit, null);
        const used = num(b.usd_used);
        const u = b.usage && typeof b.usage === 'object' ? b.usage : {};
        const cUsed = num(u.compute_seconds_used, NaN);
        const cLim = num(u.compute_seconds_limit, NaN);
        const capped = limit === 0 || (limit !== null && used >= limit);
        const stats = activity(id, t);
        const ls = stats.last ? sevOf(stats.last.action) : null;
        const state = isKilled ? ['block', 'KILLED'] : capped ? ['redact', limit === 0 ? 'NO BUDGET' : 'CAPPED'] : ['allow', 'ACTIVE'];
        return html`<li class=${'cx-agent' + (isKilled ? ' killed' : '')}>
          <div class="cx-agent-head">
            <code class="mono strong cx-agent-id">${id}</code>
            <span class=${'cx-state tone-' + state[0]}><span class="dot" aria-hidden="true"></span>${state[1]}</span>
            <span class="cx-agent-act muted num">${stats.n ? `${stats.n} req · ${stats.blocks} blocked` : 'idle'}</span>
          </div>
          <div class="cx-agent-budget">
            <span class="cx-agent-k">USD today</span>
            <${Bar} value=${used} max=${limit} label=${`${id}: USD used today`} />
            <span class="num cx-agent-v">${fmtUsd(used)} <span class="muted">/ ${limit === null ? '∞' : fmtUsd(limit)}</span></span>
          </div>
          ${isNum(cLim) && cLim > 0 ? html`<div class="cx-agent-budget">
            <span class="cx-agent-k">compute</span>
            <${Bar} value=${isNum(cUsed) ? cUsed : 0} max=${cLim} label=${`${id}: compute seconds used`} />
            <span class="num cx-agent-v">${isNum(cUsed) ? cUsed.toFixed(2) : '0'} <span class="muted">/ ${fmtInt(cLim)} s</span></span>
          </div>` : null}
          <div class="cx-agent-foot">
            <span class="muted num">${fmtInt(b.requests_min)} req/min · ${fmtInt(b.tokens_min)} tok/min</span>
            ${stats.last ? html`<span class="muted num cx-agent-last" title=${str(stats.last.summary, 200)}>last <span class=${'sev-' + sevKey(stats.last.action)}>${ls.short}</span> ${fmtAgo(t - (toSec(stats.last.ts) || 0) * 1000)} ago</span>` : null}
            <button type="button" class=${'cx-btn sm ' + (isKilled ? 'primary-outline' : 'kill')}
              onClick=${() => setDialog({ agent: id, revive: isKilled, stats })}
              aria-label=${isKilled ? `Revive ${id}` : `Kill switch for ${id} (opens a confirmation)`}>
              ${isKilled ? 'Revive…' : 'Kill switch…'}</button>
          </div>
        </li>`;
      })}
    </ul>`}
    ${dialog ? html`<${KillDialog} agent=${dialog.agent} revive=${dialog.revive} stats=${dialog.stats} onClose=${() => setDialog(null)} />` : null}
  </section>`;
}
