// Per-agent budgets and the kill switch. Kill requires typing the agent id; revive is one confirm.

import { html, useState } from '../vendor/preact-htm.js';
import { api } from '../api.js';
import { snapshot, refreshAll } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, fmtUsd, fmtInt, num, isNum } from '../lib/format.js';
import { Section, Meter, Modal, Mono, ErrorLine } from './ui.js';

function KillDialog({ agent, revive, onClose }) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const ok = revive || typed === agent;
  async function confirm(e) {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    const res = await api(`/api/kill/${encodeURIComponent(agent)}`, { method: revive ? 'DELETE' : 'POST' });
    setBusy(false);
    refreshAll();
    if (!res.ok) { setErr(res.error); return; }
    onClose();
  }
  return html`<${Modal} title=${revive ? `Revive ${agent}?` : `Kill agent ${agent}?`} onClose=${onClose} labelId="kill-title">
    <form onSubmit=${confirm}>
      ${revive
        ? html`<p>Requests with this agent's key are accepted again. Logged to the audit chain. If the agent is also listed in policy.yaml kill_switch, it stays blocked until the policy is edited.</p>`
        : html`<p>Every request with this agent's key is blocked (<code class="mono">tools.kill_switch</code>, HTTP 403) until revived. Logged to the audit chain.</p>
          <label class="label" for="kill-confirm">Type the agent id to confirm</label>
          <input id="kill-confirm" type="text" autocomplete="off" spellcheck="false" value=${typed}
            onInput=${(e) => setTyped(e.currentTarget.value)} placeholder=${agent} />`}
      <${ErrorLine} text=${err} />
      <div class="row end">
        <button type="button" class="btn" onClick=${onClose}>Cancel</button>
        <button type="submit" class=${'btn ' + (revive ? 'primary' : 'danger')} disabled=${!ok || busy}>
          ${revive ? 'Revive' : `Kill ${agent}`}
        </button>
      </div>
    </form>
  <//>`;
}

export function Agents() {
  const snap = useSig(snapshot);
  const [dialog, setDialog] = useState(null);
  if (!snap) return html`<${Section} title="Agents and budgets" id="agents-title"><p class="muted small">Connecting…</p><//>`;
  const killed = new Set(snap.policy && Array.isArray(snap.policy.kill_switch) ? snap.policy.kill_switch.map((x) => str(x)) : []);
  let rows = Array.isArray(snap.budgets) ? snap.budgets.filter((b) => b && typeof b === 'object') : [];
  if (!rows.length && Array.isArray(snap.agents)) rows = snap.agents.map((a) => ({ agent_id: a }));
  return html`<${Section} title="Agents and budgets" id="agents-title">
    ${rows.length === 0 ? html`<p class="muted small">No agents in the policy.</p>` : html`<ul class="agents">
      ${rows.map((b) => {
        const id = str(b.agent_id);
        const isKilled = killed.has(id) || b.killed === true;
        const limit = b.usd_limit === null || b.usd_limit === undefined ? null : num(b.usd_limit, null);
        const used = num(b.usd_used);
        return html`<li class=${'agent' + (isKilled ? ' killed' : '')}>
          <div class="agent-head">
            <${Mono}>${id}<//>
            ${isKilled ? html`<span class="chip sev-block"><span aria-hidden="true">■</span> KILLED</span>`
              : html`<span class="chip sev-allow"><span aria-hidden="true">●</span> active</span>`}
            <button type="button" class=${'btn small ' + (isKilled ? '' : 'danger-outline')}
              onClick=${() => setDialog({ agent: id, revive: isKilled })}>${isKilled ? 'Revive' : 'Kill'}</button>
          </div>
          <div class="agent-budget">
            <span class="small">USD today</span>
            <${Meter} value=${used} max=${limit} label=${`${id} USD used today`} />
            <span class="small num">${fmtUsd(used)} / ${limit === null ? 'no limit' : fmtUsd(limit)}${limit === 0 ? ' (capped)' : ''}</span>
          </div>
          <div class="small muted num">${isNum(num(b.requests_min, NaN)) ? `${fmtInt(b.requests_min)} req/min` : ''}
            ${isNum(num(b.tokens_min, NaN)) ? ` · ${fmtInt(b.tokens_min)} tok/min` : ''}</div>
        </li>`;
      })}
    </ul>`}
    ${dialog ? html`<${KillDialog} agent=${dialog.agent} revive=${dialog.revive} onClose=${() => setDialog(null)} />` : null}
  <//>`;
}
