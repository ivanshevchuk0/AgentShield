// Approvals inbox: pending requests with a server-time TTL countdown and approve / deny.
// Mutations are not optimistic: the list refreshes from the server after each decision.

import { html, useState } from '../vendor/preact-htm.js';
import { api } from '../api.js';
import { approvals, now, skewMs, pollApprovals, refreshAll, events, eventsVersion } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, toSec, fmtCountdown, fmtClock, shortHash, isNum } from '../lib/format.js';
import { Section, Mono, ErrorLine } from './ui.js';

function Ring({ left, total }) {
  const frac = total > 0 ? Math.max(0, Math.min(1, left / total)) : 0;
  const r = 15;
  const c = 2 * Math.PI * r;
  const tone = left <= 0 ? 'expired' : left < 30 ? 'block' : left < 60 ? 'redact' : 'neutral';
  return html`<svg class=${'ttl-ring tone-' + tone} viewBox="0 0 36 36" width="36" height="36" aria-hidden="true">
    <circle cx="18" cy="18" r=${r} class="ttl-bg" />
    <circle cx="18" cy="18" r=${r} class="ttl-fg" stroke-dasharray=${c} stroke-dashoffset=${c * (1 - frac)} />
  </svg>`;
}

function whyFor(id) {
  const rec = events().find((r) => r && r.approval_id === id && r.action === 'require_approval');
  return rec || null;
}

function Pending({ a, nowSec }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const created = toSec(a.created ?? a.created_at);
  const expires = toSec(a.expires ?? a.expires_at);
  const left = expires !== null ? expires - nowSec : null;
  const total = expires !== null && created !== null ? expires - created : 120;
  const expired = left !== null && left <= 0;
  const id = str(a.id);
  const tool = str(a.tool) || 'call';
  const why = whyFor(id);
  const args = a.args && typeof a.args === 'object' && !Array.isArray(a.args) ? Object.entries(a.args) : [];

  async function decide(approve) {
    setBusy(true);
    setErr('');
    const res = await api(`/api/approvals/${encodeURIComponent(id)}`, { method: 'POST', body: { approve } });
    setBusy(false);
    if (!res.ok) setErr(res.status === 409 ? `Already decided or expired: ${res.error}` : res.error);
    await pollApprovals();
    refreshAll();
  }

  return html`<li class=${'appr' + (expired ? ' expired' : '')}>
    <div class="appr-head">
      <${Ring} left=${left ?? 0} total=${total} />
      <div class="appr-ttl num" aria-label=${expired ? 'expired' : `${Math.max(0, Math.ceil(left || 0))} seconds left`}>
        ${left === null ? '-' : expired ? 'expired' : fmtCountdown(left) + ' left'}
      </div>
      <div class="appr-what">
        <${Mono}>${tool}<//> <span class="muted">by</span> <${Mono}>${str(a.agent_id)}<//>
        <div class="small muted">id <${Mono}>${shortHash(id, 14)}<//>${a.policy_hash ? html` · policy <${Mono}>${shortHash(a.policy_hash)}<//>` : null}</div>
      </div>
    </div>
    ${why ? html`<p class="small">Why: <${Mono}>${str(why.primary && why.primary.control_id)}<//> ${str(why.summary, 200)} <span class="muted">(#${str(why.seq)})</span></p>` : null}
    ${args.length ? html`<dl class="kv args">${args.map(([k, v]) => html`<dt>${str(k)}</dt><dd><${Mono}>${str(v, 120)}<//></dd>`)}</dl>`
      : a.args_hash ? html`<p class="small muted">args hash <${Mono}>${shortHash(a.args_hash, 16)}<//></p>` : null}
    <p class="small muted">Single use · bound to agent, tool, exact arguments and policy hash.</p>
    <div class="row">
      <button type="button" class="btn" disabled=${busy || expired} onClick=${() => decide(false)}>Deny</button>
      <button type="button" class="btn primary" disabled=${busy || expired} onClick=${() => decide(true)}>Approve ${tool}</button>
    </div>
    <${ErrorLine} text=${err} />
  </li>`;
}

export function Approvals() {
  const st = useSig(approvals);
  const t = useSig(now);
  useSig(eventsVersion);
  const skew = useSig(skewMs);
  const nowSec = (t + skew) / 1000;
  if (st.ok === false && st.status === 404) return null;
  const list = Array.isArray(st.list) ? st.list.filter((a) => a && typeof a === 'object') : [];
  const pending = list.filter((a) => a.status === 'pending');
  const decided = list.filter((a) => a.status !== 'pending').slice(0, 6);
  const live = pending.filter((a) => { const e = toSec(a.expires ?? a.expires_at); return e === null || e > nowSec; });
  return html`<${Section} title=${`Approvals${live.length ? ` (${live.length})` : ''}`} id="appr-title"
      actions=${st.ok === false ? html`<span class="chip sev-redact" title=${str(st.error)}>refresh failed</span>` : null}>
    ${pending.length === 0
      ? html`<p class="muted small">Inbox zero. Approvals appear when an agent calls an irreversible tool such as transfer_funds.</p>`
      : html`<ul class="appr-list">${pending.map((a) => html`<${Pending} key=${a.id} a=${a} nowSec=${nowSec} />`)}</ul>`}
    ${decided.length ? html`<h3 class="sub-title">Recent</h3>
      <ul class="plain small">${decided.map((a) => html`<li>
        <${Mono}>${shortHash(a.id, 10)}<//> ${str(a.tool)} · <strong>${str(a.status)}</strong>
        ${a.who ? html` by ${str(a.who)}` : null}${isNum(toSec(a.decided_at)) ? html` · ${fmtClock(a.decided_at)}` : null}
      </li>`)}</ul>` : null}
    <p class="small muted">Approver identity is recorded as "dashboard". Production: SSO identity and four-eyes approval.</p>
  <//>`;
}
