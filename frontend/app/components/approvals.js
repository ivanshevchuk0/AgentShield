// Approvals inbox: who wants to run which tool with which arguments, why, under which policy, and
// how long is left. Approve is a deliberate two-step action; Deny is one click (it is the safe side).
// Mutations are not optimistic: a card changes only after the server confirms, and a confirmed
// decision is never re-armed by a late poll (review finding #2, approvals part).

import { html, useState, useEffect, useRef } from '../vendor/preact-htm.js';
import { api } from '../api.js';
import { approvals, now, skewMs, refreshAll, events, eventsVersion, snapshot, go } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, toSec, fmtCountdown, fmtClock, shortHash, isNum, OWASP_TITLES } from '../lib/format.js';

/** Seconds of safety margin before the server-side expiry. The skew estimate in state.js treats the
 *  snapshot receipt time as the server's clock (finding #14), so it can lag by one round trip; the
 *  UI stops offering Approve this many seconds early. The server stays authoritative (409). */
const TTL_GUARD_S = 3;
const ARM_MS = 8000;

/** Server-confirmed decisions made from this browser: id -> {status, who, decided_at}. */
const confirmed = new Map();

function Ring({ left, total }) {
  const frac = total > 0 ? Math.max(0, Math.min(1, left / total)) : 0;
  const r = 16;
  const c = 2 * Math.PI * r;
  const tone = left <= 0 ? 'expired' : left < 30 ? 'block' : left < 60 ? 'redact' : 'neutral';
  return html`<svg class=${'cx-ttl tone-' + tone} viewBox="0 0 40 40" width="40" height="40" aria-hidden="true">
    <circle cx="20" cy="20" r=${r} class="cx-ttl-bg" />
    <circle cx="20" cy="20" r=${r} class="cx-ttl-fg" stroke-dasharray=${c} stroke-dashoffset=${c * (1 - frac)} />
  </svg>`;
}

function triggerFor(id) {
  return events().find((x) => x && x.approval_id === id && x.action === 'require_approval') || null;
}

function argText(v) {
  if (typeof v === 'number') return v.toLocaleString('en-US');
  return str(v, 160);
}

function Pending({ a, nowSec, policyHash, onDone }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [armed, setArmed] = useState(false);
  const armTimer = useRef(null);
  const created = toSec(a.created ?? a.created_at);
  const expires = toSec(a.expires ?? a.expires_at);
  const left = expires !== null ? expires - nowSec - TTL_GUARD_S : null;
  const total = expires !== null && created !== null ? expires - created : 120;
  const expired = left !== null && left <= 0;
  const id = str(a.id);
  const tool = str(a.tool) || 'tool call';
  const why = triggerFor(id);
  const p = why && why.primary ? why.primary : null;
  const args = a.args && typeof a.args === 'object' && !Array.isArray(a.args) ? Object.entries(a.args) : [];
  const stalePolicy = policyHash && a.policy_hash && str(a.policy_hash) !== str(policyHash);

  useEffect(() => () => clearTimeout(armTimer.current), []);
  useEffect(() => { if (expired) setArmed(false); }, [expired]);

  function arm() {
    setArmed(true);
    clearTimeout(armTimer.current);
    armTimer.current = setTimeout(() => setArmed(false), ARM_MS);
  }

  async function decide(approve) {
    clearTimeout(armTimer.current);
    setArmed(false);
    setBusy(true);
    setErr('');
    const res = await api(`/api/approvals/${encodeURIComponent(id)}`, { method: 'POST', body: { approve } });
    setBusy(false);
    if (res.ok && res.data && typeof res.data === 'object') {
      confirmed.set(id, { status: str(res.data.status) || (approve ? 'approved' : 'denied'), who: res.data.who, decided_at: res.data.decided_at });
      onDone();
    } else if (res.status === 409) {
      setErr(`Not decided: the server says it is no longer pending (${res.error}).`);
    } else if (res.status === 401) {
      setErr('Admin token required: set it under Settings, then try again.');
    } else {
      setErr(res.error || 'Decision failed.');
    }
    refreshAll();   // serialized pollers, never a parallel direct fetch
  }

  const tone = expired ? 'expired' : left < 30 ? 'block' : left < 60 ? 'redact' : 'neutral';
  return html`<li class=${'cx-appr' + (expired ? ' expired' : '') + (armed ? ' armed' : '')} aria-labelledby=${'ap-' + id}>
    <div class="cx-appr-head">
      <${Ring} left=${left ?? 0} total=${total} />
      <div class="cx-appr-main">
        <div class="cx-appr-title" id=${'ap-' + id}><code class="mono strong">${tool}</code>
          <span class="muted">${' requested by '}</span><code class="mono">${str(a.agent_id)}</code></div>
        <div class="cx-appr-sub num">${created !== null ? `requested ${fmtClock(created)}` : ''} · id <code class="mono">${shortHash(id, 10)}</code></div>
      </div>
      <div class=${'cx-appr-ttl num tone-' + tone} role="timer"
        aria-label=${expired ? 'expired' : `${Math.max(0, Math.ceil(left || 0))} seconds left to decide`}>
        ${left === null ? '—' : expired ? 'expired' : fmtCountdown(left)}<span class="cx-appr-ttl-k">${expired ? '' : 'left'}</span>
      </div>
    </div>

    <div class="cx-appr-why">
      <span class="cx-appr-k">Why</span>
      <div>${p ? html`<code class="mono">${str(p.control_id)}</code>${p.owasp ? html` <span class="cx-tag" title=${OWASP_TITLES[str(p.owasp)] || ''}>${str(p.owasp)} ${OWASP_TITLES[str(p.owasp)] || ''}</span>` : null}
          <span class="muted"> · ${str(p.detail, 200).replace(/approval_id=\w+;\s*/, '') || 'irreversible tool'}</span>
          <button type="button" class="cx-link" onClick=${() => go('#/console/' + why.seq)}>record #${str(why.seq)}</button>`
        : html`<span class="muted">Irreversible tool: the policy requires a human decision.</span>`}</div>
    </div>

    <div class="cx-appr-args">
      <span class="cx-appr-k">Arguments</span>
      ${args.length ? html`<dl class="cx-args">${args.map(([k, v]) => html`<div class="cx-arg"><dt class="mono">${str(k)}</dt><dd class="mono num">${argText(v)}</dd></div>`)}</dl>`
        : html`<span class="muted">Not shown by the gateway${a.args_hash ? html` · args hash <code class="mono">${shortHash(a.args_hash, 16)}</code>` : null}</span>`}
    </div>

    <p class="cx-appr-bind">Single use · bound to this agent, tool, exact arguments${a.args_hash ? html` (<code class="mono">${shortHash(a.args_hash, 8)}</code>)` : null}
      and policy <code class="mono">${shortHash(a.policy_hash)}</code>. Long identifiers are masked for the approver.</p>
    ${stalePolicy ? html`<p class="cx-alert tone-redact" role="note">The enforced policy changed (now <code class="mono">${shortHash(policyHash)}</code>).
      This approval cannot match a retry; the agent will receive a new approval request.</p>` : null}

    <div class="cx-appr-actions">
      <button type="button" class="cx-btn deny" disabled=${busy || expired} onClick=${() => decide(false)}>Deny</button>
      ${armed
        ? html`<button type="button" class="cx-btn approve armed" disabled=${busy || expired} onClick=${() => decide(true)}
            aria-describedby=${'arm-' + id}>Confirm: approve ${tool}</button>
          <button type="button" class="cx-btn ghost sm" onClick=${() => setArmed(false)}>Cancel</button>`
        : html`<button type="button" class="cx-btn approve" disabled=${busy || expired} onClick=${arm}>Approve ${tool}…</button>`}
    </div>
    ${armed ? html`<p class="cx-note" id=${'arm-' + id} role="status">Approving lets <code class="mono">${str(a.agent_id)}</code>${' run '}<code class="mono">${tool}</code> once with exactly these arguments. This confirmation disarms itself in ${ARM_MS / 1000} s.</p>` : null}
    ${err ? html`<p class="cx-error" role="alert">${str(err, 300)}</p>` : null}
  </li>`;
}

const STATUS_TONE = { approved: 'allow', consumed: 'allow', denied: 'block', expired: 'none', pending: 'require_approval' };

export function Approvals() {
  const st = useSig(approvals);
  const t = useSig(now);
  useSig(eventsVersion);
  const skew = useSig(skewMs);
  const snap = useSig(snapshot);
  const [, bump] = useState(0);
  const nowSec = (t + skew) / 1000;
  if (st.ok === false && st.status === 404) return null;
  const list = Array.isArray(st.list) ? st.list.filter((a) => a && typeof a === 'object') : [];
  const view = list.map((a) => {
    const c = confirmed.get(str(a.id));
    if (c && a.status === 'pending') return { ...a, ...c };   // a late poll must not re-arm a decided card
    if (c && a.status !== 'pending') confirmed.delete(str(a.id));
    return a;
  });
  const pending = view.filter((a) => a.status === 'pending');
  const live = pending.filter((a) => { const e = toSec(a.expires ?? a.expires_at); return e === null || e - TTL_GUARD_S > nowSec; });
  const decided = view.filter((a) => a.status !== 'pending').slice(0, 6);
  const policyHash = snap && snap.policy ? str(snap.policy.hash) : '';

  return html`<section class=${'cx-card cx-approvals' + (live.length ? ' has-pending' : '')} aria-labelledby="sec-appr">
    <header class="cx-card-head">
      <div class="cx-card-title-wrap">
        <h2 id="sec-appr" class="cx-card-title" tabIndex="-1">Approvals</h2>
        ${live.length ? html`<span class="cx-count-badge" aria-label=${live.length + ' pending'}>${live.length} pending</span>` : null}
      </div>
      <div class="cx-card-actions">
        ${st.ok === false ? html`<span class="cx-chip sev-redact" title=${str(st.error)}>refresh failed</span>` : html`<span class="muted small">TTL ${isNum(total(list)) ? total(list) + ' s' : '120 s'}</span>`}
      </div>
    </header>
    ${pending.length === 0
      ? html`<div class="cx-zero"><p class="strong">Inbox zero.</p>
          <p class="muted">An approval appears when an agent calls an irreversible tool such as <code class="mono">transfer_funds</code>. The agent retries with <code class="mono">X-Approval</code> after you decide.</p></div>`
      : html`<ul class="cx-appr-list">${pending.map((a) => html`<${Pending} key=${a.id} a=${a} nowSec=${nowSec} policyHash=${policyHash} onDone=${() => bump((n) => n + 1)} />`)}</ul>`}
    ${decided.length ? html`<h3 class="cx-sub">Recent decisions</h3>
      <ul class="cx-recent">${decided.map((a) => html`<li>
        <span class=${'cx-chip sev-' + (STATUS_TONE[str(a.status)] || 'none')}>${str(a.status)}</span>
        <code class="mono">${str(a.tool)}</code>
        <span class="muted">${str(a.agent_id)}</span>
        <span class="muted cx-recent-r num">${a.who ? `by ${str(a.who)}` : ''}${isNum(toSec(a.decided_at)) ? ` · ${fmtClock(a.decided_at)}` : ''}</span>
      </li>`)}</ul>` : null}
    <p class="cx-note">Approver identity is recorded as "dashboard". Production: SSO identity and four-eyes approval.</p>
  </section>`;
}

function total(list) {
  const a = list.find((x) => isNum(toSec(x.expires ?? x.expires_at)) && isNum(toSec(x.created ?? x.created_at)));
  return a ? Math.round(toSec(a.expires ?? a.expires_at) - toSec(a.created ?? a.created_at)) : null;
}
