// Shared top status bar and the banners that surface failure first: rejected policy edit,
// detectors disabled, monitor mode, judge breaker open, killed agents, stale data.

import { html, useState, useEffect, useRef } from '../vendor/preact-htm.js';
import { snapshot, conn, now, chain, route, skewMs, approvals } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, shortHash, fmtAgo, fmtClock, toSec, fmtCountdown, num, isNum, upstreamTotal, fmtInt } from '../lib/format.js';
import { getAdminToken, setAdminToken } from '../api.js';
import { Modal, Icon } from './ui.js';
import { theme, cycleTheme } from '../lib/theme.js';

const BOOT = Date.now();
const STALE_MS = 3000;
const DISCONNECTED_MS = 15000;

function Lamp({ tone, label, children, title, className }) {
  return html`<div class=${'lamp tone-' + tone + (className ? ' ' + className : '')} title=${title || undefined}>
    <span class="lamp-dot" aria-hidden="true"></span>
    <span class="lamp-k">${label}</span><span class="lamp-v">${children}</span>
  </div>`;
}

/** Connection health next to nav — fixed words only (age in title) so the bar never reflows. */
function LivePill({ tone, label, title }) {
  return html`<div class=${'live-pill tone-' + tone} title=${title || undefined} role="status">
    <span class="live-pill-dot" aria-hidden="true"></span>
    <span class="live-pill-t">${label}</span>
  </div>`;
}

const THEME_NEXT = { system: 'light', light: 'dark', dark: 'system' };
const THEME_ICON = { system: 'system', light: 'sun', dark: 'moon' };

function ThemeToggle() {
  const t = useSig(theme);
  return html`<button type="button" class="icon-btn" onClick=${cycleTheme}
      aria-label=${`Theme: ${t}. Switch to ${THEME_NEXT[t]}`} title=${`Theme: ${t} (click for ${THEME_NEXT[t]})`}>
    <${Icon} name=${THEME_ICON[t] || 'system'} size=${16} />
  </button>`;
}

function Settings({ onClose }) {
  const [val, setVal] = useState(getAdminToken());
  const [msg, setMsg] = useState('');
  function save(e) {
    e.preventDefault();
    setMsg(setAdminToken(val.trim()) ? 'Saved for this tab.' : 'Browser storage is unavailable: token kept in memory until reload.');
  }
  return html`<${Modal} title="Settings" onClose=${onClose} labelId="settings-title">
    <form onSubmit=${save}>
      <label class="label" for="admin-token">Admin token (X-Admin-Token)</label>
      <input id="admin-token" type="password" autocomplete="off" value=${val} onInput=${(e) => setVal(e.currentTarget.value)} />
      <p class="small muted">Only needed when the gateway runs with AGENTSHIELD_ADMIN_TOKEN. Kept for this tab only (sessionStorage, cleared when the browser session ends) and sent only to /api/ endpoints.</p>
      ${msg ? html`<p class="small" role="status">${msg}</p>` : null}
      <div class="row end">
        <button type="button" class="btn" onClick=${() => { setAdminToken(''); setVal(''); setMsg('Cleared.'); }}>Clear</button>
        <button type="button" class="btn" onClick=${onClose}>Close</button>
        <button type="submit" class="btn primary">Save</button>
      </div>
    </form>
  <//>`;
}

function Banners({ snap, age, everOk, locked }) {
  const [dismissed, setDismissed] = useState('');
  const out = [];
  if (locked && !snap) {
    out.push(html`<div class="banner tone-info" role="status"><span>Public view: the gateway is up, and its console data needs the admin token (Settings, top right). Every Demo card works without it.</span></div>`);
  } else if (everOk && age > DISCONNECTED_MS) {
    out.push(html`<div class="banner tone-block" role="alert"><span>Console disconnected: data frozen at ${fmtClock(Date.now() - age)}. Retrying with backoff.</span></div>`);
  } else if (!everOk && age > DISCONNECTED_MS) {
    out.push(html`<div class="banner tone-block" role="alert"><span>Gateway unreachable: no snapshot received yet. Is the backend running?</span></div>`);
  }
  if (!snap) return out.length ? html`<div class="banners">${out}</div>` : null;
  const p = snap.policy || {};
  const lr = p.last_reload || {};
  const rejKey = `${str(lr.ts)}|${str(lr.error)}`;
  if (lr.status === 'rejected' && dismissed !== rejKey) {
    out.push(html`<div class="banner tone-block" role="alert">
      <span>Policy edit rejected at ${fmtClock(lr.ts)}: ${str(lr.error, 300)}. Still enforcing v${str(p.version)} <code class="mono">${shortHash(p.hash)}</code> (last good).</span>
      <button type="button" class="btn small" onClick=${() => setDismissed(rejKey)}>Dismiss</button>
    </div>`);
  }
  const disabled = Array.isArray(p.detectors_disabled) ? p.detectors_disabled : [];
  if (disabled.length) {
    out.push(html`<div class="banner tone-block striped"><span>${disabled.length} detector${disabled.length > 1 ? 's' : ''} disabled in the effective policy (${disabled.map((x) => str(x)).join(', ')}). Flow guard ${p.flow_enabled === false ? 'is OFF' : 'is still ON'}.</span></div>`);
  }
  if (p.mode === 'monitor') {
    out.push(html`<div class="banner tone-redact"><span><strong>Monitor mode.</strong> Detector findings are logged, not enforced. Authentication, budgets, kill switches and hard limits still block.</span></div>`);
  }
  const j = snap.judge || {};
  const open = j.breaker_open === true || j.breaker === 'open';
  if (open) {
    const until = toSec(j.open_until);
    const left = until !== null ? until - (Date.now() + skewMs.peek()) / 1000 : null;
    out.push(html`<div class=${'banner ' + (p.fail_mode === 'open' ? 'tone-block' : 'tone-redact')}><span>
      Semantic judge unavailable: breaker open${left !== null && left > 0 ? ` (probe in ${fmtCountdown(left)})` : ''}.
      Grey-zone traffic follows fail_mode=${str(p.fail_mode) || 'closed'}${p.fail_mode === 'open' ? ' (ALLOWED through)' : ' (blocked)'}. Deterministic detectors are unaffected.</span></div>`);
  } else if (j.breaker === 'half_open') {
    out.push(html`<div class="banner tone-redact"><span>Semantic judge breaker half-open: probing.</span></div>`);
  }
  const killed = Array.isArray(p.kill_switch) ? p.kill_switch : [];
  if (killed.length) {
    out.push(html`<div class="banner tone-block"><span>Kill switch active for ${killed.map((x) => str(x)).join(', ')}.</span></div>`);
  }
  if (snap.feed && snap.feed.last_error) {
    out.push(html`<div class="banner tone-redact"><span>Signature feed: ${str(snap.feed.last_error, 200)}. Previous signature set still active.</span></div>`);
  }
  return out.length ? html`<div class="banners">${out}</div>` : null;
}

export function StatusBar() {
  const snap = useSig(snapshot);
  const c = useSig(conn);
  const t = useSig(now);
  const ch = useSig(chain);
  const r = useSig(route);
  const ap = useSig(approvals);
  const skew = useSig(skewMs);
  const [settings, setSettings] = useState(false);

  const everOk = c.lastOkAt > 0;
  const age = everOk ? t - c.lastOkAt : t - BOOT;
  const p = snap && snap.policy ? snap.policy : null;
  const lr = p && p.last_reload ? p.last_reload : {};
  const j = snap && snap.judge ? snap.judge : null;
  const post = snap && snap.posture ? snap.posture : null;
  const calls = snap ? upstreamTotal(snap.upstream_calls) : null;
  const pending = ap.ok ? ap.list.filter((a) => a && a.status === 'pending' && ((toSec(a.expires ?? a.expires_at) ?? Infinity) > (t + skew) / 1000)).length
    : snap ? num(snap.approvals_pending) : 0;

  let judgeTone = 'ok';
  let judgeText = '-';
  if (j) {
    const open = j.breaker_open === true || j.breaker === 'open';
    if (j.enabled === false) { judgeTone = 'off'; judgeText = 'disabled'; }
    else if (open) {
      judgeTone = 'warn';
      const until = toSec(j.open_until);
      const left = until !== null ? until - (t + skew) / 1000 : null;
      judgeText = 'breaker OPEN' + (left !== null && left > 0 ? ` ${fmtCountdown(left)}` : '');
    } else if (j.breaker === 'half_open') { judgeTone = 'warn'; judgeText = 'half-open'; }
    else judgeText = 'closed';
  }
  const judgeTitle = j
    ? `${str(j.backend)} ${str(j.model)}${isNum(j.calls) ? ` · ${fmtInt(j.calls)} calls` : ''}${isNum(j.failures) && j.failures ? `, ${fmtInt(j.failures)} fail` : ''}`
    : '';

  let liveTone = 'ok';
  let liveLabel = 'Live';
  if (c.locked && !everOk) {
    // a 401 is an answer: the gateway is up, only the console data is locked
    liveTone = 'ok';
    liveLabel = 'Live';
  } else if (!everOk) {
    liveTone = age > DISCONNECTED_MS ? 'bad' : 'off';
    liveLabel = age > DISCONNECTED_MS ? 'Offline' : 'Sync';
  } else if (age > DISCONNECTED_MS) {
    liveTone = 'bad';
    liveLabel = 'Offline';
  } else if (age > STALE_MS) {
    liveTone = 'warn';
    liveLabel = 'Stale';
  }
  const liveTitle = c.lastError
    ? `last error: ${str(c.lastError)}`
    : everOk ? `Snapshot age ${fmtAgo(age)}` : 'Waiting for first snapshot';

  let chainTone = 'off';
  let chainText = '-';
  let chainTitle = 'Audit chain not verified yet';
  if (ch && ch.locked && !('ok' in ch)) {
    // a public deployment keeps the audit API behind the admin token: that is not a failure
    chainText = 'locked';
    chainTitle = 'Verifying the chain needs the admin token (Settings)';
  } else if (ch && ch.error && !('ok' in ch)) {
    // the last verification attempt failed: never keep showing an older "ok"
    chainTone = 'warn';
    chainText = 'verify failed';
    chainTitle = `Verification failed: ${str(ch.error)}${ch.last && ch.last.ok ? ' (last successful check was intact)' : ''}`;
  } else if (ch && 'ok' in ch) {
    chainTone = ch.ok ? 'ok' : 'bad';
    chainText = ch.ok ? `ok · ${fmtInt(ch.count)}` : `BROKEN #${str(ch.broken_at)}`;
    chainTitle = ch.ok ? `HMAC chain intact: ${fmtInt(ch.count)} records` : `Chain breaks at #${str(ch.broken_at)}: ${str(ch.reason)}`;
  }
  const reloadAgo = p && toSec(lr.applied_ts ?? lr.ts) !== null ? fmtAgo(t + skew - toSec(lr.applied_ts ?? lr.ts) * 1000) : '';

  const headerRef = useRef(null);
  useEffect(() => {
    // expose the bar's height so sticky columns below it can size themselves
    const el = headerRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return undefined;
    const ro = new ResizeObserver(() => {
      document.documentElement.style.setProperty('--topbar-h', `${Math.round(el.getBoundingClientRect().height)}px`);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return html`<header ref=${headerRef} class=${'topbar' + (p && p.mode === 'monitor' ? ' monitor' : '')}>
    <div class="topbar-row">
      <div class="topbar-left">
        <a class="brand" href="#/demo" aria-label="Sealdesk home">
          <span class="brand-mark" aria-hidden="true"><${Icon} name="shield" size=${16} /></span>
          <span class="brand-name">Sealdesk</span>
        </a>
        <nav class="tabs" aria-label="Views">
          <a href="#/demo" class=${'tab' + (r.tab === 'demo' ? ' on' : '')} aria-current=${r.tab === 'demo' ? 'page' : undefined}>Demo</a>
          <a href="#/console" class=${'tab' + (r.tab === 'console' ? ' on' : '')} aria-current=${r.tab === 'console' ? 'page' : undefined}>
            Console${pending ? html` <span class="pill" aria-label=${pending + ' pending approvals'}>${pending}</span>` : null}</a>
        </nav>
        <${LivePill} tone=${liveTone} label=${liveLabel} title=${liveTitle} />
      </div>
      <div class="lamps" aria-label="Gateway status">
        <${Lamp} tone=${p ? (lr.status === 'rejected' ? 'bad' : 'ok') : 'off'} label="policy"
          title=${p ? `version ${str(p.version)}, hash ${str(p.hash)}, last reload ${str(lr.status)}${reloadAgo ? `, applied ${reloadAgo} ago` : ''}` : ''}>
          ${p ? html`v${str(p.version)} <code class="mono">${shortHash(p.hash, 8)}</code>${lr.status === 'rejected' ? html` <strong>rejected</strong>` : null}` : '-'}
        <//>
        <${Lamp} className="lamp-mode" tone=${p ? (p.mode === 'monitor' ? 'warn' : 'ok') : 'off'} label="mode"
          title=${p ? `profile ${str(p.profile)}` : ''}>
          ${p ? str(p.mode) : '-'}
        <//>
        <${Lamp} className="lamp-judge" tone=${judgeTone} label="judge" title=${judgeTitle}>${judgeText}<//>
        <${Lamp} className="lamp-posture" tone=${post ? (num(post.score) >= 80 ? 'ok' : num(post.score) >= 60 ? 'warn' : 'bad') : 'off'} label="posture">
          ${post ? `${post.grade ? str(post.grade) + ' · ' : ''}${str(post.score)}` : '-'}
        <//>
        <${Lamp} className="lamp-audit" tone=${chainTone} label="audit" title=${chainTitle}>${chainText}<//>
        ${calls !== null ? html`<${Lamp} className="lamp-calls" tone="neutral" label="model calls" title="Upstream model calls since start (all agents)">${fmtInt(calls)}<//>` : null}
      </div>
      <div class="topbar-tools">
        <${ThemeToggle} />
        <button type="button" class="icon-btn" onClick=${() => setSettings(true)} aria-label="Settings" title="Settings">
          <${Icon} name="sliders" size=${16} />
        </button>
      </div>
    </div>
    <${Banners} snap=${snap} age=${age} everOk=${everOk} locked=${c.locked} />
    ${settings ? html`<${Settings} onClose=${() => setSettings(false)} />` : null}
  </header>`;
}
