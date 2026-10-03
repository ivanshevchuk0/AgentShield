// Policy: what is enforcing now, controls with guarded toggles, profile switch, a YAML editor with
// a live diff against the enforced text, the server's validation verdict, and reload history.
//
// Edits are never overwritten by a background or post-apply reload (review finding #1): the
// draft is replaced only when it still equals the text it was loaded from, and the editor is
// read-only while a mutation or reload is in flight.

import { html, useState, useEffect, useRef, useMemo } from '../vendor/preact-htm.js';
import { api, listOf } from '../api.js';
import { snapshot, refreshAll } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, shortHash, fmtClock } from '../lib/format.js';
import { Modal } from './ui.js';

const PROFILES = [
  ['standard', 'Standard', 'enforce · fail closed'],
  ['strict', 'Strict', 'PII blocks · lower thresholds'],
  ['dev', 'Dev', 'monitor · fail open'],
];
const CONTROL_LABEL = {
  prompt_injection: 'Prompt injection', pii: 'PII', secrets: 'Secrets', signatures: 'Exploit signatures',
  canary: 'Canary tokens', loop: 'Loop guard', semantic: 'Semantic judge', flow: 'Flow guard',
};

/* ------------------------------------------------------------------ line diff (LCS) */

function lineDiff(a, b) {
  const x = a.split('\n');
  const y = b.split('\n');
  let pre = 0;
  while (pre < x.length && pre < y.length && x[pre] === y[pre]) pre += 1;
  let suf = 0;
  while (suf < x.length - pre && suf < y.length - pre && x[x.length - 1 - suf] === y[y.length - 1 - suf]) suf += 1;
  const xm = x.slice(pre, x.length - suf);
  const ym = y.slice(pre, y.length - suf);
  const n = xm.length;
  const m = ym.length;
  const ops = [];
  for (let i = 0; i < pre; i += 1) ops.push({ t: ' ', a: i + 1, b: i + 1, s: x[i] });
  if (n * m > 400000) {   // pathological paste: show as replace
    xm.forEach((s, i) => ops.push({ t: '-', a: pre + i + 1, s }));
    ym.forEach((s, j) => ops.push({ t: '+', b: pre + j + 1, s }));
  } else {
    const w = m + 1;
    const dp = new Uint32Array((n + 1) * w);
    for (let i = n - 1; i >= 0; i -= 1) {
      for (let j = m - 1; j >= 0; j -= 1) {
        dp[i * w + j] = xm[i] === ym[j] ? dp[(i + 1) * w + j + 1] + 1 : Math.max(dp[(i + 1) * w + j], dp[i * w + j + 1]);
      }
    }
    let i = 0;
    let j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && xm[i] === ym[j]) { ops.push({ t: ' ', a: pre + i + 1, b: pre + j + 1, s: xm[i] }); i += 1; j += 1; }
      else if (j < m && (i >= n || dp[i * w + j + 1] >= dp[(i + 1) * w + j])) { ops.push({ t: '+', b: pre + j + 1, s: ym[j] }); j += 1; }
      else { ops.push({ t: '-', a: pre + i + 1, s: xm[i] }); i += 1; }
    }
  }
  for (let k = 0; k < suf; k += 1) {
    const ia = x.length - suf + k;
    const ib = y.length - suf + k;
    ops.push({ t: ' ', a: ia + 1, b: ib + 1, s: x[ia] });
  }
  return ops;
}

/** Hunks with `ctx` lines of context; also returns counts and the changed line numbers of b. */
function hunks(ops, ctx = 2) {
  const keep = new Array(ops.length).fill(false);
  ops.forEach((o, i) => {
    if (o.t === ' ') return;
    for (let k = Math.max(0, i - ctx); k <= Math.min(ops.length - 1, i + ctx); k += 1) keep[k] = true;
  });
  const out = [];
  let cur = null;
  ops.forEach((o, i) => {
    if (!keep[i]) { cur = null; return; }
    if (!cur) { cur = []; out.push(cur); }
    cur.push(o);
  });
  const added = ops.filter((o) => o.t === '+').length;
  const removed = ops.filter((o) => o.t === '-').length;
  const changedB = new Set(ops.filter((o) => o.t === '+').map((o) => o.b));
  return { out, added, removed, changedB };
}

/* ------------------------------------------------------------------ result + history */

function Verdict({ res, onDismiss }) {
  if (!res) return null;
  if (res.kind === 'error') {
    return html`<div class="cx-verdict-box tone-error" role="alert">
      <div class="cx-verdict-box-head"><strong>Request failed</strong><button type="button" class="cx-btn sm ghost" onClick=${onDismiss}>Dismiss</button></div>
      <p>${str(res.text, 400)}</p></div>`;
  }
  const d = res.data || {};
  if (d.status === 'rejected') {
    return html`<div class="cx-verdict-box tone-block" role="alert">
      <div class="cx-verdict-box-head"><strong>✕ Rejected by server validation</strong><button type="button" class="cx-btn sm ghost" onClick=${onDismiss}>Dismiss</button></div>
      <p class="mono cx-verdict-err">${str(d.error, 600)}</p>
      <p>Nothing changed. Still enforcing <strong class="num">v${str(d.version)}</strong> <code class="mono">${shortHash(d.hash)}</code> (last good).
        ${d.rejected_hash ? html` Rejected text hash <code class="mono">${shortHash(d.rejected_hash)}</code>.` : null} Your draft is kept so you can fix it.</p>
    </div>`;
  }
  const changed = Array.isArray(d.changed) ? d.changed.map((x) => str(x)) : [];
  return html`<div class="cx-verdict-box tone-allow" role="status">
    <div class="cx-verdict-box-head"><strong>${str(d.status) === 'unchanged' ? 'No change: the text equals the enforced policy' : `✓ ${res.label || 'Applied'}`}</strong>
      <button type="button" class="cx-btn sm ghost" onClick=${onDismiss}>Dismiss</button></div>
    <p>Enforcing <strong class="num">v${str(d.version)}</strong> <code class="mono">${shortHash(d.hash)}</code>${changed.length ? html` · changed: ${changed.join(', ')}` : null}. Hot reloaded; every new request uses it.</p>
  </div>`;
}

/* ------------------------------------------------------------------ panel */

export function PolicyPanel() {
  const snap = useSig(snapshot);
  const [loaded, setLoaded] = useState({ text: '', hash: '', version: '', at: 0 });
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [res, setRes] = useState(null);
  const [confirm, setConfirm] = useState(null);   // {title, body, label, run}
  const [loadErr, setLoadErr] = useState('');
  const [hist, setHist] = useState({ supported: null, list: [] });
  const [showDiff, setShowDiff] = useState(true);
  const draftRef = useRef('');
  const loadedRef = useRef(loaded);
  const gen = useRef({ raw: 0, hist: 0 });
  const gutter = useRef(null);
  draftRef.current = draft;
  loadedRef.current = loaded;

  /** Fetch the enforced text. Replaces the draft only if it has no edits (or `force`). */
  async function load(force = false) {
    const g = ++gen.current.raw;
    const basis = loadedRef.current.text;
    setLoading(true);
    const r = await api('/api/policy/raw', { as: 'text' });
    if (g !== gen.current.raw) return;   // a newer load superseded this one
    setLoading(false);
    if (!r.ok) { setLoadErr(r.error); return; }
    setLoadErr('');
    const next = {
      text: r.text, at: Date.now(),
      hash: (r.headers && r.headers.get('X-Policy-Hash')) || '',
      version: (r.headers && r.headers.get('X-Policy-Version')) || '',
    };
    const untouched = draftRef.current === basis || draftRef.current === next.text;
    setLoaded(next);
    if (force || untouched) setDraft(next.text);
  }

  async function loadHistory() {
    const g = ++gen.current.hist;
    const r = await api('/api/policy/history');
    if (g !== gen.current.hist) return;
    const list = r.ok ? listOf(r.data, 'history') : null;
    if (list) setHist({ supported: true, list });
    else setHist((h) => ({ ...h, supported: r.status === 404 || r.status === 405 ? false : h.supported, error: r.error }));
  }

  useEffect(() => { load(true); loadHistory(); }, []);

  const p = snap && snap.policy ? snap.policy : null;
  const enforcedHash = p ? str(p.hash) : '';
  const dirty = draft !== loaded.text;
  const outOfDate = Boolean(p && loaded.hash && enforcedHash !== loaded.hash);

  // The enforced policy changed elsewhere (file edit, profile, another console): follow it when
  // the editor has no edits; otherwise keep the draft and say so.
  useEffect(() => {
    if (!enforcedHash || !loaded.hash || enforcedHash === loaded.hash || busy) return;
    load(false);
    loadHistory();
  }, [enforcedHash]);

  async function mutate(label, req) {
    setBusy(true);
    setRes(null);
    try {
      const r = await req();
      if (r.status === 0 || (!r.ok && !(r.data && r.data.status))) {
        setRes({ kind: 'error', text: r.status === 401 ? 'Admin token required: set it under Settings.' : r.error });
      } else setRes({ kind: 'result', label, data: r.data });
      refreshAll();
      await Promise.all([load(false), loadHistory()]);
    } finally {
      setBusy(false);
    }
  }

  const apply = () => mutate('Applied', () => api('/api/policy', { method: 'POST', body: { yaml: draft }, timeout: 8000 }));
  const profile = (name) => mutate(`Profile ${name} applied`, () => api(`/api/policy/profile/${encodeURIComponent(name)}`, { method: 'POST', body: {} }));
  const detectors = (on) => mutate(on ? 'Detector overrides cleared' : 'All detectors disabled (flow guard stays on)',
    () => api(`/api/policy/detectors-${on ? 'on' : 'off'}`, { method: 'POST', body: {} }));
  const toggle = (name, enabled) => mutate(`${CONTROL_LABEL[name] || name} ${enabled ? 'enabled' : 'disabled'}`,
    () => api('/api/policy/toggle', { method: 'POST', body: { control: name, enabled } }));

  function askProfile(name) {
    if (name === 'dev') {
      setConfirm({
        title: 'Switch to the dev profile?', label: 'Switch to dev', danger: true, run: () => profile('dev'),
        body: html`<ul class="cx-effects">
          <li><code class="mono">mode: monitor</code>: detector findings are logged and not enforced.</li>
          <li>Authentication, budgets, kill switches and hard limits still block.</li>
          <li><code class="mono">fail_mode: open</code>: grey-zone traffic is allowed while the judge is down.</li>
          <li>Posture score drops; the change is logged to the audit chain.</li></ul>`,
      });
    } else profile(name);
  }

  function askToggle(name, enabled) {
    if (enabled) { toggle(name, true); return; }
    setConfirm({
      title: `Disable ${CONTROL_LABEL[name] || name}?`, label: 'Disable', danger: true, run: () => toggle(name, false),
      body: html`<p>Runtime override: the control stops firing for every agent until re-enabled. policy.yaml is not edited.
        ${name === 'flow' ? ' The flow guard is the last line against data exfiltration through tools.' : ' The flow guard keeps protecting tool egress.'}</p>`,
    });
  }

  function askDetectorsOff() {
    setConfirm({
      title: 'Disable all detectors?', label: 'Disable all', danger: true, run: () => detectors(false),
      body: html`<p>Turns off prompt injection, PII, secrets, signatures, canary and the semantic judge for every agent.
        The flow guard, tool allow-lists, approvals, budgets and kill switches keep enforcing. Logged to the audit chain.</p>`,
    });
  }

  const diff = useMemo(() => (dirty ? hunks(lineDiff(loaded.text, draft)) : null), [dirty, loaded.text, draft]);
  const lines = draft ? draft.split('\n').length : 1;
  const tabs = /^\t/m.test(draft);
  const controls = p && p.controls && typeof p.controls === 'object' ? Object.entries(p.controls) : [];
  if (p) controls.push(['flow', { enabled: p.flow_enabled !== false, action: 'egress rules', present: true, overridden: p.overrides && 'flow' in p.overrides }]);
  const disabled = p && Array.isArray(p.detectors_disabled) ? p.detectors_disabled : [];
  const lr = p && p.last_reload ? p.last_reload : null;
  const histList = Array.isArray(hist.list) ? hist.list.slice().reverse().slice(0, 12) : [];
  const nextVersion = loaded.version && /^\d+$/.test(loaded.version) ? Number(loaded.version) + 1 : null;

  return html`<section class="cx-card cx-policy" aria-labelledby="sec-policy">
    <header class="cx-card-head">
      <div class="cx-card-title-wrap"><h2 id="sec-policy" class="cx-card-title" tabIndex="-1">Policy</h2></div>
      ${p ? html`<div class="cx-enforcing num">
        <span class="cx-state tone-allow"><span class="dot" aria-hidden="true"></span>Enforcing</span>
        <strong>v${str(p.version)}</strong> <code class="mono">${shortHash(p.hash)}</code>
        <span class="muted">· ${str(p.profile)} · ${str(p.mode)}${lr ? ` · applied ${fmtClock(lr.applied_ts || lr.ts)}` : ''}</span>
      </div>` : null}
    </header>

    ${lr && lr.status === 'rejected' ? html`<p class="cx-alert tone-block" role="alert">Last edit rejected at ${fmtClock(lr.ts)}: ${str(lr.error, 240)}. The last good version is still enforcing.</p>` : null}

    <div class="cx-policy-bar">
      <div class="cx-field">
        <span class="cx-label" id="prof-l">Profile</span>
        <div class="cx-seg" role="group" aria-labelledby="prof-l">
          ${PROFILES.map(([name, label, hint]) => html`<button type="button" class=${'cx-seg-btn' + (p && p.profile === name ? ' on' : '') + (name === 'dev' ? ' warn' : '')}
            aria-pressed=${p && p.profile === name ? 'true' : 'false'} disabled=${busy || !p || p.profile === name}
            title=${hint} onClick=${() => askProfile(name)}>${label}<span class="cx-seg-hint">${hint}</span></button>`)}
        </div>
      </div>
      <div class="cx-field">
        <span class="cx-label">Detectors</span>
        ${disabled.length
          ? html`<button type="button" class="cx-btn sm primary" disabled=${busy} onClick=${() => detectors(true)}>Re-enable all (${disabled.length} off)</button>`
          : html`<button type="button" class="cx-btn sm danger-outline" disabled=${busy} onClick=${askDetectorsOff}>Disable all…</button>`}
      </div>
    </div>

    ${controls.length ? html`<ul class="cx-controls" aria-label="Controls in the effective policy">
      ${controls.map(([name, c]) => {
        const on = Boolean(c && c.enabled);
        return html`<li class=${'cx-control' + (on ? '' : ' off')}>
          <span class=${'cx-switch' + (on ? ' on' : '')} aria-hidden="true"></span>
          <span class="cx-control-name">${CONTROL_LABEL[name] || name}</span>
          <span class="cx-control-act mono muted">${on ? str(c.action) || 'on' : c && c.present === false ? 'missing' : 'off'}</span>
          ${c && c.overridden ? html`<span class="cx-tag warn" title="Runtime dashboard override, not in policy.yaml">override</span>` : null}
          <button type="button" class="cx-btn xs ghost" disabled=${busy || (c && c.present === false)}
            onClick=${() => askToggle(name, !on)} aria-label=${`${on ? 'Disable' : 'Enable'} ${CONTROL_LABEL[name] || name}`}>${on ? 'Disable' : 'Enable'}</button>
        </li>`;
      })}
    </ul>` : null}

    <div class="cx-editor-head">
      <label class="cx-label" for="policy-yaml">policy.yaml</label>
      <span class="muted small num">${loaded.version ? `loaded v${loaded.version} ${shortHash(loaded.hash)}` : loading ? 'loading…' : ''}${busy ? ' · applying…' : loading && loaded.version ? ' · refreshing…' : ''}</span>
    </div>
    <div class=${'cx-editor' + (busy ? ' is-busy' : '')}>
      <div class="cx-gutter" ref=${gutter} aria-hidden="true">
        ${Array.from({ length: lines }, (_, i) => html`<span class=${diff && diff.changedB.has(i + 1) ? 'chg' : ''}>${i + 1}</span>`)}
      </div>
      <textarea id="policy-yaml" class="cx-yaml" rows="18" spellcheck="false" wrap="off" autocapitalize="off" autocomplete="off"
        value=${draft} readOnly=${busy} aria-busy=${busy ? 'true' : 'false'} aria-describedby="policy-hint"
        onInput=${(e) => setDraft(e.currentTarget.value)}
        onScroll=${(e) => { if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop; }}></textarea>
    </div>
    <p id="policy-hint" class="cx-hint">
      ${dirty ? html`<strong class="num">${diff ? `+${diff.added} −${diff.removed}` : ''}</strong> lines vs the loaded version. ` : 'No local edits. '}
      ${tabs ? html`<span class="sev-text-redact">Tab indentation: YAML requires spaces. </span>` : null}
      The server validates before anything is written; a rejected edit never becomes policy.
    </p>
    ${outOfDate && dirty ? html`<div class="cx-alert tone-redact" role="note">
      The enforced policy changed to v${str(p.version)} <code class="mono">${shortHash(p.hash)}</code> while you were editing. The diff below compares against what is enforced now.
      <button type="button" class="cx-link" disabled=${busy} onClick=${() => { setRes(null); load(true); }}>Discard my edits and load v${str(p.version)}</button>
    </div>` : null}

    ${dirty && diff ? html`<div class="cx-diff-wrap">
      <div class="cx-diff-head"><span class="cx-sub">Diff vs enforced</span>
        <button type="button" class="cx-btn xs ghost" aria-expanded=${showDiff ? 'true' : 'false'} onClick=${() => setShowDiff(!showDiff)}>${showDiff ? 'Hide' : 'Show'}</button></div>
      ${showDiff ? html`<div class="cx-diff" role="region" aria-label="Changes against the enforced policy" tabIndex="0">
        ${diff.out.map((h, hi) => html`${hi > 0 ? html`<div class="cx-diff-gap" aria-hidden="true">⋯</div>` : null}
          ${h.map((o) => html`<div class=${'cx-dl ' + (o.t === '+' ? 'add' : o.t === '-' ? 'del' : 'ctx')}>
            <span class="cx-dl-n num">${o.t === '+' ? '' : o.a}</span><span class="cx-dl-n num">${o.t === '-' ? '' : o.b}</span>
            <span class="cx-dl-t" aria-label=${o.t === '+' ? 'added' : o.t === '-' ? 'removed' : undefined}>${o.t === ' ' ? ' ' : o.t}</span><span class="cx-dl-s">${o.s || ' '}</span></div>`)}`)}
      </div>` : null}
    </div>` : null}

    <div class="cx-editor-actions">
      ${dirty ? html`<button type="button" class="cx-btn" disabled=${busy} onClick=${() => setDraft(loaded.text)}>Discard edits</button>` : null}
      <button type="button" class="cx-btn" disabled=${busy || loading} onClick=${() => { setRes(null); load(!dirty); loadHistory(); }}
        title=${dirty ? 'Refreshes the enforced text; your edits stay' : 'Load the enforced text'}>Reload from server</button>
      <button type="button" class="cx-btn primary" disabled=${busy || !dirty} onClick=${apply}>
        ${busy ? 'Validating…' : `Validate and apply${nextVersion && dirty ? ` as v${nextVersion}` : ''}`}</button>
    </div>
    ${loadErr ? html`<p class="cx-error" role="alert">Could not load the policy text: ${str(loadErr, 300)}</p>` : null}
    <${Verdict} res=${res} onDismiss=${() => setRes(null)} />

    ${hist.supported === false ? null : html`<h3 class="cx-sub">Reload history</h3>
      ${histList.length === 0 ? html`<p class="muted small">${hist.supported ? 'No reloads recorded yet.' : 'Loading…'}</p>` : html`<ol class="cx-history">
        ${histList.map((e) => {
          const rej = e.status === 'rejected';
          return html`<li class=${'cx-hist' + (rej ? ' rejected' : '')}>
            <span class="num muted">${fmtClock(e.ts)}</span>
            <span class=${'cx-chip ' + (rej ? 'sev-block' : 'sev-allow')}>${rej ? 'rejected' : str(e.status)}</span>
            <span class="num">${rej ? html`<span class="muted">kept v${str(e.version)}</span>` : `v${str(e.version)}`}</span>
            <code class="mono">${shortHash(e.hash)}</code>
            <span class="cx-hist-d">${rej ? str(e.error, 220) : (Array.isArray(e.changed) && e.changed.length ? e.changed.map((x) => str(x)).join(', ') : 'initial load')}</span>
          </li>`;
        })}
      </ol>`}`}

    ${confirm ? html`<${Modal} title=${confirm.title} onClose=${() => setConfirm(null)} labelId="pol-confirm-title">
      ${confirm.body}
      <div class="cx-form-actions">
        <button type="button" class="cx-btn" onClick=${() => setConfirm(null)}>Cancel</button>
        <button type="button" class=${'cx-btn ' + (confirm.danger ? 'danger' : 'primary')} onClick=${() => { const run = confirm.run; setConfirm(null); run(); }}>${confirm.label}</button>
      </div>
    <//>` : null}
  </section>`;
}
