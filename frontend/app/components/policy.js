// Policy panel: raw YAML (as the server enforces it), apply with the server's validation result,
// profile switch, detector overrides, and reload history.

import { html, useState, useEffect } from '../vendor/preact-htm.js';
import { api } from '../api.js';
import { snapshot, refreshAll, policyHistory, loadPolicyHistory } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, shortHash, fmtClock } from '../lib/format.js';
import { Section, Modal, Mono, ErrorLine } from './ui.js';

const PROFILES = ['standard', 'strict', 'dev'];

function changedLines(a, b) {
  const x = a.split('\n');
  const y = b.split('\n');
  let n = Math.abs(x.length - y.length);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) if (x[i] !== y[i]) n += 1;
  return n;
}

function ResultLine({ res }) {
  if (!res) return null;
  if (res.kind === 'error') return html`<${ErrorLine} text=${res.text} />`;
  const d = res.data || {};
  if (d.status === 'rejected') {
    return html`<p class="result rejected" role="alert"><strong>Rejected:</strong> ${str(d.error, 400)}
      <br /><span class="small">Still enforcing v${str(d.version)} <${Mono}>${shortHash(d.hash)}<//> (last good).</span></p>`;
  }
  return html`<p class="result applied" role="status"><strong>${str(d.status) === 'unchanged' ? 'No change' : 'Applied'}</strong>
    v${str(d.version)} <${Mono}>${shortHash(d.hash)}<//>
    ${Array.isArray(d.changed) && d.changed.length ? html`<br /><span class="small">changed: ${d.changed.map((x) => str(x)).join(', ')}</span>` : null}</p>`;
}

export function PolicyPanel() {
  const snap = useSig(snapshot);
  const hist = useSig(policyHistory);
  const [loaded, setLoaded] = useState({ text: '', hash: '', version: '' });
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [confirmDev, setConfirmDev] = useState(false);
  const [loadErr, setLoadErr] = useState('');

  async function load() {
    const r = await api('/api/policy/raw', { as: 'text' });
    if (!r.ok) { setLoadErr(r.error); return; }
    setLoadErr('');
    const next = { text: r.text, hash: (r.headers && r.headers.get('X-Policy-Hash')) || '', version: (r.headers && r.headers.get('X-Policy-Version')) || '' };
    setLoaded(next);
    setDraft(next.text);
  }

  useEffect(() => { load(); loadPolicyHistory(); }, []);

  async function after(r) {
    setBusy(false);
    if (r.status === 0 || (!r.ok && !(r.data && r.data.status))) setRes({ kind: 'error', text: r.error });
    else setRes({ kind: 'result', data: r.data });
    refreshAll();
    loadPolicyHistory();
    if (r.ok) await load();
  }

  async function apply() {
    setBusy(true);
    await after(await api('/api/policy', { method: 'POST', body: { yaml: draft }, timeout: 8000 }));
  }

  async function profile(name) {
    setConfirmDev(false);
    setBusy(true);
    await after(await api(`/api/policy/profile/${encodeURIComponent(name)}`, { method: 'POST', body: {} }));
  }

  async function detectors(on) {
    setBusy(true);
    const r = await api(`/api/policy/detectors-${on ? 'on' : 'off'}`, { method: 'POST', body: {} });
    setBusy(false);
    setRes(r.ok ? { kind: 'result', data: { status: 'applied', version: r.data && r.data.version, hash: r.data && r.data.hash,
      changed: [on ? 'detector overrides cleared' : 'all detectors disabled (flow guard stays on)'] } } : { kind: 'error', text: r.error });
    refreshAll();
  }

  const p = snap && snap.policy ? snap.policy : null;
  const current = p ? str(p.profile) : '';
  const dirty = draft !== loaded.text;
  const outOfDate = p && loaded.hash && str(p.hash) !== loaded.hash;
  const disabled = p && Array.isArray(p.detectors_disabled) ? p.detectors_disabled : [];
  const list = Array.isArray(hist.list) ? hist.list.slice().reverse().slice(0, 12) : [];

  return html`<${Section} title="Policy" id="policy-title" className="policy-card"
    actions=${p ? html`<span class="small">enforcing v${str(p.version)} <${Mono}>${shortHash(p.hash)}<//> · ${str(p.mode)}</span>` : null}>
    <div class="row wrap">
      <span class="label small">Profile</span>
      <div class="seg" role="group" aria-label="Policy profile">
        ${PROFILES.map((name) => html`<button type="button" class=${'seg-btn' + (current === name ? ' on' : '')}
          aria-pressed=${current === name} disabled=${busy}
          onClick=${() => (name === 'dev' && current !== 'dev' ? setConfirmDev(true) : profile(name))}>${name}${name === 'dev' ? ' (monitor)' : ''}</button>`)}
      </div>
      <span class="label small">Detectors</span>
      ${disabled.length
        ? html`<button type="button" class="btn small primary" disabled=${busy} onClick=${() => detectors(true)}>Re-enable all</button>`
        : html`<button type="button" class="btn small danger-outline" disabled=${busy} onClick=${() => detectors(false)}>All off</button>`}
    </div>
    <label class="label" for="policy-yaml">policy.yaml ${loaded.version ? html`<span class="muted small">(loaded v${loaded.version} ${shortHash(loaded.hash)})</span>` : null}</label>
    <textarea id="policy-yaml" class="yaml" rows="16" spellcheck="false" wrap="off" value=${draft}
      onInput=${(e) => setDraft(e.currentTarget.value)} aria-describedby="policy-hint"></textarea>
    <p id="policy-hint" class="small muted">
      ${dirty ? `${changedLines(loaded.text, draft)} line(s) changed vs the loaded version. ` : 'No local edits. '}
      ${outOfDate ? 'The enforced policy changed since this text was loaded. ' : ''}
      The server validates before writing; a rejected edit never becomes policy.
    </p>
    <div class="row wrap">
      <button type="button" class="btn primary" disabled=${busy || !dirty} onClick=${apply}>Validate and apply</button>
      <button type="button" class="btn" disabled=${busy} onClick=${() => { setRes(null); load(); }}>Reload from server</button>
      ${dirty ? html`<button type="button" class="btn" disabled=${busy} onClick=${() => setDraft(loaded.text)}>Discard edits</button>` : null}
    </div>
    <${ErrorLine} text=${loadErr} />
    <${ResultLine} res=${res} />
    ${hist.supported === false ? null : html`
      <h3 class="sub-title">Reload history</h3>
      ${list.length === 0 ? html`<p class="small muted">${hist.supported ? 'No reloads recorded yet.' : 'Loading…'}</p>` : html`<ol class="history">
        ${list.map((e) => html`<li class=${'hist ' + (e.status === 'rejected' ? 'rejected' : 'applied')}>
          <span class="num">${fmtClock(e.ts)}</span>
          <span class=${'chip ' + (e.status === 'rejected' ? 'sev-block' : 'sev-allow')}>${str(e.status)}</span>
          ${e.version !== undefined && e.status !== 'rejected' ? html`<span>v${str(e.version)}</span>` : null}
          <${Mono}>${shortHash(e.hash)}<//>
          <span class="small muted hist-detail">${e.status === 'rejected' ? str(e.error, 200) : (Array.isArray(e.changed) ? e.changed.map((x) => str(x)).join(', ') : '')}</span>
        </li>`)}
      </ol>`}`}
    ${confirmDev ? html`<${Modal} title="Switch to the dev profile?" onClose=${() => setConfirmDev(false)} labelId="dev-title">
      <p>dev sets <code class="mono">mode: monitor</code> and <code class="mono">fail_mode: open</code>: findings are logged but nothing is blocked, and grey-zone traffic is allowed when the judge is down. Posture drops accordingly.</p>
      <div class="row end">
        <button type="button" class="btn" onClick=${() => setConfirmDev(false)}>Cancel</button>
        <button type="button" class="btn danger" onClick=${() => profile('dev')}>Switch to dev</button>
      </div>
    <//>` : null}
  <//>`;
}
