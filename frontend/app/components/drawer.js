// Decision detail drawer, deep-linked as #/console/<seq>. Back or Esc closes it.

import { html, useEffect, useRef, useState } from '../vendor/preact-htm.js';
import { route, go, eventBySeq, findRecord, eventsVersion } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str, sevOf, owaspTags, OWASP_TITLES, shortHash, isNum } from '../lib/format.js';
import { Stamp, Evidence, FindingsList, Waterfall, Provenance, Mono, DecisionExplanation } from './ui.js';

export function Drawer() {
  const r = useSig(route);
  useSig(eventsVersion);
  const seq = r.tab === 'console' ? r.seq : null;
  const [fetched, setFetched] = useState({ seq: null, rec: null, missing: false });
  const ref = useRef(null);
  const rec = seq === null ? null : eventBySeq(seq) || (fetched.seq === seq ? fetched.rec : null);

  useEffect(() => {
    if (seq === null || eventBySeq(seq)) return undefined;
    let alive = true;
    findRecord(seq).then((found) => { if (alive) setFetched({ seq, rec: found, missing: !found }); });
    return () => { alive = false; };
  }, [seq]);

  useEffect(() => {
    if (seq === null) return undefined;
    const prev = document.activeElement;
    const h = ref.current && ref.current.querySelector('h2');
    if (h) h.focus();
    const onKey = (e) => {
      if (e.key === 'Escape' && !document.querySelector('.modal')) { e.preventDefault(); go('#/console'); }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      if (prev && prev.isConnected && typeof prev.focus === 'function') prev.focus();
    };
  }, [seq]);

  if (seq === null) return null;
  const close = () => go('#/console');
  const tags = rec ? owaspTags(rec) : [];

  async function copyLink() {
    try { await navigator.clipboard.writeText(location.href); } catch { /* clipboard unavailable: the URL bar has the link */ }
  }

  return html`<div class="drawer-backdrop" onClick=${(e) => { if (e.target === e.currentTarget) close(); }}>
    <aside class="drawer" role="dialog" aria-modal="false" aria-labelledby="drawer-title" ref=${ref}>
      <header class="drawer-head">
        <h2 id="drawer-title" tabIndex="-1">Decision #${seq}</h2>
        <div class="row">
          <button type="button" class="btn small" onClick=${copyLink}>Copy link</button>
          <button type="button" class="btn small" onClick=${close} aria-label="Close decision details">Close</button>
        </div>
      </header>
      ${!rec
        ? html`<p class="muted">${fetched.seq === seq && fetched.missing ? `Record #${seq} is not in the buffer and the gateway did not return it.` : 'Loading…'}</p>`
        : html`<div class="drawer-body">
            <div class="row wrap">
              <${Stamp} action=${str(rec.action)} />
              <div>
                <div><strong>${sevOf(rec.action).label}</strong>
                  ${rec.primary ? html` · <${Mono}>${str(rec.primary.control_id)}<//>` : null}
                  ${tags.map((t) => html` <span class="tag" title=${OWASP_TITLES[t] || ''}>${t} ${OWASP_TITLES[t] || ''}</span>`)}
                </div>
                <p class="small">${str(rec.summary, 600)}</p>
              </div>
            </div>
            <p class="small muted">policy v${str(rec.policy_version)} <${Mono}>${shortHash(rec.policy_hash)}<//>
              ${isNum(rec.seq) ? html` · audit seq ${rec.seq}` : null}</p>
            <${DecisionExplanation} rec=${rec} />
            <h3 class="sub-title">Evidence</h3>
            <${Evidence} rec=${rec} />
            <h3 class="sub-title">Findings</h3>
            <${FindingsList} rec=${rec} />
            <h3 class="sub-title">Timings</h3>
            <${Waterfall} rec=${rec} />
            <h3 class="sub-title">Provenance</h3>
            <${Provenance} rec=${rec} />
          </div>`}
    </aside>
  </div>`;
}
